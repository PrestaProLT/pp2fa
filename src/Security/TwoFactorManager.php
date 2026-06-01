<?php
/**
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 */

declare(strict_types=1);

namespace PrestaShop\Module\Pp2fa\Security;

use PrestaShop\Module\Pp2fa\Model\Pp2faSecret;

/**
 * Central 2FA decision logic shared by:
 *  - the legacy `actionAdminControllerInitBefore` hook (all PS versions),
 *  - the Symfony `kernel.request` subscriber (PS 8.x / 9.x admin pages),
 *  - the challenge and setup admin controllers.
 *
 * Keeping the logic here guarantees the three entry points enforce identical
 * rules.
 */
final class TwoFactorManager
{
    public const ACTION_NONE = 0;
    public const ACTION_ENROLL = 1;
    public const ACTION_CHALLENGE = 2;

    public const CONFIG_ENFORCE = 'PP2FA_ENFORCE_ALL';
    public const CONFIG_ISSUER = 'PP2FA_ISSUER';

    public const CONTROLLER_CHALLENGE = 'AdminPp2faChallenge';
    public const CONTROLLER_SETUP = 'AdminPp2faSetup';

    /** Cookie key holding the "this login session already passed 2FA" token. */
    private const COOKIE_PASS = 'pp2fa_pass';

    private const RECOVERY_CODE_COUNT = 8;

    /**
     * Decide what should happen for the currently authenticated employee.
     *
     * @return int one of the ACTION_* constants
     */
    public static function decideAction(\Context $context): int
    {
        $employee = $context->employee;
        if (!\Validate::isLoadedObject($employee) || !$employee->isLoggedBack()) {
            return self::ACTION_NONE;
        }

        $record = Pp2faSecret::getByEmployee((int) $employee->id);
        $hasActive = $record !== null && (int) $record->active === 1;

        if ($hasActive) {
            return self::isSessionVerified($context->cookie, $employee)
                ? self::ACTION_NONE
                : self::ACTION_CHALLENGE;
        }

        // No confirmed 2FA yet: force enrollment only when enforcement is on.
        return self::isEnforced() ? self::ACTION_ENROLL : self::ACTION_NONE;
    }

    public static function isEnforced(): bool
    {
        return (bool) \Configuration::get(self::CONFIG_ENFORCE);
    }

    public static function isActiveForEmployee(int $idEmployee): bool
    {
        $record = Pp2faSecret::getByEmployee($idEmployee);

        return $record !== null && (int) $record->active === 1;
    }

    public static function countEnrolledEmployees(): int
    {
        return (int) \Db::getInstance()->getValue(
            'SELECT COUNT(*) FROM `' . _DB_PREFIX_ . 'pp2fa_secret` WHERE active = 1'
        );
    }

    // ------------------------------------------------------------------
    // Per-login-session verified flag (stored in the admin cookie)
    // ------------------------------------------------------------------

    public static function markSessionVerified(\Cookie $cookie, \Employee $employee): void
    {
        $cookie->{self::COOKIE_PASS} = self::sessionToken($employee);
        $cookie->write();
    }

    public static function isSessionVerified(\Cookie $cookie, \Employee $employee): bool
    {
        $stored = isset($cookie->{self::COOKIE_PASS}) ? (string) $cookie->{self::COOKIE_PASS} : '';

        return $stored !== '' && hash_equals(self::sessionToken($employee), $stored);
    }

    public static function clearSessionVerified(\Cookie $cookie): void
    {
        $cookie->{self::COOKIE_PASS} = '';
        $cookie->write();
    }

    private static function sessionToken(\Employee $employee): string
    {
        $key = defined('_COOKIE_KEY_') ? _COOKIE_KEY_ : '';

        // Binding the passwd hash means the token is invalidated if the
        // employee changes their password, and cannot be reused for another
        // account.
        return hash('sha256', (int) $employee->id . '|' . (string) $employee->passwd . '|' . $key);
    }

    // ------------------------------------------------------------------
    // Enrollment
    // ------------------------------------------------------------------

    /**
     * Return the pending/active enrollment for an employee, creating a fresh
     * pending secret if none exists yet.
     */
    public static function getOrCreatePending(int $idEmployee): Pp2faSecret
    {
        $record = Pp2faSecret::getByEmployee($idEmployee);
        if ($record !== null) {
            return $record;
        }

        return self::regenerate($idEmployee);
    }

    /**
     * Create a brand new (inactive) secret for an employee, replacing any
     * previous one.
     */
    public static function regenerate(int $idEmployee): Pp2faSecret
    {
        $record = Pp2faSecret::getByEmployee($idEmployee) ?? new Pp2faSecret();
        $record->id_employee = $idEmployee;
        $record->secret = SecretCipher::encrypt(Totp::generateSecret());
        $record->recovery_codes = '';
        $record->active = 0;
        $record->save();

        return $record;
    }

    /**
     * Decrypt and return the plain base32 secret for display / verification.
     */
    public static function getPlainSecret(Pp2faSecret $record): string
    {
        return SecretCipher::decrypt((string) $record->secret);
    }

    public static function getProvisioningUri(Pp2faSecret $record, \Employee $employee): string
    {
        $issuer = (string) \Configuration::get(self::CONFIG_ISSUER);
        if ($issuer === '') {
            $issuer = (string) \Configuration::get('PS_SHOP_NAME');
        }
        if ($issuer === '') {
            $issuer = 'PrestaShop';
        }

        $label = (string) $employee->email;
        if ($label === '') {
            $label = 'employee-' . (int) $employee->id;
        }

        return Totp::getProvisioningUri($label, self::getPlainSecret($record), $issuer);
    }

    /**
     * Confirm enrollment: verify a code against the pending secret and, on
     * success, activate it and generate one-time recovery codes.
     *
     * @return string[]|null the plain recovery codes on success, null on failure
     */
    public static function confirmEnrollment(int $idEmployee, string $code): ?array
    {
        $record = Pp2faSecret::getByEmployee($idEmployee);
        if ($record === null) {
            return null;
        }

        if (!Totp::verify(self::getPlainSecret($record), $code)) {
            return null;
        }

        $plainCodes = self::generateRecoveryCodes();
        $hashes = array_map([self::class, 'hashRecoveryCode'], $plainCodes);

        $record->recovery_codes = SecretCipher::encrypt((string) json_encode($hashes));
        $record->active = 1;
        $record->save();

        return $plainCodes;
    }

    // ------------------------------------------------------------------
    // Verification (challenge step)
    // ------------------------------------------------------------------

    /**
     * Verify a submitted code against the employee's active secret. Accepts a
     * TOTP code or a one-time recovery code (which is then consumed).
     */
    public static function verifyChallenge(int $idEmployee, string $code): bool
    {
        $record = Pp2faSecret::getByEmployee($idEmployee);
        if ($record === null || (int) $record->active !== 1) {
            return false;
        }

        if (Totp::verify(self::getPlainSecret($record), $code)) {
            return true;
        }

        return self::consumeRecoveryCode($record, $code);
    }

    public static function disableForEmployee(int $idEmployee): bool
    {
        $record = Pp2faSecret::getByEmployee($idEmployee);
        if ($record === null) {
            return true;
        }

        return (bool) $record->delete();
    }

    private static function consumeRecoveryCode(Pp2faSecret $record, string $code): bool
    {
        $normalized = self::normalizeRecoveryCode($code);
        if ($normalized === '') {
            return false;
        }

        $stored = json_decode(SecretCipher::decrypt((string) $record->recovery_codes), true);
        if (!is_array($stored) || $stored === []) {
            return false;
        }

        $candidate = self::hashRecoveryCode($normalized);
        $matchedIndex = null;
        foreach ($stored as $index => $hash) {
            if (hash_equals((string) $hash, $candidate)) {
                $matchedIndex = $index;
                break;
            }
        }

        if ($matchedIndex === null) {
            return false;
        }

        unset($stored[$matchedIndex]);
        $record->recovery_codes = SecretCipher::encrypt((string) json_encode(array_values($stored)));
        $record->save();

        return true;
    }

    /** @return string[] */
    private static function generateRecoveryCodes(): array
    {
        $codes = [];
        for ($i = 0; $i < self::RECOVERY_CODE_COUNT; ++$i) {
            $raw = strtoupper(bin2hex(random_bytes(5))); // 10 hex chars
            $codes[] = substr($raw, 0, 5) . '-' . substr($raw, 5, 5);
        }

        return $codes;
    }

    private static function normalizeRecoveryCode(string $code): string
    {
        return strtoupper(preg_replace('/[^a-zA-Z0-9]/', '', $code) ?? '');
    }

    private static function hashRecoveryCode(string $code): string
    {
        $key = defined('_COOKIE_KEY_') ? _COOKIE_KEY_ : '';

        return hash('sha256', self::normalizeRecoveryCode($code) . '|' . $key);
    }
}
