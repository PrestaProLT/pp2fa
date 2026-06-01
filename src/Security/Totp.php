<?php
/**
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 */

declare(strict_types=1);

namespace PrestaShop\Module\Pp2fa\Security;

/**
 * Dependency-free RFC 6238 (TOTP) / RFC 4226 (HOTP) implementation.
 *
 * Compatible with Google Authenticator, Authy, Microsoft Authenticator,
 * FreeOTP and any other standard authenticator app. SHA1 / 6 digits / 30s
 * period are used because that is what the apps assume by default.
 */
final class Totp
{
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public const DEFAULT_PERIOD = 30;
    public const DEFAULT_DIGITS = 6;
    public const DEFAULT_WINDOW = 1;

    /**
     * Generate a new random base32 secret.
     *
     * @param int $length number of base32 characters (16 = 80 bits, 32 = 160 bits)
     */
    public static function generateSecret(int $length = 32): string
    {
        $length = max(16, $length);
        $bytes = random_bytes((int) ceil($length * 5 / 8));
        $encoded = self::base32Encode($bytes);

        return substr($encoded, 0, $length);
    }

    /**
     * Verify a user-supplied TOTP code, allowing a small clock-drift window.
     */
    public static function verify(
        string $secret,
        string $code,
        int $window = self::DEFAULT_WINDOW,
        ?int $timestamp = null,
        int $period = self::DEFAULT_PERIOD,
        int $digits = self::DEFAULT_DIGITS
    ): bool {
        $code = preg_replace('/\s+/', '', $code);
        if ($code === null || !preg_match('/^\d{' . $digits . '}$/', $code)) {
            return false;
        }

        $timestamp = $timestamp ?? time();
        $counter = (int) floor($timestamp / $period);

        for ($i = -$window; $i <= $window; ++$i) {
            if (hash_equals(self::hotp($secret, $counter + $i, $digits), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Compute the current TOTP code (mostly useful for testing).
     */
    public static function getCode(
        string $secret,
        ?int $timestamp = null,
        int $period = self::DEFAULT_PERIOD,
        int $digits = self::DEFAULT_DIGITS
    ): string {
        $timestamp = $timestamp ?? time();
        $counter = (int) floor($timestamp / $period);

        return self::hotp($secret, $counter, $digits);
    }

    /**
     * Build the otpauth:// provisioning URI rendered as a QR code on the
     * enrollment page.
     */
    public static function getProvisioningUri(
        string $label,
        string $secret,
        string $issuer,
        int $period = self::DEFAULT_PERIOD,
        int $digits = self::DEFAULT_DIGITS
    ): string {
        $path = rawurlencode($issuer) . ':' . rawurlencode($label);
        $query = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => $digits,
            'period' => $period,
        ]);

        return 'otpauth://totp/' . $path . '?' . $query;
    }

    private static function hotp(string $secret, int $counter, int $digits): string
    {
        $key = self::base32Decode($secret);
        if ($key === '') {
            return str_repeat('0', $digits);
        }

        // 8-byte big-endian counter (high 32 bits are 0 for any realistic time).
        $binCounter = pack('N', 0) . pack('N', $counter);
        $hash = hash_hmac('sha1', $binCounter, $key, true);

        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $truncated = (
            ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF)
        );

        $code = $truncated % (10 ** $digits);

        return str_pad((string) $code, $digits, '0', STR_PAD_LEFT);
    }

    private static function base32Encode(string $data): string
    {
        if ($data === '') {
            return '';
        }

        $binary = '';
        foreach (str_split($data) as $char) {
            $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $output = '';
        foreach (str_split($binary, 5) as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $output .= self::BASE32_ALPHABET[bindec($chunk)];
        }

        return $output;
    }

    private static function base32Decode(string $secret): string
    {
        $secret = strtoupper(preg_replace('/[^A-Z2-7]/', '', $secret) ?? '');
        if ($secret === '') {
            return '';
        }

        $binary = '';
        foreach (str_split($secret) as $char) {
            $position = strpos(self::BASE32_ALPHABET, $char);
            if ($position === false) {
                continue;
            }
            $binary .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
        }

        $output = '';
        foreach (str_split($binary, 8) as $byte) {
            if (strlen($byte) === 8) {
                $output .= chr(bindec($byte));
            }
        }

        return $output;
    }
}
