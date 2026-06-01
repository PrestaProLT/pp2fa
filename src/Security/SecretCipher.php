<?php
/**
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   MIT (https://opensource.org/licenses/MIT)
 */

declare(strict_types=1);

namespace PrestaShop\Module\Pp2fa\Security;

/**
 * Symmetric encryption for TOTP secrets at rest.
 *
 * The encryption key is derived from the shop's _COOKIE_KEY_ (unique per
 * installation, never shipped with the code) so a database dump alone is not
 * enough to recover a usable secret.
 */
final class SecretCipher
{
    private const CIPHER = 'aes-256-cbc';
    private const IV_LENGTH = 16;

    public static function encrypt(string $plain): string
    {
        $iv = random_bytes(self::IV_LENGTH);
        $cipherText = openssl_encrypt($plain, self::CIPHER, self::key(), OPENSSL_RAW_DATA, $iv);

        if ($cipherText === false) {
            return '';
        }

        return base64_encode($iv . $cipherText);
    }

    public static function decrypt(string $payload): string
    {
        $raw = base64_decode($payload, true);
        if ($raw === false || strlen($raw) <= self::IV_LENGTH) {
            return '';
        }

        $iv = substr($raw, 0, self::IV_LENGTH);
        $cipherText = substr($raw, self::IV_LENGTH);
        $plain = openssl_decrypt($cipherText, self::CIPHER, self::key(), OPENSSL_RAW_DATA, $iv);

        return $plain === false ? '' : $plain;
    }

    private static function key(): string
    {
        $material = (defined('_COOKIE_KEY_') ? _COOKIE_KEY_ : '')
            . (defined('_COOKIE_IV_') ? _COOKIE_IV_ : '')
            . '|pp2fa-secret-store';

        return hash('sha256', $material, true);
    }
}
