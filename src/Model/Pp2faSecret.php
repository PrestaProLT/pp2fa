<?php
/**
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 */

declare(strict_types=1);

namespace PrestaShop\Module\Pp2fa\Model;

/**
 * Stores one TOTP enrollment per employee.
 *
 * `secret` holds the base32 TOTP secret encrypted at rest (see SecretCipher);
 * `recovery_codes` holds a JSON array of one-time recovery code hashes, also
 * encrypted. `active = 1` means the employee finished the enrollment by
 * confirming a valid code.
 */
class Pp2faSecret extends \ObjectModel
{
    /** @var int */
    public $id_employee;

    /** @var string encrypted base32 secret */
    public $secret;

    /** @var string encrypted JSON array of recovery code hashes */
    public $recovery_codes;

    /** @var int 1 once enrollment is confirmed */
    public $active = 0;

    /** @var string */
    public $date_add;

    /** @var string */
    public $date_upd;

    /** @var array<string, mixed> */
    public static $definition = [
        'table' => 'pp2fa_secret',
        'primary' => 'id_pp2fa_secret',
        'fields' => [
            'id_employee' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedId', 'required' => true],
            'secret' => ['type' => self::TYPE_STRING, 'validate' => 'isAnything', 'size' => 255],
            'recovery_codes' => ['type' => self::TYPE_STRING, 'validate' => 'isAnything'],
            'active' => ['type' => self::TYPE_BOOL],
            'date_add' => ['type' => self::TYPE_DATE, 'validate' => 'isDate'],
            'date_upd' => ['type' => self::TYPE_DATE, 'validate' => 'isDate'],
        ],
    ];

    /**
     * Load the enrollment row for a given employee, or null if none exists.
     */
    public static function getByEmployee(int $idEmployee): ?self
    {
        if ($idEmployee <= 0) {
            return null;
        }

        $id = (int) \Db::getInstance()->getValue(
            'SELECT id_pp2fa_secret FROM `' . _DB_PREFIX_ . 'pp2fa_secret`'
            . ' WHERE id_employee = ' . (int) $idEmployee
        );

        if ($id <= 0) {
            return null;
        }

        $secret = new self($id);

        return \Validate::isLoadedObject($secret) ? $secret : null;
    }
}
