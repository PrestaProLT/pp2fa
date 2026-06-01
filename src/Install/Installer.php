<?php
/**
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 */

declare(strict_types=1);

namespace PrestaShop\Module\Pp2fa\Install;

use PrestaShop\Module\Pp2fa\Security\TwoFactorManager;

/**
 * Handles installation / uninstallation side effects: database table, hidden
 * admin tabs (for the challenge & setup controllers), default configuration
 * and hook registration.
 */
final class Installer
{
    /** @var \Module */
    private $module;

    /** @var string[] */
    private const HOOKS = [
        'actionAdminControllerInitBefore',
        'actionAdminLoginControllerLoginAfter',
    ];

    /**
     * Hidden controllers reached only by redirect (active = 0 keeps them out
     * of the admin menu while still being routable by the dispatcher).
     *
     * @var array<string, string>
     */
    private const TABS = [
        TwoFactorManager::CONTROLLER_CHALLENGE => 'Two-factor authentication',
        TwoFactorManager::CONTROLLER_SETUP => 'Two-factor authentication setup',
    ];

    public function __construct(\Module $module)
    {
        $this->module = $module;
    }

    public function install(): bool
    {
        return $this->installTables()
            && $this->installConfiguration()
            && $this->registerHooks()
            && $this->installTabs();
    }

    public function uninstall(): bool
    {
        // Keep going even if one step fails so the module can always be removed.
        $this->uninstallTabs();
        $this->uninstallConfiguration();
        $this->uninstallTables();

        return true;
    }

    private function installTables(): bool
    {
        $sql = 'CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'pp2fa_secret` (
            `id_pp2fa_secret` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
            `id_employee` INT(10) UNSIGNED NOT NULL,
            `secret` VARCHAR(255) NOT NULL DEFAULT \'\',
            `recovery_codes` TEXT NULL,
            `active` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
            `date_add` DATETIME NULL,
            `date_upd` DATETIME NULL,
            PRIMARY KEY (`id_pp2fa_secret`),
            UNIQUE KEY `id_employee` (`id_employee`)
        ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=utf8mb4;';

        return (bool) \Db::getInstance()->execute($sql);
    }

    private function uninstallTables(): bool
    {
        return (bool) \Db::getInstance()->execute(
            'DROP TABLE IF EXISTS `' . _DB_PREFIX_ . 'pp2fa_secret`'
        );
    }

    private function installConfiguration(): bool
    {
        $shopName = (string) \Configuration::get('PS_SHOP_NAME');

        \Configuration::updateValue(TwoFactorManager::CONFIG_ENFORCE, 1);
        \Configuration::updateValue(TwoFactorManager::CONFIG_ISSUER, $shopName !== '' ? $shopName : 'PrestaShop');

        return true;
    }

    private function uninstallConfiguration(): bool
    {
        \Configuration::deleteByName(TwoFactorManager::CONFIG_ENFORCE);
        \Configuration::deleteByName(TwoFactorManager::CONFIG_ISSUER);

        return true;
    }

    private function registerHooks(): bool
    {
        foreach (self::HOOKS as $hook) {
            if (!$this->module->registerHook($hook)) {
                return false;
            }
        }

        return true;
    }

    private function installTabs(): bool
    {
        foreach (self::TABS as $className => $name) {
            if (!$this->installTab($className, $name)) {
                return false;
            }
        }

        return true;
    }

    private function installTab(string $className, string $name): bool
    {
        if ((int) \Tab::getIdFromClassName($className) > 0) {
            return true;
        }

        $tab = new \Tab();
        $tab->class_name = $className;
        $tab->module = $this->module->name;
        $tab->active = 0; // hidden from the menu, still routable
        $tab->id_parent = 0;

        $names = [];
        foreach (\Language::getLanguages(false) as $language) {
            $names[(int) $language['id_lang']] = $name;
        }
        $tab->name = $names;

        return (bool) $tab->add();
    }

    private function uninstallTabs(): bool
    {
        foreach (array_keys(self::TABS) as $className) {
            $idTab = (int) \Tab::getIdFromClassName($className);
            if ($idTab > 0) {
                $tab = new \Tab($idTab);
                if (\Validate::isLoadedObject($tab)) {
                    $tab->delete();
                }
            }
        }

        return true;
    }
}
