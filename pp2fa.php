<?php
/**
 * PrestaPro — Admin 2FA Login
 *
 * Enforces two-factor authentication (TOTP) for every PrestaShop back office
 * login. Compatible with PrestaShop 1.7.x, 8.x and 9.x.
 *
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__ . '/vendor/autoload.php';

use PrestaShop\Module\Pp2fa\Install\Installer;
use PrestaShop\Module\Pp2fa\Security\TwoFactorManager;

class Pp2fa extends Module
{
    public function __construct()
    {
        $this->name = 'pp2fa';
        $this->tab = 'administration';
        $this->version = '1.0.0';
        $this->author = 'PrestaPro';
        $this->need_instance = 0;
        $this->ps_versions_compliancy = ['min' => '1.7.0.0', 'max' => _PS_VERSION_];
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->l('PrestaPro — Admin 2FA Login');
        $this->description = $this->l('Enforces two-factor authentication (TOTP) for every back office login. Works on PrestaShop 1.7, 8 and 9.');
        $this->confirmUninstall = $this->l('Are you sure? Employees will no longer be asked for a 2FA code when signing in.');
    }

    public function install(): bool
    {
        return parent::install() && (new Installer($this))->install();
    }

    public function uninstall(): bool
    {
        return (new Installer($this))->uninstall() && parent::uninstall();
    }

    /**
     * Universal guard: runs at the top of AdminController::init() on every
     * legacy back office page across PS 1.7 / 8 / 9. Symfony-only pages on
     * 8/9 are covered separately by the kernel.request subscriber.
     */
    public function hookActionAdminControllerInitBefore(array $params): void
    {
        // Never interfere with the logout action — it is processed *after*
        // this hook in AdminController::init(), so redirecting here would trap
        // an employee who is trying to sign out.
        if (Tools::getValue('logout') !== false || isset($_GET['logout'])) {
            return;
        }

        $current = $this->resolveControllerName($params);

        // Always allow the login screen and our own challenge / setup flow,
        // otherwise the redirect below would loop forever.
        if (in_array($current, [
            'AdminLogin',
            TwoFactorManager::CONTROLLER_CHALLENGE,
            TwoFactorManager::CONTROLLER_SETUP,
        ], true)) {
            return;
        }

        $this->enforce(TwoFactorManager::decideAction($this->context));
    }

    /**
     * Force a fresh 2FA challenge for every new login session: clear the
     * "already verified" flag right after a successful authentication.
     */
    public function hookActionAdminLoginControllerLoginAfter(array $params): void
    {
        TwoFactorManager::clearSessionVerified($this->context->cookie);
    }

    private function enforce(int $action): void
    {
        if ($action === TwoFactorManager::ACTION_CHALLENGE) {
            Tools::redirectAdmin(
                $this->context->link->getAdminLink(TwoFactorManager::CONTROLLER_CHALLENGE)
            );
        } elseif ($action === TwoFactorManager::ACTION_ENROLL) {
            Tools::redirectAdmin(
                $this->context->link->getAdminLink(TwoFactorManager::CONTROLLER_SETUP)
            );
        }
    }

    private function resolveControllerName(array $params): string
    {
        if (isset($params['controller']) && is_object($params['controller'])) {
            $class = get_class($params['controller']);

            return preg_replace('/Controller$/', '', $class) ?? $class;
        }

        return (string) Tools::getValue('controller');
    }

    /**
     * Module configuration page (Module Manager → Configure).
     */
    public function getContent(): string
    {
        $output = '';

        if (Tools::isSubmit('submitPp2faSettings')) {
            $enforce = (int) (bool) Tools::getValue(TwoFactorManager::CONFIG_ENFORCE);
            $issuer = trim((string) Tools::getValue(TwoFactorManager::CONFIG_ISSUER));

            Configuration::updateValue(TwoFactorManager::CONFIG_ENFORCE, $enforce);
            Configuration::updateValue(TwoFactorManager::CONFIG_ISSUER, $issuer);

            $output .= $this->displayConfirmation($this->l('Settings updated.'));
        }

        return $output . $this->renderStatusPanel() . $this->renderSettingsForm();
    }

    private function renderStatusPanel(): string
    {
        $enrolled = TwoFactorManager::countEnrolledEmployees();
        $mine = TwoFactorManager::isActiveForEmployee((int) $this->context->employee->id);
        $setupUrl = $this->context->link->getAdminLink(TwoFactorManager::CONTROLLER_SETUP);

        $this->context->smarty->assign([
            'pp2fa_enrolled' => $enrolled,
            'pp2fa_mine_active' => $mine,
            'pp2fa_setup_url' => $setupUrl,
            'pp2fa_enforced' => TwoFactorManager::isEnforced(),
        ]);

        return $this->display(__FILE__, 'views/templates/admin/config-status.tpl');
    }

    private function renderSettingsForm(): string
    {
        $fields = [
            'form' => [
                'legend' => [
                    'title' => $this->l('Settings'),
                    'icon' => 'icon-cogs',
                ],
                'input' => [
                    [
                        'type' => 'switch',
                        'label' => $this->l('Require 2FA for all employees'),
                        'name' => TwoFactorManager::CONFIG_ENFORCE,
                        'is_bool' => true,
                        'desc' => $this->l('When enabled, every employee must set up an authenticator app before they can use the back office.'),
                        'values' => [
                            ['id' => 'active_on', 'value' => 1, 'label' => $this->l('Yes')],
                            ['id' => 'active_off', 'value' => 0, 'label' => $this->l('No')],
                        ],
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Issuer name'),
                        'name' => TwoFactorManager::CONFIG_ISSUER,
                        'desc' => $this->l('Shown in the authenticator app next to the account. Usually your shop name.'),
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];

        $helper = new HelperForm();
        $helper->module = $this;
        $helper->name_controller = $this->name;
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->currentIndex = AdminController::$currentIndex . '&configure=' . $this->name;
        $helper->submit_action = 'submitPp2faSettings';
        $helper->default_form_language = (int) $this->context->language->id;
        $helper->fields_value = [
            TwoFactorManager::CONFIG_ENFORCE => (int) Configuration::get(TwoFactorManager::CONFIG_ENFORCE),
            TwoFactorManager::CONFIG_ISSUER => (string) Configuration::get(TwoFactorManager::CONFIG_ISSUER),
        ];

        return $helper->generateForm([$fields]);
    }
}
