<?php
/**
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   MIT (https://opensource.org/licenses/MIT)
 */

use PrestaShop\Module\Pp2fa\Security\TwoFactorManager;

/**
 * Enrollment page: shows the QR code / secret and confirms the first TOTP
 * code, then reveals one-time recovery codes. Reached automatically when 2FA
 * is enforced and the employee has not enrolled yet.
 */
class AdminPp2faSetupController extends ModuleAdminController
{
    /** @var string[]|null populated right after a successful enrollment */
    private $justEnabledCodes = null;

    public function __construct()
    {
        $this->bootstrap = true;
        $this->display = 'view';
        $this->show_toolbar = false;

        parent::__construct();

        $this->meta_title = $this->module->l('Two-factor authentication setup', 'AdminPp2faSetupController');
    }

    /**
     * Any authenticated employee may set up their own 2FA — bypass the normal
     * per-tab permission check (the tab is hidden and used only for this flow).
     */
    public function viewAccess($disable = false)
    {
        return (bool) ($this->context->employee && $this->context->employee->id);
    }

    public function setMedia($isNewTheme = false)
    {
        parent::setMedia($isNewTheme);

        $this->addCSS($this->module->getPathUri() . 'views/css/pp2fa.css');
        $this->addJS($this->module->getPathUri() . 'views/js/qrcode.min.js');
        $this->addJS($this->module->getPathUri() . 'views/js/pp2fa.js');
    }

    public function postProcess()
    {
        $employeeId = (int) $this->context->employee->id;

        if (Tools::isSubmit('submitPp2faRegenerate')) {
            TwoFactorManager::regenerate($employeeId);
            Tools::redirectAdmin($this->context->link->getAdminLink('AdminPp2faSetup'));

            return;
        }

        if (Tools::isSubmit('submitPp2faDisable') && !TwoFactorManager::isEnforced()) {
            TwoFactorManager::disableForEmployee($employeeId);
            TwoFactorManager::clearSessionVerified($this->context->cookie);
            $this->confirmations[] = $this->module->l('Two-factor authentication has been disabled for your account.', 'AdminPp2faSetupController');

            return;
        }

        if (Tools::isSubmit('submitPp2faEnable')) {
            $code = (string) Tools::getValue('pp2fa_code');
            $codes = TwoFactorManager::confirmEnrollment($employeeId, $code);

            if ($codes === null) {
                $this->errors[] = $this->module->l('That code is not valid. Make sure your device clock is correct and try again.', 'AdminPp2faSetupController');

                return;
            }

            // Enrollment complete: this login session is now verified.
            TwoFactorManager::markSessionVerified($this->context->cookie, $this->context->employee);
            $this->justEnabledCodes = $codes;
        }
    }

    public function renderView()
    {
        $employee = $this->context->employee;
        $employeeId = (int) $employee->id;
        $templateDir = _PS_MODULE_DIR_ . $this->module->name . '/views/templates/admin/';

        // Success state: reveal recovery codes once.
        if ($this->justEnabledCodes !== null) {
            $this->context->smarty->assign([
                'pp2fa_recovery_codes' => $this->justEnabledCodes,
                'pp2fa_dashboard_url' => $this->context->link->getAdminLink('AdminDashboard'),
            ]);

            return $this->context->smarty->fetch($templateDir . 'setup-done.tpl');
        }

        $record = \PrestaShop\Module\Pp2fa\Model\Pp2faSecret::getByEmployee($employeeId);

        // Already enrolled and just viewing the page.
        if ($record !== null && (int) $record->active === 1) {
            $this->context->smarty->assign([
                'pp2fa_enforced' => TwoFactorManager::isEnforced(),
                'pp2fa_regenerate_action' => $this->selfAction('submitPp2faRegenerate'),
                'pp2fa_disable_action' => $this->selfAction('submitPp2faDisable'),
                'pp2fa_dashboard_url' => $this->context->link->getAdminLink('AdminDashboard'),
                'pp2fa_token_field' => $this->tokenField(),
            ]);

            return $this->context->smarty->fetch($templateDir . 'setup-enabled.tpl');
        }

        // Pending enrollment: show QR + secret + confirmation form.
        $record = TwoFactorManager::getOrCreatePending($employeeId);
        $secret = TwoFactorManager::getPlainSecret($record);
        $uri = TwoFactorManager::getProvisioningUri($record, $employee);

        $this->context->smarty->assign([
            'pp2fa_secret' => $secret,
            'pp2fa_secret_chunks' => trim(chunk_split($secret, 4, ' ')),
            'pp2fa_otpauth_uri' => $uri,
            'pp2fa_form_action' => $this->context->link->getAdminLink('AdminPp2faSetup'),
            'pp2fa_regenerate_action' => $this->selfAction('submitPp2faRegenerate'),
            'pp2fa_token_field' => $this->tokenField(),
            'pp2fa_logout_url' => $this->logoutUrl(),
        ]);

        return $this->context->smarty->fetch($templateDir . 'setup.tpl');
    }

    private function selfAction(string $submitName): string
    {
        return $this->context->link->getAdminLink('AdminPp2faSetup') . '&' . $submitName . '=1';
    }

    private function tokenField(): string
    {
        return '<input type="hidden" name="token" value="' . htmlspecialchars($this->token, ENT_QUOTES) . '" />';
    }

    private function logoutUrl(): string
    {
        return $this->context->link->getAdminLink('AdminLogin') . '&logout=1';
    }
}
