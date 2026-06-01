<?php
/**
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 */

use PrestaShop\Module\Pp2fa\Security\TwoFactorManager;

/**
 * Challenge page: asks the already-authenticated employee for their current
 * TOTP code (or a recovery code) before granting access to the back office.
 */
class AdminPp2faChallengeController extends ModuleAdminController
{
    private const MAX_ATTEMPTS = 5;
    private const LOCK_SECONDS = 300;

    public function __construct()
    {
        $this->bootstrap = true;
        $this->display = 'view';
        $this->show_toolbar = false;

        parent::__construct();

        $this->meta_title = $this->module->l('Two-factor authentication', 'AdminPp2faChallengeController');
    }

    public function viewAccess($disable = false)
    {
        return (bool) ($this->context->employee && $this->context->employee->id);
    }

    public function setMedia($isNewTheme = false)
    {
        parent::setMedia($isNewTheme);

        $this->addCSS($this->module->getPathUri() . 'views/css/pp2fa.css');
    }

    public function initContent()
    {
        $employeeId = (int) $this->context->employee->id;

        // No active enrollment → this employee belongs on the setup page.
        if (!TwoFactorManager::isActiveForEmployee($employeeId)) {
            Tools::redirectAdmin($this->context->link->getAdminLink('AdminPp2faSetup'));

            return;
        }

        // Already verified this session → nothing to do.
        if (TwoFactorManager::isSessionVerified($this->context->cookie, $this->context->employee)) {
            Tools::redirectAdmin($this->destinationUrl());

            return;
        }

        parent::initContent();
    }

    public function postProcess()
    {
        if (!Tools::isSubmit('submitPp2faChallenge')) {
            return;
        }

        if ($this->isLocked()) {
            $this->errors[] = $this->module->l('Too many attempts. Please wait a few minutes before trying again.', 'AdminPp2faChallengeController');

            return;
        }

        $code = (string) Tools::getValue('pp2fa_code');
        if (TwoFactorManager::verifyChallenge((int) $this->context->employee->id, $code)) {
            $this->resetAttempts();
            TwoFactorManager::markSessionVerified($this->context->cookie, $this->context->employee);
            Tools::redirectAdmin($this->destinationUrl());

            return;
        }

        $this->registerFailedAttempt();
        $this->errors[] = $this->module->l('Invalid code. Please try again.', 'AdminPp2faChallengeController');
    }

    public function renderView()
    {
        $templateDir = _PS_MODULE_DIR_ . $this->module->name . '/views/templates/admin/';

        $this->context->smarty->assign([
            'pp2fa_form_action' => $this->context->link->getAdminLink('AdminPp2faChallenge'),
            'pp2fa_token_field' => '<input type="hidden" name="token" value="' . htmlspecialchars($this->token, ENT_QUOTES) . '" />',
            'pp2fa_logout_url' => $this->context->link->getAdminLink('AdminLogin') . '&logout=1',
            'pp2fa_locked' => $this->isLocked(),
            'pp2fa_employee_name' => trim((string) $this->context->employee->firstname . ' ' . (string) $this->context->employee->lastname),
        ]);

        return $this->context->smarty->fetch($templateDir . 'challenge.tpl');
    }

    private function destinationUrl(): string
    {
        $defaultTab = (int) $this->context->employee->default_tab;
        if ($defaultTab > 0) {
            $tab = new Tab($defaultTab);
            if (Validate::isLoadedObject($tab) && $tab->class_name) {
                return $this->context->link->getAdminLink($tab->class_name);
            }
        }

        return $this->context->link->getAdminLink('AdminDashboard');
    }

    // ------------------------------------------------------------------
    // Basic brute-force throttling (per browser, via the admin cookie)
    // ------------------------------------------------------------------

    private function isLocked(): bool
    {
        $cookie = $this->context->cookie;
        $attempts = (int) ($cookie->pp2fa_fail ?? 0);
        $lastFail = (int) ($cookie->pp2fa_fail_time ?? 0);

        if ($attempts < self::MAX_ATTEMPTS) {
            return false;
        }

        if (time() - $lastFail >= self::LOCK_SECONDS) {
            $this->resetAttempts();

            return false;
        }

        return true;
    }

    private function registerFailedAttempt(): void
    {
        $cookie = $this->context->cookie;
        $cookie->pp2fa_fail = (int) ($cookie->pp2fa_fail ?? 0) + 1;
        $cookie->pp2fa_fail_time = time();
        $cookie->write();
    }

    private function resetAttempts(): void
    {
        $cookie = $this->context->cookie;
        $cookie->pp2fa_fail = 0;
        $cookie->pp2fa_fail_time = 0;
        $cookie->write();
    }
}
