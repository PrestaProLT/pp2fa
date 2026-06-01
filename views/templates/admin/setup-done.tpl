{*
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 *}
<div class="pp2fa-wrapper">
    <div class="panel pp2fa-panel">
        <div class="panel-heading">
            <i class="icon-check-circle"></i> {l s='Two-factor authentication is enabled' mod='pp2fa'}
        </div>
        <div class="panel-body">
            <div class="alert alert-success">
                {l s='Your account is now protected with two-factor authentication.' mod='pp2fa'}
            </div>

            <h4>{l s='Save your recovery codes' mod='pp2fa'}</h4>
            <p class="pp2fa-intro">
                {l s='Keep these one-time recovery codes somewhere safe. Each can be used once to sign in if you lose access to your authenticator app. They will not be shown again.' mod='pp2fa'}
            </p>

            <ul class="pp2fa-recovery-list">
                {foreach from=$pp2fa_recovery_codes item=code}
                    <li><code>{$code|escape:'html':'UTF-8'}</code></li>
                {/foreach}
            </ul>

            <a href="{$pp2fa_dashboard_url|escape:'html':'UTF-8'}" class="btn btn-primary btn-lg">
                <i class="icon-arrow-right"></i> {l s='Continue to the dashboard' mod='pp2fa'}
            </a>
        </div>
    </div>
</div>
