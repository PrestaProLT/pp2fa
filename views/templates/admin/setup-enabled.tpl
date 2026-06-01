{*
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 *}
<div class="pp2fa-wrapper">
    <div class="panel pp2fa-panel">
        <div class="panel-heading">
            <i class="icon-lock"></i> {l s='Two-factor authentication' mod='pp2fa'}
        </div>
        <div class="panel-body">
            <div class="alert alert-success">
                {l s='Two-factor authentication is currently enabled for your account.' mod='pp2fa'}
            </div>

            <p>{l s='You can generate a new secret (you will need to re-scan the QR code in your authenticator app) below.' mod='pp2fa'}</p>

            <form method="post" action="{$pp2fa_regenerate_action|escape:'html':'UTF-8'}">
                {$pp2fa_token_field nofilter}
                <button type="submit" name="submitPp2faRegenerate" value="1" class="btn btn-default">
                    <i class="icon-refresh"></i> {l s='Reconfigure two-factor authentication' mod='pp2fa'}
                </button>
            </form>

            {if !$pp2fa_enforced}
                <form method="post" action="{$pp2fa_disable_action|escape:'html':'UTF-8'}" class="pp2fa-mt">
                    {$pp2fa_token_field nofilter}
                    <button type="submit" name="submitPp2faDisable" value="1" class="btn btn-danger">
                        <i class="icon-remove"></i> {l s='Disable two-factor authentication' mod='pp2fa'}
                    </button>
                </form>
            {/if}

            <hr />
            <a href="{$pp2fa_dashboard_url|escape:'html':'UTF-8'}" class="btn btn-primary">
                {l s='Back to the dashboard' mod='pp2fa'}
            </a>
        </div>
    </div>
</div>
