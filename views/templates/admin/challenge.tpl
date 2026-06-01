{*
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   MIT (https://opensource.org/licenses/MIT)
 *}
<div class="pp2fa-wrapper pp2fa-wrapper--narrow">
    <div class="panel pp2fa-panel">
        <div class="panel-heading">
            <i class="icon-lock"></i> {l s='Two-factor authentication' mod='pp2fa'}
        </div>
        <div class="panel-body">
            {if $pp2fa_employee_name}
                <p class="pp2fa-intro">{l s='Signed in as' mod='pp2fa'} <strong>{$pp2fa_employee_name|escape:'html':'UTF-8'}</strong></p>
            {/if}
            <p>{l s='Enter the 6-digit code from your authenticator app to continue.' mod='pp2fa'}</p>

            <form method="post" action="{$pp2fa_form_action|escape:'html':'UTF-8'}" autocomplete="off">
                {$pp2fa_token_field nofilter}
                <div class="form-group">
                    <input
                        type="text"
                        name="pp2fa_code"
                        class="form-control pp2fa-code-input"
                        inputmode="numeric"
                        autocomplete="one-time-code"
                        pattern="[0-9A-Za-z\-]*"
                        maxlength="11"
                        placeholder="••••••"
                        {if $pp2fa_locked}disabled{else}autofocus{/if} />
                    <p class="help-block">{l s='You can also enter one of your recovery codes.' mod='pp2fa'}</p>
                </div>
                <button type="submit" name="submitPp2faChallenge" value="1" class="btn btn-primary btn-lg" {if $pp2fa_locked}disabled{/if}>
                    <i class="icon-sign-in"></i> {l s='Verify' mod='pp2fa'}
                </button>
                <a href="{$pp2fa_logout_url|escape:'html':'UTF-8'}" class="btn btn-link pull-right">
                    {l s='Log out' mod='pp2fa'}
                </a>
            </form>
        </div>
    </div>
</div>
