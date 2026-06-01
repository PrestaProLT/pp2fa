{*
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 *}
<div class="pp2fa-wrapper">
    <div class="panel pp2fa-panel">
        <div class="panel-heading">
            <i class="icon-lock"></i> {l s='Set up two-factor authentication' mod='pp2fa'}
        </div>
        <div class="panel-body">
            <p class="pp2fa-intro">
                {l s='Your administrator requires two-factor authentication to access the back office. Follow the steps below to finish setting up your account.' mod='pp2fa'}
            </p>

            <div class="row">
                <div class="col-md-5 col-sm-12 pp2fa-step">
                    <h4><span class="pp2fa-step-num">1</span> {l s='Scan the QR code' mod='pp2fa'}</h4>
                    <p>{l s='Open an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, FreeOTP…) and scan this code:' mod='pp2fa'}</p>
                    <div class="pp2fa-qr" id="pp2fa-qr" data-otpauth="{$pp2fa_otpauth_uri|escape:'html':'UTF-8'}"></div>

                    <p class="pp2fa-manual">
                        {l s='Can\'t scan? Enter this key manually:' mod='pp2fa'}<br />
                        <code class="pp2fa-secret">{$pp2fa_secret_chunks|escape:'html':'UTF-8'}</code>
                    </p>
                </div>

                <div class="col-md-7 col-sm-12 pp2fa-step">
                    <h4><span class="pp2fa-step-num">2</span> {l s='Enter the 6-digit code' mod='pp2fa'}</h4>
                    <p>{l s='Type the current code shown in your app to confirm the connection:' mod='pp2fa'}</p>

                    <form method="post" action="{$pp2fa_form_action|escape:'html':'UTF-8'}" autocomplete="off">
                        {$pp2fa_token_field nofilter}
                        <div class="form-group">
                            <input
                                type="text"
                                name="pp2fa_code"
                                class="form-control pp2fa-code-input"
                                inputmode="numeric"
                                autocomplete="one-time-code"
                                pattern="[0-9]*"
                                maxlength="6"
                                placeholder="••••••"
                                autofocus />
                        </div>
                        <button type="submit" name="submitPp2faEnable" value="1" class="btn btn-primary btn-lg">
                            <i class="icon-check"></i> {l s='Enable two-factor authentication' mod='pp2fa'}
                        </button>
                    </form>

                    <hr />
                    <a href="{$pp2fa_regenerate_action|escape:'html':'UTF-8'}" class="btn btn-default btn-sm">
                        <i class="icon-refresh"></i> {l s='Generate a new secret' mod='pp2fa'}
                    </a>
                    <a href="{$pp2fa_logout_url|escape:'html':'UTF-8'}" class="btn btn-link btn-sm pull-right">
                        {l s='Log out' mod='pp2fa'}
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>
