{*
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   MIT (https://opensource.org/licenses/MIT)
 *}
<div class="panel">
    <div class="panel-heading">
        <i class="icon-shield"></i> {l s='Two-factor authentication status' mod='pp2fa'}
    </div>
    <div class="panel-body">
        {if $pp2fa_enforced}
            <p class="text-success"><i class="icon-check"></i> {l s='2FA is enforced for all employees.' mod='pp2fa'}</p>
        {else}
            <p class="text-warning"><i class="icon-warning-sign"></i> {l s='2FA is optional. Employees who have enabled it are still challenged at login.' mod='pp2fa'}</p>
        {/if}

        <p>{l s='Employees with 2FA enabled:' mod='pp2fa'} <strong>{$pp2fa_enrolled|intval}</strong></p>

        {if $pp2fa_mine_active}
            <p class="text-success"><i class="icon-check"></i> {l s='Your own account is protected with 2FA.' mod='pp2fa'}</p>
        {else}
            <p class="text-danger"><i class="icon-warning-sign"></i> {l s='Your account does not have 2FA enabled yet.' mod='pp2fa'}</p>
        {/if}

        <a href="{$pp2fa_setup_url|escape:'html':'UTF-8'}" class="btn btn-default">
            <i class="icon-lock"></i> {l s='Manage my two-factor authentication' mod='pp2fa'}
        </a>
    </div>
</div>
