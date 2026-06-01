# PrestaPro — Admin 2FA Login (`pp2fa`)

Enforces **two-factor authentication (TOTP)** for the PrestaShop back office.
After entering their password, every employee must confirm a 6-digit code from
an authenticator app (Google Authenticator, Microsoft Authenticator, Authy,
FreeOTP, …) before they can use the admin.

Compatible with **PrestaShop 1.7.x, 8.x and 9.x**.

## How it works

| Layer | Mechanism | Covers |
|-------|-----------|--------|
| Legacy guard | `actionAdminControllerInitBefore` hook | All legacy `AdminController` pages (1.7 / 8 / 9) + the login flow |
| Symfony guard | `kernel.request` subscriber (`config/admin/services.yml`) | Migrated **Symfony** back office pages on 8.x / 9.x |
| Per-login reset | `actionAdminLoginControllerLoginAfter` hook | Forces a fresh challenge on every new login |

On each back office request the module checks the authenticated employee:

- **2FA enabled, not yet verified this session** → redirected to the challenge page.
- **2FA not set up + enforcement on** → redirected to the enrollment page.
- **2FA not set up + enforcement off** → allowed through (only employees who opted in are challenged).

The challenge/setup pages are served by two hidden admin controllers
(`AdminPp2faChallenge`, `AdminPp2faSetup`) registered as `active = 0` tabs so
they are routable but never appear in the menu. `viewAccess()` is overridden so
any authenticated employee can always reach their own 2FA flow regardless of
profile permissions.

## Security notes

- TOTP secrets and recovery-code hashes are **encrypted at rest** (AES-256-CBC,
  key derived from `_COOKIE_KEY_`).
- The "verified this session" token is bound to the employee id + password hash,
  so it cannot be reused for another account and is invalidated on password change.
- Eight one-time **recovery codes** are generated at enrollment (shown once).
- The challenge page throttles brute force (5 attempts, then a 5-minute lock).

## Configuration

Module Manager → **PrestaPro — Admin 2FA Login** → Configure:

- **Require 2FA for all employees** (`PP2FA_ENFORCE_ALL`, default **on**).
- **Issuer name** (`PP2FA_ISSUER`, default = shop name) — label shown in the app.

## ⚠️ Recovery / lockout escape hatch

Because this module gates *all* admin access, keep a way back in:

1. **Use a recovery code** on the challenge page.
2. **Disable the module** in the database if you are locked out:
   ```sql
   UPDATE `ps_module` SET `active` = 0 WHERE `name` = 'pp2fa';
   ```
   (replace `ps_` with your table prefix). With the module inactive, the guard
   hooks no longer run.
3. Or remove the `modules/pp2fa/` directory.
4. **Reset one employee's 2FA** directly:
   ```sql
   DELETE FROM `ps_pp2fa_secret` WHERE `id_employee` = <ID>;
   ```

## Files

```
pp2fa.php                         Main module: hooks, guard, config page
src/Install/Installer.php         DB table, hidden tabs, config, hook registration
src/Model/Pp2faSecret.php         ObjectModel — one enrollment per employee
src/Security/Totp.php             RFC 6238 TOTP / RFC 4226 HOTP (dependency-free)
src/Security/SecretCipher.php     AES-256-CBC encryption of secrets at rest
src/Security/TwoFactorManager.php Shared decision logic for all entry points
src/Subscriber/RequestGuardSubscriber.php  kernel.request guard (PS 8/9 Symfony pages)
controllers/admin/AdminPp2faChallengeController.php  Code-entry challenge
controllers/admin/AdminPp2faSetupController.php      QR enrollment + recovery codes
config/admin/services.yml         Registers the request subscriber in the admin container
views/                            Templates, CSS, bundled qrcode.min.js
```
