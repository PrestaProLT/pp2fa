<?php
/**
 * @author    PrestaPro
 * @copyright PrestaPro
 * @license   Proprietary
 */

declare(strict_types=1);

namespace PrestaShop\Module\Pp2fa\Subscriber;

use PrestaShop\Module\Pp2fa\Security\TwoFactorManager;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Gates the back office Symfony pages on PrestaShop 8.x / 9.x.
 *
 * The legacy `actionAdminControllerInitBefore` hook only fires for controllers
 * that extend the legacy AdminController. Modern (migrated) admin pages are
 * pure Symfony controllers that never trigger it, so without this guard a
 * still-authenticated employee could reach them before completing 2FA.
 *
 * Wired as a plain `kernel.event_listener` (NOT an EventSubscriberInterface) in
 * `config/admin/services.yml` with the event name declared in the tag. This is
 * deliberate: a subscriber forces Symfony to load this class at container
 * COMPILE time (to call the static getSubscribedEvents()), which would depend
 * on the module autoloader already being registered during compilation — the
 * classic "admin redirects to homepage" failure. As a listener the class is
 * resolved lazily at runtime, by which point AppKernel has already included the
 * module's vendor/autoload.php. It is registered only in the admin container,
 * so it never touches the front office.
 *
 * The event argument is intentionally untyped: the concrete event class
 * differs across the Symfony versions shipped with PS 1.7 (GetResponseEvent),
 * 8 (RequestEvent) and 9 (RequestEvent), so we rely on duck typing instead.
 */
final class RequestGuardSubscriber
{
    /**
     * @param object $event Symfony kernel request event
     */
    public function onKernelRequest($event): void
    {
        if (!$this->isMainRequest($event) || !method_exists($event, 'getRequest')) {
            return;
        }

        if (!class_exists('\Context') || !class_exists('\Validate')) {
            return;
        }

        $request = $event->getRequest();

        // Legacy admin controllers (?controller=Admin...) are bridged through
        // the Symfony kernel too, but they are already handled by the
        // actionAdminControllerInitBefore hook. Skipping them here keeps this
        // subscriber focused on migrated Symfony pages AND avoids a redirect
        // loop on our own challenge/setup controllers (which are legacy).
        if ($this->isLegacyControllerRequest($request)) {
            return;
        }

        // Never interfere with logout or AJAX/JSON sub-calls.
        if ($this->isLogout($request) || $this->isAjax($request)) {
            return;
        }

        $context = \Context::getContext();
        if ($context === null || $context->employee === null || $context->link === null) {
            return;
        }

        $action = TwoFactorManager::decideAction($context);
        if ($action === TwoFactorManager::ACTION_NONE) {
            return;
        }

        $controller = $action === TwoFactorManager::ACTION_CHALLENGE
            ? TwoFactorManager::CONTROLLER_CHALLENGE
            : TwoFactorManager::CONTROLLER_SETUP;

        $url = $context->link->getAdminLink($controller);
        $event->setResponse(new RedirectResponse($url));
    }

    private function isMainRequest($event): bool
    {
        // Symfony >= 5.3
        if (method_exists($event, 'isMainRequest')) {
            return (bool) $event->isMainRequest();
        }
        // Symfony 3.4 / 4.4
        if (method_exists($event, 'isMasterRequest')) {
            return (bool) $event->isMasterRequest();
        }

        return true;
    }

    private function isLegacyControllerRequest($request): bool
    {
        if (!is_object($request) || !isset($request->query) || !is_object($request->query)) {
            return false;
        }

        return method_exists($request->query, 'has') && $request->query->has('controller');
    }

    private function isLogout($request): bool
    {
        if (!is_object($request)) {
            return false;
        }

        $uri = method_exists($request, 'getRequestUri') ? (string) $request->getRequestUri() : '';

        return stripos($uri, 'logout') !== false;
    }

    private function isAjax($request): bool
    {
        return is_object($request)
            && method_exists($request, 'isXmlHttpRequest')
            && $request->isXmlHttpRequest();
    }
}
