/**
 * PrestaPro — Admin 2FA Login
 *
 * Renders the otpauth:// provisioning URI as a QR code on the enrollment page,
 * using the bundled qrcode.min.js library (no external request).
 */
(function () {
    'use strict';

    function renderQr() {
        var container = document.getElementById('pp2fa-qr');
        if (!container || typeof QRCode === 'undefined') {
            return;
        }

        var uri = container.getAttribute('data-otpauth');
        if (!uri) {
            return;
        }

        // eslint-disable-next-line no-new
        new QRCode(container, {
            text: uri,
            width: 180,
            height: 180,
            correctLevel: QRCode.CorrectLevel.M
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', renderQr);
    } else {
        renderQr();
    }
})();
