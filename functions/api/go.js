/**
 * GET /api/go
 *
 * Checks for a valid HMAC-signed session cookie before redirecting
 * to the protected TARGET_URL.  Any direct call without a valid cookie
 * (e.g. from a bot that skipped Turnstile) is silently sent back to /.
 *
 * Required environment variables:
 *   TARGET_URL     – The destination URL to redirect to
 *   COOKIE_SECRET  – Must match the secret used in verify.js
 */

import { verifyToken, parseCookie } from '../_hmac.js';

export async function onRequest(context) {
    const { request, env } = context;

    // ── Validate env ────────────────────────────────────────────────────────
    if (!env.COOKIE_SECRET || !env.TARGET_URL) {
        console.error('Missing required environment variables.');
        // Redirect home rather than leaking server details
        return Response.redirect(new URL('/', request.url).href, 302);
    }

    // ── Extract and cryptographically verify the session cookie ─────────────
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookieValue = parseCookie(cookieHeader, 'cf_verified');
    const valid = await verifyToken(cookieValue, env.COOKIE_SECRET);

    if (!valid) {
        // No valid cookie → back to the verification page. No error details exposed.
        return Response.redirect(new URL('/', request.url).href, 302);
    }

    // ── One-time use: immediately invalidate the cookie ─────────────────────
    // Even if the redirect response is somehow replayed, the cookie is gone.
    return new Response(null, {
        status: 302,
        headers: {
            'Location': env.TARGET_URL,
            'Set-Cookie': `cf_verified=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
        },
    });
}
