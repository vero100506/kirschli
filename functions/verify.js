/**
 * POST /verify
 *
 * Validates the Cloudflare Turnstile token server-side.
 * On success, issues an HMAC-signed session cookie that go.js will verify.
 *
 * Required environment variables (set in Cloudflare Pages → Settings → Variables):
 *   TURNSTILE_SECRET  – Turnstile secret key
 *   COOKIE_SECRET     – A long, random string used to sign the session cookie
 *                       (generate with: openssl rand -hex 32)
 */

import { sign } from './_hmac.js';

export async function onRequestPost(context) {
    const { request, env } = context;

    // ── Validate env ────────────────────────────────────────────────────────
    if (!env.TURNSTILE_SECRET || !env.COOKIE_SECRET) {
        console.error('Missing required environment variables.');
        return Response.json({ success: false, message: 'Server misconfigured.' }, { status: 500 });
    }

    // ── Parse request body ───────────────────────────────────────────────────
    let token;
    try {
        ({ token } = await request.json());
    } catch {
        return Response.json({ success: false, message: 'Invalid request body.' }, { status: 400 });
    }

    if (!token || typeof token !== 'string') {
        return Response.json({ success: false, message: 'Missing token.' }, { status: 400 });
    }

    // ── Verify with Cloudflare Turnstile ────────────────────────────────────
    // Including remoteip tightens the verification (Cloudflare strongly recommends it).
    const formData = new FormData();
    formData.append('secret', env.TURNSTILE_SECRET);
    formData.append('response', token);
    const clientIP = request.headers.get('CF-Connecting-IP');
    if (clientIP) formData.append('remoteip', clientIP);

    let tsResult;
    try {
        const tsRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: formData,
        });
        tsResult = await tsRes.json();
    } catch (err) {
        console.error('Turnstile siteverify error:', err);
        return Response.json({ success: false, message: 'Verification service unavailable.' }, { status: 502 });
    }

    if (!tsResult.success) {
        // Log the error codes for debugging (visible in Cloudflare logs, not sent to client)
        console.warn('Turnstile rejection:', tsResult['error-codes']);
        return Response.json(
            { success: false, message: 'Verifizierung fehlgeschlagen. Bitte erneut versuchen.' },
            { status: 403 },
        );
    }

    // ── Issue signed session cookie ─────────────────────────────────────────
    // Cookie value: <uuid>.<hmac-signature>
    // The HMAC prevents any client from forging a valid cookie without COOKIE_SECRET.
    const sessionId = crypto.randomUUID();
    const signature = await sign(sessionId, env.COOKIE_SECRET);
    const cookieValue = `${sessionId}.${signature}`;

    return new Response(JSON.stringify({ success: true }), {
        headers: {
            'Content-Type': 'application/json',
            // Max-Age=300: cookie valid for 5 minutes — plenty of time to click the button.
            'Set-Cookie': `cf_verified=${cookieValue}; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Strict`,
        },
    });
}
