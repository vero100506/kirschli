/**
 * Shared HMAC-SHA256 helpers for cookie signing/verification.
 * Requires env.COOKIE_SECRET to be set in Cloudflare Pages settings.
 */

const ENC = new TextEncoder();

/** Import the raw secret as an HMAC-SHA-256 key. */
async function importKey(secret) {
    return crypto.subtle.importKey(
        'raw',
        ENC.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify'],
    );
}

/** Return a URL-safe base64 HMAC signature for `data`. */
export async function sign(data, secret) {
    const key = await importKey(secret);
    const sig = await crypto.subtle.sign('HMAC', key, ENC.encode(data));
    return btoa(String.fromCharCode(...new Uint8Array(sig)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Verify a signed cookie value of the form `<uuid>.<signature>`.
 * Uses a timing-safe byte comparison to prevent timing attacks.
 */
export async function verifyToken(cookieValue, secret) {
    if (!cookieValue || typeof cookieValue !== 'string') return false;

    const dot = cookieValue.lastIndexOf('.');
    if (dot === -1) return false;

    const uuid = cookieValue.slice(0, dot);
    const receivedSig = cookieValue.slice(dot + 1);

    // UUID must look like a UUID (basic sanity check)
    if (!/^[0-9a-f-]{36}$/.test(uuid)) return false;

    const expectedSig = await sign(uuid, secret);

    // Constant-time comparison
    if (receivedSig.length !== expectedSig.length) return false;
    const a = ENC.encode(receivedSig);
    const b = ENC.encode(expectedSig);
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

/** Parse a single named cookie out of the Cookie header. */
export function parseCookie(header, name) {
    for (const part of (header || '').split(';')) {
        const [k, ...v] = part.trim().split('=');
        if (k === name) return decodeURIComponent(v.join('='));
    }
    return null;
}
