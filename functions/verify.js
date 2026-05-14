export async function onRequestPost(context) {
    const { token } = await context.request.json();

    const verify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            secret: context.env.TURNSTILE_SECRET,
            response: token,
        }),
    });

    const result = await verify.json();

    if (result.success) {
        return new Response(JSON.stringify({ success: true }), {
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': `cf_verified=1; Path=/; Max-Age=120; HttpOnly; Secure; SameSite=Strict`,
            },
        });
    } else {
        return Response.json({ error: 'Verification failed' }, { status: 403 });
    }
}
