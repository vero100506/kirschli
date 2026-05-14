export async function onRequest(context) {
    const { request, env } = context;

    const cookie = request.headers.get('Cookie') || '';
    const verified = cookie.split(';').some(c => c.trim() === 'cf_verified=1');

    if (!verified) {
        return Response.redirect(new URL('/', request.url).href, 302);
    }

    return new Response(null, {
        status: 302,
        headers: {
            'Location': env.TARGET_URL,
            'Set-Cookie': `cf_verified=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
        },
    });
}
