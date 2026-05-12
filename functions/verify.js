export async function onRequestPost(context) {
    try {
        const { token } = await context.request.json();
        const secret = context.env.TURNSTILE_SECRET;
        const target = context.env.TARGET_URL;

        if (!secret || !target) {
            return new Response(JSON.stringify({ error: "Variablen fehlen im Dashboard" }), { status: 500 });
        }

        const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${encodeURIComponent(secret)}&response=${encodeURIComponent(token)}`
        });

        const data = await response.json();

        if (data.success) {
            return new Response(JSON.stringify({ url: target }), {
                headers: { 'Content-Type': 'application/json' }
            });
        } else {
            return new Response(JSON.stringify({ error: "Token ungültig" }), { status: 403 });
        }
    } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500 });
    }
}
