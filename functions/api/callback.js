export async function onRequest(context) {
  const { searchParams } = new URL(context.request.url);
  const code = searchParams.get('code');
  const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'accept': 'application/json' },
    body: JSON.stringify({
      client_id: context.env.GITHUB_CLIENT_ID,
      client_secret: context.env.GITHUB_CLIENT_SECRET,
      code
    })
  });
  const tokenData = await tokenResponse.json();
  if (!tokenData.access_token) return new Response('Auth failed', { status: 400 });
  const encryptedToken = await encryptString(tokenData.access_token, context.env.ENCRYPTION_SECRET);
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/admin.html',
      'Set-Cookie': `gh_session=${encryptedToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`
    }
  });
}
async function encryptString(text, secret) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: enc.encode('salt'), iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(encrypted)));
}
