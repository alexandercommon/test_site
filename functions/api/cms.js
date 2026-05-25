export async function onRequest(context) {
  const cookieHeader = context.request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/gh_session=([^;]+)/);
  if (!match) return new Response('Unauthorized', { status: 401 });
  let token;
  try {
    token = await decryptString(match[1], context.env.ENCRYPTION_SECRET);
  } catch {
    return new Response('Invalid Session', { status: 401 });
  }
  const githubUrl = `https://api.github.com/repos/${context.env.GH_OWNER}/${context.env.GH_REPO}/contents/data.json`;
  if (context.request.method === 'GET') {
    const ghRes = await fetch(githubUrl, { headers: { 'Authorization': `token ${token}`, 'User-Agent': 'CF-Pages' } });
    return new Response(ghRes.body, { headers: { 'Content-Type': 'application/json' } });
  }
  if (context.request.method === 'POST') {
    const body = await context.request.json();
    const ghRes = await fetch(githubUrl, {
      method: 'PUT',
      headers: { 'Authorization': `token ${token}`, 'User-Agent': 'CF-Pages', 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'Update via CMS', content: btoa(JSON.stringify(body, null, 2)), sha: body.sha })
    });
    return new Response(ghRes.body, { status: ghRes.status });
  }
}
async function decryptString(encryptedBase64, secret) {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const binary = atob(encryptedBase64);
  const iv = new Uint8Array([...binary].slice(0, 12).map(c => c.charCodeAt(0)));
  const data = new Uint8Array([...binary].slice(12).map(c => c.charCodeAt(0)));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: enc.encode('salt'), iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return dec.decode(decrypted);
}
