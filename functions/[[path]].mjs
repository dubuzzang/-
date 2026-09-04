export async function onRequest(context) {
  let path = new URL(context.request.url).pathname;
  try { path = decodeURIComponent(path); } catch (_error) {}
  if (path.toLowerCase() === '/__cloudflare' || path.toLowerCase().startsWith('/__cloudflare/')) {
    return new Response('Not Found', { status: 404 });
  }
  return context.env.APP.fetch(context.request);
}
