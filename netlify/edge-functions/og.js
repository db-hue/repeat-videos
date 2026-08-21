// Per-video Open Graph tags for shared /watch?v=<id> links.
// Rewrites the static index.html meta tags so link previews (WhatsApp,
// Telegram, Slack, X, Discord, …) show the actual video title + thumbnail
// instead of the generic site card. Fails open: any error → untouched page.

export default async (request, context) => {
  const response = await context.next();

  const v = new URL(request.url).searchParams.get("v") || "";
  if (!/^[A-Za-z0-9_-]{11}$/.test(v)) return response;

  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("text/html")) return response;

  let html = await response.text();

  // Video title via YouTube oEmbed — no API key needed. 3 s budget, then
  // fall back to generic title but still swap URL/thumbnail tags.
  let title = null;
  try {
    const r = await fetch(
      "https://www.youtube.com/oembed?format=json&url=" +
        encodeURIComponent("https://www.youtube.com/watch?v=" + v),
      { signal: AbortSignal.timeout(3000) },
    );
    if (r.ok) {
      const j = await r.json();
      if (j && typeof j.title === "string" && j.title.trim()) title = j.title.trim();
    }
  } catch (_) { /* oEmbed down or video private — keep generic title */ }

  const esc = (s) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const pageUrl = "https://repeat-videos.com/watch?v=" + v;
  const thumb = "https://img.youtube.com/vi/" + v + "/hqdefault.jpg";

  html = html
    .replace(/(<link rel="canonical" href=")[^"]*(")/, "$1" + pageUrl + "$2")
    .replace(/(<meta property="og:url" content=")[^"]*(")/, "$1" + pageUrl + "$2")
    .replace(/(<meta property="og:image" content=")[^"]*(")/, "$1" + thumb + "$2")
    .replace(/(<meta name="twitter:image" content=")[^"]*(")/, "$1" + thumb + "$2")
    .replace(/(<meta name="twitter:card" content=")[^"]*(")/, "$1summary_large_image$2");

  if (title) {
    const t = esc(title);
    html = html
      .replace(/<title>[^<]*<\/title>/, "<title>" + t + " — Repeat Videos</title>")
      .replace(/(<meta property="og:title" content=")[^"]*(")/, "$1" + t + "$2")
      .replace(/(<meta name="twitter:title" content=")[^"]*(")/, "$1" + t + "$2")
      .replace(/(<meta property="og:description" content=")[^"]*(")/, "$1" + t + " — on repeat$2")
      .replace(/(<meta name="twitter:description" content=")[^"]*(")/, "$1" + t + " — on repeat$2")
      .replace(/(<meta name="description" content=")[^"]*(")/, "$1Watch " + t + " on repeat. Set A-B loop points, track play counts, build a personal library.$2");
  }

  const headers = new Headers(response.headers);
  headers.delete("content-length");
  return new Response(html, { status: response.status, headers });
};

export const config = { path: "/watch" };
