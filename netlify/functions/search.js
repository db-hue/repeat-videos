// GET /.netlify/functions/search?q=<text>
// Resolves a free-text query to the YouTube video worth looping: take the
// top relevance-ranked results and pick the most-viewed among them, so a
// misspelled or vague title still lands on the canonical upload rather than
// a low-view re-upload that happens to match the words better.
//
// Two backends, same output shape:
//   1. YouTube Data API v3 when YOUTUBE_API_KEY is set (official, stable;
//      search.list costs 100 quota units → ~100 searches/day on the free tier).
//   2. Otherwise the public results page is fetched and ytInitialData parsed.
//      No key, no quota, but depends on YouTube's page markup.
// No auth: guests may search too. Nothing is stored.

const API_KEY    = process.env.YOUTUBE_API_KEY;
const TOP_N      = 5;   // relevance window the view-count pick is taken from
const MAX_Q_LEN  = 200;

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Content-Type':                 'application/json',
  'Cache-Control':                'public, max-age=3600',
};

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36';

function parseViews(text) {
  // "2,101,390,350 views" | "1.2M views" | "No views" → number
  if (!text) return 0;
  const m = String(text).replace(/,/g, '').match(/([\d.]+)\s*([KMB])?/i);
  if (!m) return 0;
  const mult = { K: 1e3, M: 1e6, B: 1e9 }[(m[2] || '').toUpperCase()] || 1;
  return Math.round(parseFloat(m[1]) * mult);
}

// ── Backend 1: Data API ────────────────────────────────────────────────────
async function searchDataApi(q) {
  const sp = new URLSearchParams({
    part: 'snippet', type: 'video', maxResults: String(TOP_N),
    order: 'relevance', q, key: API_KEY,
  });
  const sr = await fetch('https://www.googleapis.com/youtube/v3/search?' + sp);
  if (!sr.ok) throw new Error(`search.list ${sr.status}`);
  const items = (await sr.json()).items || [];
  const ids = items.map(i => i.id?.videoId).filter(Boolean);
  if (!ids.length) return [];

  const vr = await fetch('https://www.googleapis.com/youtube/v3/videos?' + new URLSearchParams({
    part: 'statistics,contentDetails', id: ids.join(','), key: API_KEY,
  }));
  const stats = {};
  if (vr.ok) for (const v of (await vr.json()).items || []) stats[v.id] = v;

  return items.map(i => ({
    id:       i.id.videoId,
    title:    i.snippet?.title || '',
    channel:  i.snippet?.channelTitle || '',
    views:    Number(stats[i.id.videoId]?.statistics?.viewCount || 0),
    duration: stats[i.id.videoId]?.contentDetails?.duration || null, // ISO 8601
    live:     i.snippet?.liveBroadcastContent === 'live',
  }));
}

// ── Backend 2: results page ────────────────────────────────────────────────
async function searchScrape(q) {
  // sp=EgIQAQ== → filter "Type: Video" (no channels/playlists/shorts shelves)
  const url = 'https://www.youtube.com/results?' + new URLSearchParams({
    search_query: q, sp: 'EgIQAQ==', hl: 'en', gl: 'US',
  });
  const r = await fetch(url, {
    headers: {
      'User-Agent': UA,
      'Accept-Language': 'en-US,en;q=0.9',
      // Skip the EU consent interstitial, which otherwise replaces the page.
      'Cookie': 'CONSENT=YES+cb; SOCS=CAI',
    },
  });
  if (!r.ok) throw new Error(`results page ${r.status}`);
  const html = await r.text();
  const m = html.match(/var ytInitialData = (\{.*?\});<\/script>/s);
  if (!m) throw new Error('ytInitialData not found');
  const data = JSON.parse(m[1]);

  const out = [];
  (function walk(o) {
    if (!o || typeof o !== 'object' || out.length >= TOP_N) return;
    if (o.videoRenderer) {
      const v = o.videoRenderer;
      if (!v.videoId) return;
      const badges = (v.badges || []).map(b => b.metadataBadgeRenderer?.style || '');
      out.push({
        id:       v.videoId,
        title:    (v.title?.runs || []).map(x => x.text).join(''),
        channel:  v.ownerText?.runs?.[0]?.text || '',
        views:    parseViews(v.viewCountText?.simpleText),
        duration: v.lengthText?.simpleText || null,             // "6:00"
        live:     badges.includes('BADGE_STYLE_TYPE_LIVE_NOW') || !v.lengthText,
      });
      return;
    }
    if (Array.isArray(o)) { for (const x of o) walk(x); return; }
    for (const k in o) walk(o[k]);
  })(data.contents);
  return out;
}

function pick(cands) {
  // Prefer non-live; among the relevance window take the most viewed.
  const pool = cands.filter(c => !c.live);
  const list = pool.length ? pool : cands;
  return list.reduce((best, c) => (!best || c.views > best.views ? c : best), null);
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };
  if (event.httpMethod !== 'GET')    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method not allowed' }) };

  const q = (event.queryStringParameters?.q || '').trim().slice(0, MAX_Q_LEN);
  if (!q) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Missing q' }) };

  try {
    const source = API_KEY ? 'data-api' : 'scrape';
    const candidates = API_KEY ? await searchDataApi(q) : await searchScrape(q);
    const picked = pick(candidates);
    if (!picked) return { statusCode: 404, headers: CORS, body: JSON.stringify({ error: 'No results', query: q, source }) };
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ query: q, source, picked, candidates }) };
  } catch (err) {
    console.error('search failed:', err.message);
    return { statusCode: 502, headers: CORS, body: JSON.stringify({ error: 'Search failed', detail: err.message }) };
  }
};
