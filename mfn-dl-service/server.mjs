// Admin-only audio download service — runs on the MF-N home server, exposed
// publicly via Tailscale Funnel. This exists because YouTube bot-walls ALL
// player clients (WEB, TV, embedded, MWEB) from datacenter egress IPs, so the
// same pipeline hosted as a Netlify Function can never work; from the home
// residential IP it works reliably.
//
// Same auth as the old Netlify function: Auth0 JWT + admin email. The
// endpoint must never be opened to regular users (YouTube ToS / AdSense
// exposure is acceptable only for personal admin use). Bonus of running here:
// no 26 s serverless timeout, and hosting is fully off repeat-videos.com's
// infrastructure.
//
// Pipeline: BotGuard PO token (bgutils-js + jsdom) → Innertube session
// (youtubei.js) → SABR/UMP audio-only stream (googlevideo). Optional A/B trim
// via system ffmpeg (stream-copy, packet-accurate for AAC).
import http from 'node:http';
import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { Innertube, Constants, Platform } from 'youtubei.js';
import { BG, buildURL, GOOG_API_KEY, USER_AGENT } from 'bgutils-js';
import { JSDOM } from 'jsdom';
import { SabrStream } from 'googlevideo/sabr-stream';
import { buildSabrFormat, EnabledTrackTypes } from 'googlevideo/utils';

const PORT           = Number(process.env.PORT || 8790);
const AUTH0_DOMAIN   = process.env.AUTH0_DOMAIN || 'dev-wi0i54wuxsdja4bg.us.auth0.com';
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || 'https://api.repeat-videos.com';
const ADMIN_EMAIL    = process.env.ADMIN_EMAIL || 'd.b@nuolix.com';
const FFMPEG         = process.env.FFMPEG_PATH || 'ffmpeg';

// youtubei.js ships no JS evaluator (it removed implicit eval); sig/nsig
// deciphering needs one. data.output defines exportedVars + process().
Platform.shim.eval = async (data, env) => {
  const fn = new Function('env', `${data.output}\nreturn process(env.n ?? '', env.sp ?? '', env.sig ?? '');`);
  return fn(env);
};

let jwks = null;

function getJWKS() {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`https://${AUTH0_DOMAIN}/.well-known/jwks.json`));
  }
  return jwks;
}

async function verifyAdmin(authHeader) {
  if (!authHeader?.startsWith('Bearer ')) throw Object.assign(new Error('Unauthorized'), { status: 401 });
  let payload;
  try {
    ({ payload } = await jwtVerify(authHeader.slice(7), getJWKS(), {
      audience: AUTH0_AUDIENCE,
      issuer:   `https://${AUTH0_DOMAIN}/`,
    }));
  } catch {
    throw Object.assign(new Error('Unauthorized'), { status: 401 });
  }
  let email = payload.email || null;
  if (!email) email = await getEmailFromAuth0(authHeader, payload.sub);
  // Admin is always allowed (no external dependency — this must keep working
  // even when Netlify/Atlas are unreachable). Other users need the
  // can_download grant set in the admin dashboard.
  if (email === ADMIN_EMAIL) return;
  if (!(await isDownloadGranted(authHeader, payload.sub))) {
    throw Object.assign(new Error('Forbidden'), { status: 403 });
  }
}

// Per-user download grants live in MongoDB behind the site's library
// function (this service deliberately has no Mongo dependency). The user's
// own Bearer token is forwarded; the function answers for that user only.
const ENTITLEMENT_URL = process.env.ENTITLEMENT_URL
  || 'https://repeat-videos.com/.netlify/functions/library?me=1';
const grantCache = new Map(); // sub -> { allowed, exp }

async function isDownloadGranted(authHeader, sub) {
  const hit = grantCache.get(sub);
  if (hit && hit.exp > Date.now()) return hit.allowed;
  let allowed = false;
  try {
    const res = await fetch(ENTITLEMENT_URL, {
      headers: { Authorization: authHeader },
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) allowed = (await res.json())?.can_download === true;
  } catch { /* entitlement service unreachable → deny non-admins */ }
  // Denials expire fast so a fresh grant applies within a minute
  grantCache.set(sub, { allowed, exp: Date.now() + (allowed ? 5 : 1) * 60_000 });
  return allowed;
}

// Access tokens don't carry the email claim; resolve it via Auth0's /userinfo
// (the SPA requests the `email` scope). Cached per user id — userinfo is
// rate-limited.
const emailCache = new Map(); // sub -> email
async function getEmailFromAuth0(authHeader, sub) {
  if (emailCache.has(sub)) return emailCache.get(sub);
  const res = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, { headers: { Authorization: authHeader } });
  if (!res.ok) throw Object.assign(new Error('Could not verify identity'), { status: 401 });
  const email = (await res.json()).email || null;
  if (email) emailCache.set(sub, email);
  return email;
}

// ── YouTube session (long-lived process — cache with TTL) ─────────────────
let ytSession = null; // { yt, minter, expiresAt }

async function mintPoToken() {
  const boot = await Innertube.create({ user_agent: USER_AGENT, retrieve_player: false });
  const visitorData = boot.session.context.client.visitorData;
  if (!visitorData) throw new Error('Could not get visitor data');

  if (!globalThis.__bgDomReady) {
    const dom = new JSDOM('<!DOCTYPE html>', {
      url: 'https://www.youtube.com/', referrer: 'https://www.youtube.com/', userAgent: USER_AGENT,
    });
    Object.assign(globalThis, { window: dom.window, document: dom.window.document, location: dom.window.location, origin: dom.window.origin });
    if (!Reflect.has(globalThis, 'navigator')) Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator });
    globalThis.__bgDomReady = true;
  }

  const ch = await boot.getAttestationChallenge('ENGAGEMENT_TYPE_UNBOUND');
  if (!ch.bg_challenge) throw new Error('Could not get BotGuard challenge');
  const interpreterUrl = ch.bg_challenge.interpreter_url.private_do_not_access_or_else_trusted_resource_url_wrapped_value;
  const interpreterJavascript = await (await fetch(`https:${interpreterUrl}`)).text();
  if (!interpreterJavascript) throw new Error('Could not load BotGuard VM');
  new Function(interpreterJavascript)();

  const botguard = await BG.BotGuardClient.create({
    program: ch.bg_challenge.program,
    globalName: ch.bg_challenge.global_name,
    globalObj: globalThis,
  });
  const webPoSignalOutput = [];
  const botguardResponse = await botguard.snapshot({ webPoSignalOutput });

  const itJson = await (await fetch(buildURL('GenerateIT', true), {
    method: 'POST',
    headers: {
      'content-type': 'application/json+protobuf',
      'x-goog-api-key': GOOG_API_KEY,
      'x-user-agent': 'grpc-web-javascript/0.1',
      'user-agent': USER_AGENT,
    },
    body: JSON.stringify(['O43z0dpjhgX20SCx4KAo', botguardResponse]),
  })).json();
  if (typeof itJson[0] !== 'string') throw new Error('Could not get integrity token');

  const minter = await BG.WebPoMinter.create({ integrityToken: itJson[0] }, webPoSignalOutput);
  return { minter, visitorData };
}

async function getYtSession(forceNew = false) {
  if (!forceNew && ytSession && Date.now() < ytSession.expiresAt) return ytSession;
  const { minter, visitorData } = await mintPoToken();
  const sessionPot = await minter.mintAsWebsafeString(visitorData);
  const yt = await Innertube.create({ po_token: sessionPot, visitor_data: visitorData, user_agent: USER_AGENT });
  ytSession = { yt, minter, expiresAt: Date.now() + 45 * 60 * 1000 };
  return ytSession;
}

// From a residential IP the WEB client normally just works; keep the fallback
// chain anyway — it costs nothing unless WEB fails.
const PLAYER_CLIENTS = ['WEB', 'TV', 'TV_EMBEDDED', 'WEB_EMBEDDED', 'MWEB'];

async function openAudioStream(videoId) {
  const { yt, minter } = await getYtSession();
  // The SABR PO token must be CONTENT-bound (minted against the video id).
  // A session-bound token works for most videos but high-protection ones
  // (music labels) stall with streamProtectionStatus=2 and zero media parts.
  const poToken = await minter.mintAsWebsafeString(videoId);

  const failures = [];
  let info = null, clientUsed = null;
  for (const client of PLAYER_CLIENTS) {
    let candidate;
    try {
      candidate = await yt.getBasicInfo(videoId, client);
    } catch (err) {
      failures.push(`${client}: ${err.message}`);
      continue;
    }
    const ps = candidate.playability_status;
    if (ps?.status !== 'OK') {
      failures.push(`${client}: ${ps?.reason || ps?.status}`);
      continue;
    }
    if (!candidate.streaming_data?.server_abr_streaming_url
        || !candidate.player_config?.media_common_config?.media_ustreamer_request_config?.video_playback_ustreamer_config) {
      failures.push(`${client}: playable but no SABR parameters`);
      continue;
    }
    info = candidate;
    clientUsed = client;
    break;
  }
  if (!info) {
    const detail = failures.join(' | ');
    // Bot-check failures may clear with a fresh visitor session — leave them
    // retryable (no status) so the handler re-mints once. Everything else
    // (private, region lock, ...) is a hard 422.
    const retryable = /bot|sign in/i.test(detail);
    throw Object.assign(new Error(`Video not playable: ${detail}`), retryable ? {} : { status: 422 });
  }
  if (clientUsed !== 'WEB') console.log(`Client fallback for ${videoId}: using ${clientUsed} (${failures.join(' | ')})`);

  const serverAbrUrl = await yt.session.player?.decipher(info.streaming_data?.server_abr_streaming_url);
  const ustreamerConfig = info.player_config?.media_common_config?.media_ustreamer_request_config?.video_playback_ustreamer_config;
  if (!serverAbrUrl || !ustreamerConfig) throw new Error('Missing SABR streaming parameters');

  const sabr = new SabrStream({
    formats: (info.streaming_data?.adaptive_formats || []).map(buildSabrFormat),
    serverAbrStreamingUrl: serverAbrUrl,
    videoPlaybackUstreamerConfig: ustreamerConfig,
    durationMs: (info.basic_info.duration || 0) * 1000,
    clientInfo: {
      clientName: parseInt(Constants.CLIENT_NAME_IDS[Constants.CLIENTS[clientUsed].NAME]),
      clientVersion: Constants.CLIENTS[clientUsed].VERSION,
    },
    poToken,
  });

  const { audioStream } = await sabr.start({
    enabledTrackTypes: EnabledTrackTypes.AUDIO_ONLY,
    audioFormat: formats => formats
      .filter(f => f.mimeType?.startsWith('audio/mp4'))
      .sort((a, b) => (b.bitrate || 0) - (a.bitrate || 0))[0],
  });

  return { audioStream, info };
}

// ── Music metadata (best-effort, all sources may fail independently) ───────
// The player response only carries video title / channel / category /
// keywords. Clean song title + artist + genre come from the YT Music
// surface; album only exists for tracks that are part of one; the year is
// parsed from the watch page's "Premiered/published" text.
const eqi = (a, b) => a && b && a.toLowerCase() === b.toLowerCase();

// Strip promo noise from video titles: "(Official Video)", "(Official Music
// Videos)", "[4K Remaster]", "(Lyrics)", "(Video Oficial)", "… - Official
// Music Video", … — none of it belongs in a music tag. Covers plural forms,
// the common "Offical" typo, full-width CJK brackets, and un-bracketed
// trailing phrases.
function cleanVideoTitle(raw) {
  let t = String(raw || '');
  t = t.replace(/\s*[([{（【][^)\]}）】]*\b(off?ici?als?|videos?|audios?|lyrics?|visuali[sz]ers?|remaster(ed)?|hd|4k|8k|m\/?v|explicit|videoclip|oficial|officiel)\b[^)\]}）】]*[)\]}）】]/gi, ' ');
  const tail = /[\s\-–—|:]+(off?ici?als?\s+)?((music|lyrics?)\s+)?(videos?|audios?|visuali[sz]ers?|m\/?v)\s*$/i;
  while (tail.test(t)) t = t.replace(tail, '');
  return t.replace(/\s{2,}/g, ' ').replace(/[\s\-–—|]+$/g, '').trim();
}

async function gatherTags(yt, videoId, info) {
  const tags = {
    title:  cleanVideoTitle(info.basic_info?.title) || videoId,
    artist: (info.basic_info?.author || '').replace(/\s*-\s*Topic\s*$/i, '').replace(/VEVO\s*$/i, '').trim() || null,
    album:  null,
    genre:  info.basic_info?.category || null,
    date:   null,
  };
  // "Artist - Song" convention: prefer the artist named in the title over
  // the channel name (channels are often "SomeartistVEVO" or a label).
  const dash = tags.title.split(/\s+[-–—]\s+/);
  if (dash.length === 2 && dash[0] && dash[1]) {
    tags.artist = dash[0].trim();
    tags.title  = dash[1].trim();
  }
  const keywords = info.basic_info?.keywords || [];
  try {
    const track = await yt.music.getInfo(videoId);
    // The music surface usually returns the clean song title, but not
    // always — run it through the same cleaner.
    if (track.basic_info?.title)  tags.title  = cleanVideoTitle(track.basic_info.title) || tags.title;
    if (track.basic_info?.author) tags.artist = track.basic_info.author;
    // First tag that isn't a variant of the artist/title is usually the
    // genre (e.g. "Latin Urban" for SAOKO). Substring matches are still
    // name echoes ("jawed" → "jawed karim"), not genres.
    // Keywords are only genre-shaped on actual music content; elsewhere
    // they're arbitrary video tags and the category is the honest answer.
    if (info.basic_info?.category === 'Music') {
      const echoes = s => [tags.title, tags.artist].some(x =>
        x && (s.toLowerCase().includes(x.toLowerCase()) || x.toLowerCase().includes(s.toLowerCase())));
      const cand = (track.basic_info?.tags || keywords).find(t => t && !echoes(t));
      if (cand) tags.genre = cand;
    }
    try {
      const upNext  = await track.getUpNext();
      const current = upNext?.contents?.find(c => c.selected);
      const album   = current?.album?.name || current?.album?.text || null;
      if (album) tags.album = String(album);
    } catch { /* album stays null */ }
  } catch { /* fall back to player-response values */ }
  try {
    const full = await yt.getInfo(videoId);
    const published = full.primary_info?.published?.text || '';
    const year = /\b(19|20)\d{2}\b/.exec(published);
    if (year) tags.date = year[0];
  } catch { /* date stays null */ }
  return tags;
}

async function fetchCover(videoId, info) {
  const urls = [
    `https://i.ytimg.com/vi/${videoId}/maxresdefault.jpg`,
    `https://i.ytimg.com/vi/${videoId}/hqdefault.jpg`,
  ];
  const t0 = info.basic_info?.thumbnail?.[0]?.url;
  if (t0 && /\.jpe?g/i.test(new URL(t0).pathname)) urls.unshift(t0);
  for (const url of urls) {
    try {
      const res = await fetch(url);
      if (res.ok) return Buffer.from(await res.arrayBuffer());
    } catch { /* try next */ }
  }
  return null;
}

// Single ffmpeg pass: optional A/B trim + music tags + embedded cover art.
// Stream-copy (no re-encode): AAC packets are all independently decodable,
// so cuts land on packet boundaries (~23 ms) — effectively exact for loop
// use. The SABR stream is fragmented MP4, which ffmpeg demuxes fine from a
// pipe; the output needs a seekable target (moov rewrite), hence the temp
// file.
async function processAudio(audioStream, { start = 0, end = null, tags = {}, cover = null }) {
  const dir = await mkdtemp(join(tmpdir(), 'rvdl-'));
  const outPath = join(dir, 'out.m4a');
  try {
    const args = ['-hide_banner', '-loglevel', 'error', '-y'];
    if (start > 0) args.push('-ss', String(start));
    args.push('-i', 'pipe:0');
    if (cover) {
      const coverPath = join(dir, 'cover.jpg');
      await writeFile(coverPath, cover);
      args.push('-i', coverPath, '-map', '0:a', '-map', '1:v', '-disposition:v:0', 'attached_pic');
    } else {
      args.push('-map', '0:a');
    }
    // Output option — must come after ALL -i inputs, or it would bind to the
    // next input instead of limiting the output duration.
    if (end != null) args.push('-t', String(Math.max(0.1, end - start)));
    for (const [key, value] of Object.entries(tags)) {
      if (value) args.push('-metadata', `${key}=${value}`);
    }
    args.push('-c', 'copy', '-movflags', '+faststart', outPath);
    const proc = spawn(FFMPEG, args, { stdio: ['pipe', 'ignore', 'pipe'] });
    let stderr = '';
    proc.stderr.on('data', d => { stderr += d; });
    await new Promise((resolve, reject) => {
      proc.on('error', reject);
      proc.on('close', code => code === 0
        ? resolve()
        : reject(new Error(`ffmpeg exited ${code}: ${stderr.trim().slice(-300)}`)));
      Readable.fromWeb(audioStream).pipe(proc.stdin)
        .on('error', () => {}); // EPIPE if ffmpeg bails early — surfaced via exit code
    });
    return await readFile(outPath);
  } finally {
    rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

const CORS = {
  'Access-Control-Allow-Origin':   '*',
  'Access-Control-Allow-Headers':  'Authorization, Content-Type',
  'Access-Control-Allow-Methods':  'GET, OPTIONS',
  'Access-Control-Expose-Headers': 'Content-Disposition',
};

function jsonError(res, status, message) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS });
  res.end(JSON.stringify({ error: message }));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === 'OPTIONS') { res.writeHead(204, CORS); res.end(); return; }
  if (url.pathname === '/healthz') { res.writeHead(200, CORS); res.end('ok'); return; }
  if (url.pathname !== '/download') return jsonError(res, 404, 'Not found');
  if (req.method !== 'GET') return jsonError(res, 405, 'Method not allowed');

  // Local testing escape hatch: only honored when DEV_BYPASS=1 is set in the
  // service environment (never set in the systemd unit).
  const bypass = process.env.DEV_BYPASS === '1' && url.searchParams.get('devbypass') === '1';
  if (!bypass) {
    try {
      await verifyAdmin(req.headers.authorization);
    } catch (err) {
      return jsonError(res, err.status || 401, err.message);
    }
  }

  const videoId = url.searchParams.get('v');
  if (!videoId || !/^[\w-]{11}$/.test(videoId)) return jsonError(res, 400, 'Invalid or missing video id');

  // Optional A/B loop trim window (seconds). start defaults to 0; end null = to end.
  let start = 0, end = null;
  if (url.searchParams.get('start') != null) {
    start = Number(url.searchParams.get('start'));
    if (!Number.isFinite(start) || start < 0) return jsonError(res, 400, 'Invalid start');
  }
  if (url.searchParams.get('end') != null) {
    end = Number(url.searchParams.get('end'));
    if (!Number.isFinite(end) || end <= start) return jsonError(res, 400, 'Invalid end');
  }
  const trim = start > 0 || end != null;

  let result;
  try {
    result = await openAudioStream(videoId);
  } catch (err) {
    if (err.status) return jsonError(res, err.status, err.message);
    // Session may have gone stale (expired PO token / player change) — re-mint once.
    console.error('Audio stream failed, retrying with fresh session:', err.message);
    try {
      await getYtSession(true);
      result = await openAudioStream(videoId);
    } catch (err2) {
      console.error('Audio stream retry failed:', err2);
      return jsonError(res, 502, `Could not fetch audio: ${err2.message}`);
    }
  }

  const { yt } = await getYtSession();
  const [tags, cover] = await Promise.all([
    gatherTags(yt, videoId, result.info),
    fetchCover(videoId, result.info),
  ]);

  let body;
  try {
    body = await processAudio(result.audioStream, { start, end: trim ? end : null, tags, cover });
  } catch (err) {
    console.error('Audio processing failed:', err);
    return jsonError(res, 500, `Could not process audio: ${err.message}`);
  }

  const baseName = tags.artist && !eqi(tags.artist, tags.title)
    ? `${tags.artist} - ${tags.title}` : tags.title;
  const suffix = trim ? ' (loop)' : '';
  const safeTitle = (baseName.replace(/[\\/:*?"<>|]+/g, '').trim().slice(0, 120) || videoId) + suffix;
  const asciiTitle = safeTitle.replace(/[^\x20-\x7E]+/g, '').trim() || videoId + suffix;
  res.writeHead(200, {
    'Content-Type': 'audio/mp4',
    'Content-Disposition': `attachment; filename="${asciiTitle}.m4a"; filename*=UTF-8''${encodeURIComponent(safeTitle)}.m4a`,
    'Content-Length': String(body.length),
    'Cache-Control': 'no-store',
    ...CORS,
  });
  res.end(body);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`repeat-videos download service listening on 127.0.0.1:${PORT}`);
});
