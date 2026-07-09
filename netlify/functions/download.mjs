// Admin-only audio download. Streams the audio-only MP4 track (AAC, itag 140)
// of a YouTube video to the caller. Gated on the same Auth0 JWT + admin email
// check as admin.js — this endpoint must never be opened to regular users
// (YouTube ToS / AdSense exposure is acceptable only for personal admin use).
//
// Pipeline: BotGuard PO token (bgutils-js + jsdom) → Innertube session
// (youtubei.js) → SABR/UMP audio-only stream (googlevideo). YouTube no longer
// returns direct format URLs to any client, so SABR streaming is required.
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { Innertube, Constants, Platform } from 'youtubei.js';
import { BG, buildURL, GOOG_API_KEY, USER_AGENT } from 'bgutils-js';
import { JSDOM } from 'jsdom';
import { SabrStream } from 'googlevideo/sabr-stream';
import { buildSabrFormat, EnabledTrackTypes } from 'googlevideo/utils';

const AUTH0_DOMAIN   = process.env.AUTH0_DOMAIN;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || 'https://api.repeat-videos.com';
const ADMIN_EMAIL    = 'd.b@nuolix.com';

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
  if (email !== ADMIN_EMAIL) throw Object.assign(new Error('Forbidden'), { status: 403 });
}

// Access tokens don't carry the email claim; resolve it via Auth0's /userinfo
// (the SPA requests the `email` scope). Cached per user id — userinfo is
// rate-limited, and this also keeps the function fully independent of MongoDB.
const emailCache = new Map(); // sub -> email
async function getEmailFromAuth0(authHeader, sub) {
  if (emailCache.has(sub)) return emailCache.get(sub);
  const res = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, { headers: { Authorization: authHeader } });
  if (!res.ok) throw Object.assign(new Error('Could not verify identity'), { status: 401 });
  const email = (await res.json()).email || null;
  if (email) emailCache.set(sub, email);
  return email;
}

// ── YouTube session (cached across warm invocations) ──────────────────────
let ytSession = null; // { yt, expiresAt }

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

// YouTube serves "Sign in to confirm you're not a bot" (LOGIN_REQUIRED) to the
// WEB client from untrusted datacenter IPs (Netlify/AWS egress). TV and embedded
// clients are exempt from that wall, so walk the chain until one is playable.
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

  return { audioStream, title: info.basic_info.title || videoId };
}

function jsonError(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

export default async (request) => {
  if (request.method === 'OPTIONS') {
    return new Response('', {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
      },
    });
  }
  if (request.method !== 'GET') return jsonError(405, 'Method not allowed');

  try {
    await verifyAdmin(request.headers.get('authorization'));
  } catch (err) {
    return jsonError(err.status || 401, err.message);
  }

  const videoId = new URL(request.url).searchParams.get('v');
  if (!videoId || !/^[\w-]{11}$/.test(videoId)) return jsonError(400, 'Invalid or missing video id');

  let result;
  try {
    result = await openAudioStream(videoId);
  } catch (err) {
    if (err.status) return jsonError(err.status, err.message);
    // Session may have gone stale (expired PO token / player change) — re-mint once.
    console.error('Audio stream failed, retrying with fresh session:', err.message);
    try {
      await getYtSession(true);
      result = await openAudioStream(videoId);
    } catch (err2) {
      console.error('Audio stream retry failed:', err2);
      return jsonError(502, `Could not fetch audio: ${err2.message}`);
    }
  }

  const safeTitle = result.title.replace(/[\\/:*?"<>|]+/g, '').trim().slice(0, 120) || videoId;
  const asciiTitle = safeTitle.replace(/[^\x20-\x7E]+/g, '').trim() || videoId;
  return new Response(result.audioStream, {
    status: 200,
    headers: {
      'Content-Type': 'audio/mp4',
      'Content-Disposition': `attachment; filename="${asciiTitle}.m4a"; filename*=UTF-8''${encodeURIComponent(safeTitle)}.m4a`,
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Expose-Headers': 'Content-Disposition',
    },
  });
};
