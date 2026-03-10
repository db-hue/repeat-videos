const { MongoClient } = require('mongodb');
const { createRemoteJWKSet, jwtVerify } = require('jose');

const MONGODB_URI    = process.env.MONGODB_URI;
const AUTH0_DOMAIN   = process.env.AUTH0_DOMAIN;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || 'https://api.repeat-videos.com';

let mongoClient = null;
let jwks        = null;

let indexesEnsured = false;

async function getDb() {
  if (!mongoClient) {
    mongoClient = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
  }
  // Ping to check if the connection is still alive; reconnect if stale
  try {
    await mongoClient.db('admin').command({ ping: 1 });
  } catch {
    mongoClient = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    await mongoClient.connect();
  }
  const db = mongoClient.db('repeat-videos');
  // Ensure unique index on (owner_id, videoId) — idempotent, runs once per cold start
  if (!indexesEnsured) {
    indexesEnsured = true;
    db.collection('library').createIndex(
      { owner_id: 1, videoId: 1 },
      { unique: true, background: true }
    ).catch(err => console.warn('Index creation skipped:', err.message));
  }
  return db;
}

function getJWKS() {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`https://${AUTH0_DOMAIN}/.well-known/jwks.json`));
  }
  return jwks;
}

async function verifyToken(authHeader) {
  if (!authHeader?.startsWith('Bearer ')) throw new Error('No token');
  const token = authHeader.slice(7);
  const { payload } = await jwtVerify(token, getJWKS(), {
    audience: AUTH0_AUDIENCE,
    issuer:   `https://${AUTH0_DOMAIN}/`,
  });
  return payload;
}

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Content-Type':                 'application/json',
};

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  let payload;
  try {
    payload = await verifyToken(event.headers.authorization);
  } catch (err) {
    console.error('Token verification failed:', err.message, err.code);
    return { statusCode: 401, headers: CORS, body: JSON.stringify({ error: 'Unauthorized', detail: err.message }) };
  }

  const userId = payload.sub;

  try {
    const db  = await getDb();

    // PUT — track user login
    if (event.httpMethod === 'PUT') {
      const body = JSON.parse(event.body || '{}');
      if (body.action === 'track_login') {
        const users = db.collection('users');
        const now = new Date();
        const userAgent = event.headers['user-agent'] || '';
        await users.updateOne(
          { user_id: userId },
          {
            $setOnInsert: { user_id: userId, first_login: now },
            $set: {
              email: body.email || payload.email || null,
              name: body.name || null,
              picture: body.picture || null,
              last_login: now,
              last_user_agent: userAgent,
            },
            $inc: { login_count: 1 },
          },
          { upsert: true }
        );
        return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true }) };
      }
      return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Unknown action' }) };
    }

    const col = db.collection('library');

    // GET — return all library entries for this user
    if (event.httpMethod === 'GET') {
      const docs = await col.find({ owner_id: userId }, { projection: { _id: 0, owner_id: 0 } }).toArray();
      return { statusCode: 200, headers: CORS, body: JSON.stringify(docs) };
    }

    const body = JSON.parse(event.body || '{}');

    // POST — upsert a video entry (insert only if not already present)
    if (event.httpMethod === 'POST') {
      const { videoId, title, loopA = null, loopB = null, loops = 0, addedAt, playlistId = null } = body;
      await col.updateOne(
        { owner_id: userId, videoId },
        { $setOnInsert: {
            owner_id: userId, videoId, title,
            loops, loopA, loopB, playlistId,
            addedAt: new Date(addedAt || Date.now()),
          }
        },
        { upsert: true }
      );
      return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true }) };
    }

    // PATCH — update fields (increment loops, set title/loopA/loopB)
    if (event.httpMethod === 'PATCH') {
      const { videoId, incLoops, title, loopA, loopB, playlistId } = body;
      const update = {};
      if (incLoops) update.$inc = { loops: 1 };
      const $set = {};
      if (title !== undefined) $set.title = title;
      if (loopA !== undefined) $set.loopA = loopA;
      if (loopB !== undefined) $set.loopB = loopB;
      if (playlistId !== undefined) $set.playlistId = playlistId;
      if (Object.keys($set).length) update.$set = $set;
      if (!Object.keys(update).length) {
        return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'No update fields' }) };
      }
      await col.updateOne({ owner_id: userId, videoId }, update);
      return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true }) };
    }

    // DELETE — remove one video or all
    if (event.httpMethod === 'DELETE') {
      const { videoId, all } = body;
      if (all) {
        await col.deleteMany({ owner_id: userId });
      } else {
        await col.deleteOne({ owner_id: userId, videoId });
      }
      return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true }) };
    }

    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method not allowed' }) };
  } catch (err) {
    console.error('library function error:', err);
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'Internal error', detail: err.message }) };
  }
};
