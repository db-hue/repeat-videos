const { MongoClient } = require('mongodb');
const { createRemoteJWKSet, jwtVerify } = require('jose');

const MONGODB_URI    = process.env.MONGODB_URI;
const AUTH0_DOMAIN   = process.env.AUTH0_DOMAIN;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || 'https://api.repeat-videos.com';
const ADMIN_EMAIL    = 'd.b@nuolix.com';

let mongoClient = null;
let jwks        = null;

async function getDb() {
  if (!mongoClient) {
    mongoClient = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
  }
  try {
    await mongoClient.db('admin').command({ ping: 1 });
  } catch {
    mongoClient = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    await mongoClient.connect();
  }
  return mongoClient.db('repeat-videos');
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
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Content-Type':                 'application/json',
};

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  // 1. Verify JWT
  let payload;
  try {
    payload = await verifyToken(event.headers.authorization);
  } catch (err) {
    return { statusCode: 401, headers: CORS, body: JSON.stringify({ error: 'Unauthorized' }) };
  }

  // 2. Verify admin email — check both token claims and DB record
  const userId = payload.sub;
  const db = await getDb();

  const userDoc = await db.collection('users').findOne({ user_id: userId });
  const email = payload.email || userDoc?.email || null;

  if (email !== ADMIN_EMAIL) {
    return { statusCode: 403, headers: CORS, body: JSON.stringify({ error: 'Forbidden' }) };
  }

  try {
    // 3. Fetch all users with activity stats
    const users = await db.collection('users').find({}, {
      projection: { _id: 0, user_id: 1, email: 1, name: 1, picture: 1, first_login: 1, last_login: 1, login_count: 1 }
    }).sort({ last_login: -1 }).toArray();

    // 4. For each user, get library stats (count + total loops)
    const stats = await db.collection('library').aggregate([
      { $group: {
        _id: '$owner_id',
        videoCount: { $sum: 1 },
        totalLoops: { $sum: '$loops' },
        lastActivity: { $max: '$lastPlayedAt' },
      }}
    ]).toArray();

    const statsMap = {};
    for (const s of stats) statsMap[s._id] = s;

    const result = users.map(u => ({
      ...u,
      videoCount:   statsMap[u.user_id]?.videoCount || 0,
      totalLoops:   statsMap[u.user_id]?.totalLoops || 0,
      lastActivity: statsMap[u.user_id]?.lastActivity || null,
    }));

    return {
      statusCode: 200,
      headers: CORS,
      body: JSON.stringify({ users: result, totalUsers: users.length }),
    };
  } catch (err) {
    console.error('Admin function error:', err);
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'Internal error' }) };
  }
};
