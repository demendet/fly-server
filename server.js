import 'dotenv/config';
import express from 'express';
import compression from 'compression';
import cors from 'cors';
import admin from 'firebase-admin';
import { PostgresDatabaseManager } from './database-postgres.js';
import { StateManager } from './state-manager.js';

let firebaseAdmin = null;
try {
  const sa = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (sa) {
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(sa)) });
    firebaseAdmin = admin;
    console.log('[INIT] Firebase Admin initialized');
  }
} catch (err) { console.error('[INIT] Firebase error:', err.message); }

const ADMIN_ROLES = ['admin', 'superadmin', 'root'];
const MODERATOR_ROLES = ['moderator', 'admin', 'superadmin', 'root'];
const mxbmrp3Stats = { totalRequests: 0, requestsToday: 0, lastReset: Date.now(), recentRequests: [], byTrack: {}, byIP: {} };

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing authorization' });
  if (!firebaseAdmin) return res.status(503).json({ error: 'Auth unavailable' });
  try {
    const decoded = await firebaseAdmin.auth().verifyIdToken(auth.split('Bearer ')[1]);
    req.user = decoded;
    req.userId = decoded.uid;
    next();
  } catch (err) { res.status(401).json({ error: 'Invalid token' }); }
}

async function checkRole(req, res, roles) {
  if (!req.userId) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const doc = await firebaseAdmin.firestore().collection('users').doc(req.userId).get();
    if (!doc.exists) return res.status(403).json({ error: 'User not found' });
    const data = doc.data();
    const role = data.role || 'user';
    if (!roles.includes(role)) return res.status(403).json({ error: 'Insufficient permissions' });
    req.userRole = role;
    req.userProfile = data;
    return null;
  } catch (err) { return res.status(500).json({ error: 'Permission check failed' }); }
}

function requireRole(roles) {
  return async (req, res, next) => { const err = await checkRole(req, res, roles); if (!err) next(); };
}
const requireAdmin = async (req, res, next) => { const err = await checkRole(req, res, ADMIN_ROLES); if (!err) next(); };
const requireRoot = async (req, res, next) => { const err = await checkRole(req, res, ['root']); if (!err) next(); };
const requireModerator = async (req, res, next) => { const err = await checkRole(req, res, MODERATOR_ROLES); if (!err) next(); };

const app = express();
const PORT = process.env.PORT || 8080;
const env = {
  DATABASE_URL: process.env.DATABASE_URL,
  MXBIKES_API_URL_1: process.env.MXBIKES_API_URL_1,
  MXBIKES_API_URL_2: process.env.MXBIKES_API_URL_2,
  MXBIKES_API_KEY_1: process.env.MXBIKES_API_KEY_1,
  MXBIKES_API_KEY_2: process.env.MXBIKES_API_KEY_2,
  STEAM_API_KEY: process.env.STEAM_API_KEY,
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET,
};

let stripe = null;
if (env.STRIPE_SECRET_KEY) {
  import('stripe').then(Stripe => {
    stripe = new Stripe.default(env.STRIPE_SECRET_KEY);
    console.log('[INIT] Stripe initialized');
  }).catch(err => console.error('[INIT] Stripe error:', err.message));
}

function guidToSteam64(guid) {
  if (!guid || guid.length !== 18) return null;
  try { return BigInt('0x' + guid.substring(2)).toString(); } catch { return null; }
}

function steam64ToGuid(steam64) {
  if (!steam64) return null;
  try { return 'FF' + BigInt(steam64).toString(16).toUpperCase().padStart(16, '0'); } catch { return null; }
}

async function fetchSteamProfile(steam64) {
  if (!env.STEAM_API_KEY) throw new Error('Steam API key not configured');
  const resp = await fetch(`https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${env.STEAM_API_KEY}&steamids=${steam64}`);
  if (!resp.ok) throw new Error('Failed to fetch Steam profile');
  const data = await resp.json();
  const p = data.response?.players?.[0];
  return p ? { steamId: p.steamid, displayName: p.personaname, profileUrl: p.profileurl, avatar: p.avatar, avatarMedium: p.avatarmedium, avatarFull: p.avatarfull, profileState: p.profilestate, countryCode: p.loccountrycode } : null;
}

let db, stateManager;
let bannedGuidsCache = { guids: [], lastUpdated: 0, syncing: false };

function getAllBannedGuids() { return bannedGuidsCache.guids; }

async function syncBannedGuidsBackground() {
  if (bannedGuidsCache.syncing) return;
  bannedGuidsCache.syncing = true;
  const globalTimeout = setTimeout(() => { console.error('[BAN-SYNC] Global timeout'); bannedGuidsCache.syncing = false; }, 30000);
  try {
    const guids = new Set();
    const sources = getApiSources();
    await Promise.all(sources.map(async (src) => {
      try {
        const servers = await fetchFromManager(src, '/servers', 'GET', null, 5000);
        if (!Array.isArray(servers)) return;
        await Promise.all(servers.map(async (srv) => {
          try {
            const bans = await fetchFromManager(src, `/servers/${srv.id || srv.Id}/bans`, 'GET', null, 3000);
            if (Array.isArray(bans)) bans.forEach(b => { if ((b.isActive ?? b.IsActive ?? true)) guids.add((b.playerGuid || b.PlayerGuid || '').toUpperCase()); });
          } catch {}
        }));
      } catch {}
    }));
    clearTimeout(globalTimeout);
    const newGuids = Array.from(guids);
    if (newGuids.length !== bannedGuidsCache.guids.length) console.log(`[BAN-SYNC] ${newGuids.length} banned GUIDs`);
    bannedGuidsCache = { guids: newGuids, lastUpdated: Date.now(), syncing: false };
  } catch (err) { clearTimeout(globalTimeout); console.error('[BAN-SYNC] Error:', err.message); bannedGuidsCache.syncing = false; }
}

function startBannedGuidsSyncLoop() {
  console.log('[BAN-SYNC] Starting (60s interval)');
  syncBannedGuidsBackground();
  setInterval(syncBannedGuidsBackground, 60000);
}

try {
  db = new PostgresDatabaseManager(env.DATABASE_URL);
  await db.initializeTables();
  stateManager = new StateManager(db, env);
  console.log('[INIT] Database and StateManager initialized');
} catch (err) { console.error('[INIT] Failed:', err.message); process.exit(1); }

const allowedOrigins = ['https://cbrservers.com', 'http://localhost:3000', 'http://localhost:3001', 'http://localhost:5173', 'https://api1.cbrservers.com', 'https://api2.cbrservers.com'];
app.use(compression());
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || allowedOrigins.includes(origin) ? true : 'https://cbrservers.com'),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use((req, res, next) => {
  // Skip JSON parsing for Stripe webhook (needs raw body for signature verification)
  if (req.path === '/api/donations/webhook') return next();
  express.json()(req, res, next);
});

const rateLimitMap = new Map();
setInterval(() => { const now = Date.now(); for (const [ip, d] of rateLimitMap) if (now - d.start > 120000) rateLimitMap.delete(ip); }, 300000);

app.use('/api/', (req, res, next) => {
  if (req.path === '/records/top' || req.path === '/analytics/track') return next();
  if (req.path.match(/^\/player\/[A-Za-z0-9]+$/) && req.method === 'GET') return next();
  if (req.path === '/leaderboards' && req.method === 'GET') return next();
  if (req.path.match(/^\/session\/[A-Za-z0-9_-]+$/) && req.method === 'GET') return next();
  if (req.path === '/donations/webhook') return next(); // Stripe webhook - no origin check
  const origin = req.headers.origin || '', referer = req.headers.referer || '';
  const validOrigins = ['https://cbrservers.com', 'http://localhost:3000', 'http://localhost:5173', 'http://localhost', 'https://api1.cbrservers.com', 'https://api2.cbrservers.com'];
  const isTunneled = req.headers['cf-connecting-ip'] || req.headers['cf-ray'];
  const realIp = req.headers['cf-connecting-ip'] || req.ip || '';
  const isLocal = !isTunneled && (realIp === '::1' || realIp === '127.0.0.1' || realIp === '::ffff:127.0.0.1');
  const apiKey = req.headers['x-api-key'];
  const hasKey = apiKey && (apiKey === env.MXBIKES_API_KEY_1 || apiKey === env.MXBIKES_API_KEY_2);
  if (isLocal || validOrigins.some(o => origin === o || referer.startsWith(o)) || hasKey) return next();
  res.status(403).json({ error: 'Forbidden' });
});

app.use('/api/', (req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
  const now = Date.now();
  let c = rateLimitMap.get(ip);
  if (!c || now - c.start > 60000) c = { count: 1, start: now }; else c.count++;
  rateLimitMap.set(ip, c);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, 500 - c.count));
  if (c.count > 500) return res.status(429).json({ error: 'Too many requests', retryAfter: Math.ceil((c.start + 60000 - now) / 1000) });
  next();
});

app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));
app.get('/', (req, res) => res.send('CBRServers API'));

let allSessionsCache = { data: null, timestamp: 0, generating: false };
let allPlayersCache = { data: null, timestamp: 0, generating: false };
let bulkResponseCache = { data: null, timestamp: 0, generating: false };

async function regenerateAllSessionsCache() {
  if (allSessionsCache.generating) return;
  allSessionsCache.generating = true;
  try {
    const data = await Promise.race([db.getAllFinalizedSessions(), new Promise((_, r) => setTimeout(() => r(new Error('Sessions cache timeout')), 20000))]);
    allSessionsCache = { data, timestamp: Date.now(), generating: false };
  } catch (err) { console.error('[SESSIONS-CACHE] Error:', err.message); allSessionsCache.generating = false; }
}

async function regenerateAllPlayersCache() {
  if (allPlayersCache.generating) return;
  allPlayersCache.generating = true;
  try {
    const data = await Promise.race([db.getAllPlayers(), new Promise((_, r) => setTimeout(() => r(new Error('Players cache timeout')), 20000))]);
    allPlayersCache = { data, timestamp: Date.now(), generating: false };
  } catch (err) { console.error('[PLAYERS-CACHE] Error:', err.message); allPlayersCache.generating = false; }
}

async function regenerateBulkCache() {
  if (bulkResponseCache.generating) return;
  bulkResponseCache.generating = true;
  const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('Bulk cache timeout')), 10000));
  try {
    const [players, sessions, servers, mmr, sr, records, stats, bannedGuids] = await Promise.race([
      Promise.all([
        db.getAllPlayersSlim(), db.getRecentSessions(50), Promise.resolve(stateManager.getCachedServerData()),
        db.getTopPlayersByMMR(100), db.getTopPlayersBySR(100), db.getAllTrackRecords(),
        db.getTotalFinalizedSessionsCount().then(c => ({ totalRaces: c })), Promise.resolve(getAllBannedGuids())
      ]),
      timeout
    ]);
    bulkResponseCache = { data: { players, sessions, servers, leaderboards: { mmr, sr }, records, stats, bannedGuids }, timestamp: Date.now(), generating: false };
  } catch (err) { console.error('[BULK-CACHE] Error:', err.message); bulkResponseCache.generating = false; }
}

function startBulkCacheLoop() {
  console.log('[CACHE] Starting pre-generation loops');
  regenerateBulkCache(); regenerateAllSessionsCache(); regenerateAllPlayersCache();
  setInterval(regenerateBulkCache, 5000);
  setInterval(regenerateAllSessionsCache, 30000);
  setInterval(regenerateAllPlayersCache, 30000);
}

function cachedResponse(res, cache, maxAge = 3) {
  res.set('Cache-Control', `public, max-age=${maxAge}, stale-while-revalidate=${maxAge * 3}`);
  res.set('ETag', `"${cache.timestamp}"`);
  return cache.data;
}

app.get('/api/sessions/all', async (req, res) => {
  try {
    if (allSessionsCache.data) {
      const etag = req.get('If-None-Match');
      if (etag === `"${allSessionsCache.timestamp}"`) return res.status(304).end();
      return res.json(cachedResponse(res, allSessionsCache, 15));
    }
    await regenerateAllSessionsCache();
    res.json(allSessionsCache.data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/players/all', async (req, res) => {
  try {
    if (allPlayersCache.data) {
      const etag = req.get('If-None-Match');
      if (etag === `"${allPlayersCache.timestamp}"`) return res.status(304).end();
      return res.json(cachedResponse(res, allPlayersCache, 15));
    }
    await regenerateAllPlayersCache();
    res.json(allPlayersCache.data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/bulk', async (req, res) => {
  try {
    if (bulkResponseCache.data) {
      const etag = req.get('If-None-Match');
      if (etag === `"${bulkResponseCache.timestamp}"`) return res.status(304).end();
      return res.json(cachedResponse(res, bulkResponseCache));
    }
    await regenerateBulkCache();
    res.json(bulkResponseCache.data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/banned-guids', (req, res) => res.json({ bannedGuids: getAllBannedGuids() }));
app.get('/api/under-investigation', async (req, res) => { try { res.json({ players: await db.getPlayersUnderInvestigation() }); } catch (err) { res.status(500).json({ error: err.message }); } });

app.post('/api/admin/investigate/:guid', requireAuth, requireRole(ADMIN_ROLES), async (req, res) => {
  try {
    const { guid } = req.params;
    let adminName = 'Admin';
    if (firebaseAdmin) { const u = await firebaseAdmin.auth().getUser(req.userId); adminName = u.displayName || u.email || 'Admin'; }
    const result = await db.investigatePlayer(guid.toUpperCase(), req.body.reason || 'Under investigation', adminName);
    console.log(`[ADMIN] ${adminName} investigated ${guid}`);
    res.json({ success: true, ...result });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/admin/restore/:guid', requireAuth, requireRole(ADMIN_ROLES), async (req, res) => {
  try {
    const { guid } = req.params;
    let adminName = 'Admin';
    if (firebaseAdmin) { const u = await firebaseAdmin.auth().getUser(req.userId); adminName = u.displayName || u.email || 'Admin'; }
    const result = await db.restorePlayer(guid.toUpperCase());
    console.log(`[ADMIN] ${adminName} restored ${guid}`);
    res.json({ success: true, ...result });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.get('/api/players', async (req, res) => { try { res.json(await db.getAllPlayers()); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/players/search', async (req, res) => { try { const q = req.query.q || ''; res.json(q.length < 2 ? [] : await db.searchPlayers(q, 100)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/sessions', async (req, res) => { try { res.json(await db.getRecentSessions(parseInt(req.query.limit) || 50)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/session/:sessionId', async (req, res) => { try { const s = await db.getSession(req.params.sessionId); s ? res.json(s) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/sessions/player/:playerGuid', async (req, res) => { try { res.json(await db.searchSessionsByPlayer(req.params.playerGuid, parseInt(req.query.limit) || 100)); } catch (err) { res.status(500).json({ error: err.message }); } });

app.get('/api/player/:guid', async (req, res) => {
  try {
    const result = await db.pool.query('SELECT guid, "displayName", mmr, "safetyRating", "totalRaces", wins, podiums, holeshots, "steamAvatarUrl" FROM players WHERE guid = $1', [req.params.guid.toUpperCase()]);
    if (!result.rows.length) return res.status(404).json({ error: 'Player not found' });
    const r = result.rows[0];
    res.json({ guid: r.guid, displayName: r.displayName, mmr: r.mmr || 1000, safetyRating: r.safetyRating || 0.5, totalRaces: r.totalRaces || 0, wins: r.wins || 0, podiums: r.podiums || 0, holeshots: r.holeshots || 0, profileImageUrl: r.steamAvatarUrl || null });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/player/:guid/sessions', async (req, res) => { try { res.json(await db.getPlayerSessions(req.params.guid.toUpperCase(), parseInt(req.query.limit) || 50)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/leaderboards', async (req, res) => { try { const [mmr, sr] = await Promise.all([db.getTopPlayersByMMR(100), db.getTopPlayersBySR(100)]); res.json({ mmr, safetyRating: sr }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/records', async (req, res) => { try { res.json(await db.getAllTrackRecords()); } catch (err) { res.status(500).json({ error: err.message }); } });

app.get('/api/records/top', async (req, res) => {
  try {
    const { track, limit = 10, category } = req.query;
    const limitNum = Math.min(Math.max(parseInt(limit) || 10, 1), 50);
    const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
    const now = Date.now();
    if (now - mxbmrp3Stats.lastReset > 86400000) { mxbmrp3Stats.requestsToday = 0; mxbmrp3Stats.lastReset = now; }
    mxbmrp3Stats.totalRequests++; mxbmrp3Stats.requestsToday++;
    mxbmrp3Stats.byTrack[track || 'all'] = (mxbmrp3Stats.byTrack[track || 'all'] || 0) + 1;
    mxbmrp3Stats.byIP[ip] = (mxbmrp3Stats.byIP[ip] || 0) + 1;
    mxbmrp3Stats.recentRequests.unshift({ time: now, track: track || 'all', ip });
    if (mxbmrp3Stats.recentRequests.length > 100) mxbmrp3Stats.recentRequests.pop();
    const records = track ? await db.getTrackRecords(track, limitNum, category) : await db.getTopTrackRecords(limitNum, category);
    res.json({ notice: "MXBMRP3 Plugin - Thomas. CBR reserves the right to revoke this endpoint.", records: records.map(r => ({ track: r.trackName, laptime: Math.round(r.lapTime * 1000), player: r.playerName, bike: r.bikeName || 'Unknown', category: r.bikeCategory || null, timestamp: r.setAt ? new Date(r.setAt).toISOString() : null })) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stats', async (req, res) => { try { res.json({ totalRaces: await db.getTotalFinalizedSessionsCount() }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/mxbmrp3-stats', requireAuth, requireRoot, (req, res) => res.json(mxbmrp3Stats));
app.get('/api/servers', async (req, res) => { try { let d = stateManager.getCachedServerData(); if (!d) d = await stateManager.fetchServersFromAPI(); res.json(d); } catch (err) { res.status(500).json({ error: err.message }); } });

app.post('/api/players/link', async (req, res) => {
  try {
    const { playerGuid, displayName } = req.body;
    if (!playerGuid || !/^[0-9a-f]{18}$/i.test(playerGuid)) return res.status(400).json({ error: 'Invalid GUID' });
    if (displayName && (displayName.length > 50 || displayName.length < 1)) return res.status(400).json({ error: 'Invalid name length' });
    const guid = playerGuid.toUpperCase();
    const existing = await db.getPlayer(guid);
    if (existing) return res.json({ success: true, player: existing, existed: true });
    await db.upsertPlayer({ guid, displayName: displayName || `Player_${guid.slice(-8)}`, mmr: 1000, safetyRating: 0.5, totalRaces: 0, wins: 0, podiums: 0, autoGenerated: false, lastSeen: Date.now(), firstSeen: Date.now() });
    res.json({ success: true, player: await db.getPlayer(guid), existed: false });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/players/connect', async (req, res) => {
  try {
    const { playerGuid, playerName, serverName, trackName, raceNumber, bikeName } = req.body;
    if (!playerGuid || !playerName) return res.status(400).json({ error: 'Missing fields' });
    const guid = playerGuid.toUpperCase();
    await db.upsertPlayer({ guid, displayName: playerName, currentServer: serverName || null, currentTrack: trackName || null, raceNumber: raceNumber || null, bikeName: bikeName || null, lastSeen: Date.now(), firstSeen: Date.now(), autoGenerated: true });
    res.json({ success: true, playerGuid: guid, playerName });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/check-pb', async (req, res) => {
  try {
    const { playerGuid, playerName, trackName, lapTime, sessionType, raceNumber, bikeName, bikeCategory, serverId } = req.body;
    let track = trackName;
    if (!track && serverId) track = stateManager.getTrackForServer(serverId);
    if (!playerGuid || !track || !lapTime) return res.status(400).json({ error: 'Missing fields' });
    if (typeof lapTime !== 'number' || lapTime < 10 || lapTime > 1800) return res.status(400).json({ error: 'Invalid lap time' });
    const result = await db.checkSinglePlayerPB({ playerGuid: playerGuid.toUpperCase(), playerName, trackName: track, lapTime, sessionType: sessionType || 'race', raceNumber: raceNumber || 0, bikeName: bikeName || null, bikeCategory: bikeCategory || null });
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/steam/profile/:steamId', async (req, res) => {
  try {
    if (!/^\d{17}$/.test(req.params.steamId)) return res.status(400).json({ error: 'Invalid Steam64 ID' });
    const p = await fetchSteamProfile(req.params.steamId);
    p ? res.json(p) : res.status(404).json({ error: 'Not found' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/steam/profile/guid/:guid', async (req, res) => {
  try {
    const guid = req.params.guid.toUpperCase();
    const steam64 = guidToSteam64(guid);
    if (!steam64) return res.status(400).json({ error: 'Invalid GUID' });
    const p = await fetchSteamProfile(steam64);
    p ? res.json({ ...p, guid }) : res.status(404).json({ error: 'Not found' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/steam/convert/to-guid/:steamId', (req, res) => { const g = steam64ToGuid(req.params.steamId); g ? res.json({ steamId: req.params.steamId, guid: g }) : res.status(400).json({ error: 'Invalid Steam64 ID' }); });
app.get('/api/steam/convert/to-steam/:guid', (req, res) => { const s = guidToSteam64(req.params.guid.toUpperCase()); s ? res.json({ guid: req.params.guid.toUpperCase(), steamId: s }) : res.status(400).json({ error: 'Invalid GUID' }); });

app.post('/api/steam/verify', async (req, res) => {
  try {
    const params = req.body;
    const verifyParams = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) verifyParams.append(k, v);
    verifyParams.set('openid.mode', 'check_authentication');
    const resp = await fetch('https://steamcommunity.com/openid/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: verifyParams.toString() });
    if (!resp.text().then(t => t.includes('is_valid:true'))) return res.status(401).json({ error: 'Steam auth failed' });
    const steamId = params['openid.claimed_id']?.match(/\/id\/(\d+)$/)?.[1];
    if (!steamId) return res.status(400).json({ error: 'No Steam ID' });
    const profile = await fetchSteamProfile(steamId);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    const guid = steam64ToGuid(steamId);
    const existingPlayer = await db.getPlayer(guid);
    let firebaseToken = null, existingFirebaseUser = null;
    if (firebaseAdmin) {
      try {
        const snap = await firebaseAdmin.firestore().collection('users').where('steamId', '==', steamId).limit(1).get();
        let uid;
        if (!snap.empty) { uid = snap.docs[0].id; existingFirebaseUser = { id: uid, ...snap.docs[0].data() }; }
        else uid = `steam_${steamId}`;
        firebaseToken = await firebaseAdmin.auth().createCustomToken(uid, { steamId, guid, provider: 'steam' });
      } catch {}
    }
    res.json({ verified: true, steamProfile: profile, guid, existingPlayer, existingFirebaseUser, firebaseToken });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const steamAvatarCache = new Map();
function getCachedSteamAvatar(guid) { const c = steamAvatarCache.get(guid); if (!c) return undefined; if (Date.now() - c.timestamp > 3600000) { steamAvatarCache.delete(guid); return undefined; } return c.data; }
function setCachedSteamAvatar(guid, data) { steamAvatarCache.set(guid, { data, timestamp: Date.now() }); }

async function syncSteamAvatars() {
  try {
    const guids = await db.getPlayersNeedingAvatarSync(100);
    if (!guids.length) return { done: true };
    const steam64s = guids.map(g => ({ guid: g, steam64: guidToSteam64(g) })).filter(x => x.steam64);
    if (!steam64s.length) return;
    const resp = await fetch(`https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${env.STEAM_API_KEY}&steamids=${steam64s.map(s => s.steam64).join(',')}`, { signal: AbortSignal.timeout(15000) });
    if (!resp.ok) return;
    const players = (await resp.json()).response?.players || [];
    const avatarMap = {};
    const pmap = new Map();
    for (const p of players) { const g = steam64ToGuid(p.steamid); if (g) pmap.set(g, p.avatarfull || p.avatarmedium || p.avatar); }
    for (const g of guids) avatarMap[g] = pmap.get(g) || null;
    await db.batchUpdateSteamAvatars(avatarMap);
  } catch (err) { console.error('[AVATAR SYNC] Error:', err.message); }
}

let avatarSyncInterval = null;
function startAvatarSyncLoop() {
  if (avatarSyncInterval) return;
  console.log('[AVATAR SYNC] Starting (2 min interval)');
  avatarSyncInterval = setInterval(syncSteamAvatars, 120000);
}

app.post('/api/steam/avatars', async (req, res) => {
  try {
    const { guids } = req.body;
    if (!Array.isArray(guids) || !guids.length) return res.status(400).json({ error: 'guids required' });
    const limited = guids.slice(0, 100);
    const avatars = {};
    const uncached = [];
    for (const g of limited) {
      const n = g.toUpperCase();
      const c = getCachedSteamAvatar(n);
      if (c !== undefined) { if (c) avatars[n] = c; }
      else uncached.push(n);
    }
    if (!uncached.length) return res.json({ avatars });
    const steam64s = uncached.map(g => ({ guid: g, steam64: guidToSteam64(g) })).filter(x => x.steam64);
    if (!steam64s.length) { uncached.forEach(g => setCachedSteamAvatar(g, null)); return res.json({ avatars }); }
    const resp = await fetch(`https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${env.STEAM_API_KEY}&steamids=${steam64s.map(s => s.steam64).join(',')}`, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) { uncached.forEach(g => setCachedSteamAvatar(g, null)); return res.json({ avatars }); }
    const players = (await resp.json()).response?.players || [];
    const pmap = new Map();
    for (const p of players) { const g = steam64ToGuid(p.steamid); if (g) pmap.set(g, { avatar: p.avatar, avatarMedium: p.avatarmedium, avatarFull: p.avatarfull, displayName: p.personaname }); }
    for (const g of uncached) { const d = pmap.get(g) || null; setCachedSteamAvatar(g, d); if (d) avatars[g] = d; }
    res.json({ avatars });
  } catch (err) { res.json({ avatars: {} }); }
});

app.post('/api/ban-appeals', requireAuth, async (req, res) => {
  try {
    const { playerGuid, playerName, banReason, banDate, banExpiry, isPermanent, serverName, isGlobal, appealReason, additionalInfo, videoUrl } = req.body;
    if (!playerGuid || !appealReason) return res.status(400).json({ error: 'Missing fields' });
    const canAppeal = await db.canUserAppeal(req.userId, playerGuid.toUpperCase());
    if (!canAppeal.canAppeal) return res.status(403).json({ error: canAppeal.reason, cooldownUntil: canAppeal.cooldownUntil });
    const appeal = await db.createBanAppeal({ playerGuid: playerGuid.toUpperCase(), playerName: playerName || 'Unknown', userId: req.userId, banReason: banReason || 'Unknown', banDate, banExpiry, isPermanent: isPermanent !== false, serverName, isGlobal: isGlobal !== false, appealReason, additionalInfo, videoUrl });
    res.json({ success: true, appeal });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/ban-appeals/my', requireAuth, async (req, res) => { try { await db.autoResolveExpiredAppeals(); res.json(await db.getUserAppeals(req.userId)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/ban-appeals/can-appeal', requireAuth, async (req, res) => { try { if (!req.query.playerGuid) return res.status(400).json({ error: 'Missing playerGuid' }); res.json(await db.canUserAppeal(req.userId, req.query.playerGuid.toUpperCase())); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/ban-appeals', requireAuth, requireModerator, async (req, res) => { try { await db.autoResolveExpiredAppeals(); res.json(await db.getAllAppeals(req.query.status || null)); } catch (err) { res.status(500).json({ error: err.message }); } });

app.post('/api/admin/ban-appeals/:id/claim', requireAuth, requireModerator, async (req, res) => {
  try {
    const adminName = req.userProfile?.displayName || req.user?.email || 'Admin';
    const appeal = await db.claimAppeal(req.params.id, adminName, req.userProfile?.linkedPlayerGuid);
    if (!appeal) return res.status(404).json({ error: 'Not found or claimed' });
    try { await db.createNotification({ userId: appeal.userId, type: 'appeal_claimed', title: 'Ban Appeal Under Review', message: `Your appeal is being reviewed by ${adminName}.`, link: '/ban-appeal', relatedId: appeal.id }); } catch {}
    res.json({ success: true, appeal });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/ban-appeals/:id/resolve', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { accepted, resolution, cooldownHours } = req.body;
    if (typeof accepted !== 'boolean') return res.status(400).json({ error: 'Missing accepted' });
    const adminName = req.userProfile?.displayName || req.user?.email || 'Admin';
    const appeal = await db.resolveAppeal(req.params.id, adminName, req.userProfile?.linkedPlayerGuid, accepted, resolution || '', cooldownHours || 24);
    if (!appeal) return res.status(404).json({ error: 'Not found' });
    if (accepted) {
      const sources = getApiSources();
      for (const src of sources) { try { const servers = await fetchFromManager(src, '/servers'); if (Array.isArray(servers) && servers.length) await fetchFromManager(src, `/servers/${servers[0].id || servers[0].Id}/full-unban`, 'POST', { playerGuid: appeal.playerGuid }).catch(() => fetchFromManager(src, `/servers/${servers[0].id || servers[0].Id}/unban`, 'POST', { playerGuid: appeal.playerGuid })); } catch {} }
      await db.addBanHistory({ playerGuid: appeal.playerGuid, playerName: appeal.playerName, action: 'unban', reason: `Appeal #${appeal.appealIndex} accepted`, isGlobal: true, performedBy: adminName, sourceManager: 'appeal' });
    }
    try { await db.createNotification({ userId: appeal.userId, type: accepted ? 'appeal_accepted' : 'appeal_denied', title: accepted ? 'Ban Appeal Accepted' : 'Ban Appeal Denied', message: accepted ? 'Your appeal was accepted.' : `Your appeal was denied. ${resolution || ''}`, link: '/ban-appeal', relatedId: appeal.id }); } catch {}
    res.json({ success: true, appeal, unbanned: accepted });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/reports', requireAuth, async (req, res) => {
  try {
    const { reporterGuid, reporterName, offenderGuid, offenderName, serverName, reason, description, videoUrl } = req.body;
    if (!offenderGuid || !offenderName || !reason || !description || !videoUrl) return res.status(400).json({ error: 'Missing fields' });
    const report = await db.createReport({ reporterGuid: (reporterGuid || '').toUpperCase(), reporterName: reporterName || 'Unknown', reporterUserId: req.userId, offenderGuid: offenderGuid.toUpperCase(), offenderName, serverName, reason, description, videoUrl });
    res.json({ success: true, report });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reports/my', requireAuth, async (req, res) => { try { res.json(await db.getUserReports(req.userId)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/reports', requireAuth, requireModerator, async (req, res) => { try { res.json(await db.getAllReports(req.query.status || null)); } catch (err) { res.status(500).json({ error: err.message }); } });

app.post('/api/admin/reports/:id/claim', requireAuth, requireModerator, async (req, res) => {
  try {
    const adminName = req.userProfile?.displayName || req.user?.email || 'Admin';
    const report = await db.claimReport(req.params.id, adminName, req.userProfile?.linkedPlayerGuid);
    if (!report) return res.status(404).json({ error: 'Not found or claimed' });
    try { await db.createNotification({ userId: report.reporterUserId, type: 'report_claimed', title: 'Report Under Review', message: `Your report is being reviewed by ${adminName}.`, link: '/report', relatedId: report.id }); } catch {}
    res.json({ success: true, report });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/reports/:id/resolve', requireAuth, requireModerator, async (req, res) => {
  try {
    const { actionTaken, resolution, warningReason } = req.body;
    if (!actionTaken) return res.status(400).json({ error: 'Missing actionTaken' });
    if (actionTaken === 'warned' && !warningReason) return res.status(400).json({ error: 'Warning reason required' });
    const adminName = req.userProfile?.displayName || req.user?.email || 'Admin';
    const report = await db.resolveReport(req.params.id, adminName, req.userProfile?.linkedPlayerGuid, actionTaken, resolution || '');
    if (!report) return res.status(404).json({ error: 'Not found' });
    if (actionTaken === 'warned' && warningReason) {
      const upperGuid = report.offenderGuid.toUpperCase();
      await db.createWarning({ playerGuid: upperGuid, playerName: report.offenderName, reason: warningReason, warnedBy: adminName, warnedByGuid: req.userProfile?.linkedPlayerGuid, reportId: report.id });
      const templates = await db.getMessageTemplates();
      const fmt = (t) => t.replace(/{name}/g, report.offenderName || 'Unknown').replace(/{reason}/g, warningReason).slice(0, 99);
      const sources = getApiSources();
      for (const src of sources) {
        try {
          const servers = await fetchFromManager(src, '/servers');
          if (Array.isArray(servers) && servers.length) {
            const sid = servers[0].id || servers[0].Id;
            if (templates.warningMessageEnabled && templates.warningMessageTemplate) try { await fetchFromManager(src, `/servers/${sid}/message`, 'POST', { message: fmt(templates.warningMessageTemplate), targetGuid: upperGuid }); } catch {}
            if (templates.warningGlobalMessageEnabled && templates.warningGlobalMessageTemplate) try { await fetchFromManager(src, `/servers/${sid}/message`, 'POST', { message: fmt(templates.warningGlobalMessageTemplate) }); } catch {}
          }
        } catch {}
      }
      await new Promise(r => setTimeout(r, 200));
      const banReason = `Warning: ${warningReason} - Acknowledge at cbrservers.com`;
      for (const src of sources) { try { const servers = await fetchFromManager(src, '/servers'); if (Array.isArray(servers) && servers.length) await fetchFromManager(src, `/servers/${servers[0].id || servers[0].Id}/full-ban`, 'POST', { PlayerGuid: upperGuid, PlayerName: report.offenderName, Reason: banReason, Duration: 0, DurationType: 5, IsGlobal: true, SendPrivateMessage: false, SendGlobalMessage: false }).catch(() => {}); } catch {} }
      try { await db.pool.query('UPDATE players SET "isBanned" = true, "banReason" = $1 WHERE guid = $2', [banReason, upperGuid]); } catch {}
      await db.addBanHistory({ playerGuid: upperGuid, playerName: report.offenderName, action: 'ban', reason: banReason, isGlobal: true, isPermanent: true, performedBy: adminName, sourceManager: 'Website (Warning)' });
    }
    if (actionTaken === 'pending_ban') return res.json({ success: true, report });
    try { const txt = actionTaken === 'banned' ? 'action was taken' : actionTaken === 'warned' ? 'a warning was issued' : 'no action was taken'; await db.createNotification({ userId: report.reporterUserId, type: 'report_resolved', title: 'Report Resolved', message: `Your report against ${report.offenderName} - ${txt}.`, link: '/report', relatedId: report.id }); } catch {}
    res.json({ success: true, report });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/reports/:id/transfer', requireAuth, requireModerator, async (req, res) => {
  try {
    const { newAdminGuid, newAdminName } = req.body;
    if (!newAdminGuid || !newAdminName) return res.status(400).json({ error: 'Missing fields' });
    const report = await db.transferReport(req.params.id, newAdminGuid, newAdminName);
    if (!report) return res.status(404).json({ error: 'Not found' });
    try { const snap = await firebaseAdmin.firestore().collection('users').where('linkedPlayerGuid', '==', newAdminGuid.toUpperCase()).limit(1).get(); if (!snap.empty) await db.createNotification({ userId: snap.docs[0].id, type: 'report_transferred', title: 'Report Transferred', message: `Report #${report.reportIndex} transferred to you.`, link: '/admin/reports', relatedId: report.id }); } catch {}
    res.json({ success: true, report });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/ban-appeals/:id/transfer', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { newAdminGuid, newAdminName } = req.body;
    if (!newAdminGuid || !newAdminName) return res.status(400).json({ error: 'Missing fields' });
    const appeal = await db.transferAppeal(req.params.id, newAdminGuid, newAdminName);
    if (!appeal) return res.status(404).json({ error: 'Not found' });
    try { const snap = await firebaseAdmin.firestore().collection('users').where('linkedPlayerGuid', '==', newAdminGuid.toUpperCase()).limit(1).get(); if (!snap.empty) await db.createNotification({ userId: snap.docs[0].id, type: 'appeal_transferred', title: 'Appeal Transferred', message: `Appeal #${appeal.appealIndex} transferred to you.`, link: '/admin/reports', relatedId: appeal.id }); } catch {}
    res.json({ success: true, appeal });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/reports/:id', requireAuth, requireAdmin, async (req, res) => { try { const d = await db.deleteReport(req.params.id); d ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/ban-appeals/:id', requireAuth, requireAdmin, async (req, res) => { try { const d = await db.deleteAppeal(req.params.id); d ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });

app.get('/api/notifications', requireAuth, async (req, res) => { try { res.json(await db.getUserNotifications(req.userId, parseInt(req.query.limit) || 20)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/notifications/unread-count', requireAuth, async (req, res) => { try { res.json({ count: await db.getUnreadNotificationCount(req.userId) }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/notifications/unread-by-type', requireAuth, async (req, res) => { try { res.json(await db.getUnreadNotificationCountsByType(req.userId)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/pending-counts', requireAuth, requireModerator, async (req, res) => { try { res.json(await db.getAdminPendingCounts()); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/notifications/:id/read', requireAuth, async (req, res) => { try { const n = await db.markNotificationRead(req.params.id); n ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/notifications/read-all', requireAuth, async (req, res) => { try { await db.markAllNotificationsRead(req.userId); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); } });

app.get('/api/announcements', async (req, res) => { try { res.json(await db.getActiveAnnouncements()); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/announcements', requireAuth, requireModerator, async (req, res) => { try { res.json(await db.getAllAnnouncements()); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/announcements', requireAuth, requireAdmin, async (req, res) => { try { const { title, message, type, expiresAt } = req.body; if (!title || !message) return res.status(400).json({ error: 'Title and message required' }); res.json({ success: true, announcement: await db.createAnnouncement({ title, message, type: type || 'info', createdBy: req.userId, createdByName: req.userProfile?.displayName || 'Admin', expiresAt }) }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/api/admin/announcements/:id', requireAuth, requireAdmin, async (req, res) => { try { const a = await db.updateAnnouncement(req.params.id, req.body); a ? res.json({ success: true, announcement: a }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/announcements/:id/toggle', requireAuth, requireAdmin, async (req, res) => { try { const a = await db.toggleAnnouncementActive(req.params.id); a ? res.json({ success: true, announcement: a }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/announcements/:id', requireAuth, requireAdmin, async (req, res) => { try { const d = await db.deleteAnnouncement(req.params.id); d ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });

app.get('/api/admin/feature-requests', requireAuth, requireModerator, async (req, res) => { try { res.json(await db.getAllFeatureRequests()); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/feature-requests', requireAuth, requireModerator, async (req, res) => { try { const { title, description, type } = req.body; if (!title || !description) return res.status(400).json({ error: 'Title and description required' }); res.json({ success: true, request: await db.createFeatureRequest({ title, description, type: type || 'feature', submittedBy: req.userId, submittedByName: req.userProfile?.displayName || 'Admin', submittedByGuid: req.userProfile?.guid }) }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/api/admin/feature-requests/:id', requireAuth, requireRoot, async (req, res) => { try { const r = await db.updateFeatureRequest(req.params.id, req.body); r ? res.json({ success: true, request: r }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/feature-requests/:id/vote', requireAuth, requireModerator, async (req, res) => { try { const r = await db.voteFeatureRequest(req.params.id, req.userId, req.body.vote); r ? res.json({ success: true, request: r }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/feature-requests/:id', requireAuth, requireRoot, async (req, res) => { try { const d = await db.deleteFeatureRequest(req.params.id); d ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });

app.get('/api/admin/support-tickets', requireAuth, requireModerator, async (req, res) => { try { res.json(await db.getAllSupportTickets(req.query.status || null)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/api/admin/support-tickets/:id', requireAuth, requireModerator, async (req, res) => { try { const t = await db.updateSupportTicket(req.params.id, { ...req.body, resolvedBy: req.userProfile?.displayName || req.user?.email, resolvedByGuid: req.userProfile?.linkedPlayerGuid }); t ? res.json(t) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/support-tickets/:id', requireAuth, requireAdmin, async (req, res) => { try { const d = await db.deleteSupportTicket(req.params.id); d ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/support-tickets', requireAuth, async (req, res) => { try { const { subject, description, issueType, reporterGuid, reporterName } = req.body; if (!subject || !description || !issueType) return res.status(400).json({ error: 'Missing fields' }); res.json({ ticket: await db.createSupportTicket({ userId: req.userId, userEmail: req.user?.email, reporterGuid, reporterName, issueType, subject, description }) }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/support-tickets/my', requireAuth, async (req, res) => { try { res.json(await db.getUserSupportTickets(req.userId)); } catch (err) { res.status(500).json({ error: err.message }); } });

function getApiSources() { return [{ id: 'manager1', url: env.MXBIKES_API_URL_1, key: env.MXBIKES_API_KEY_1 }, { id: 'manager2', url: env.MXBIKES_API_URL_2, key: env.MXBIKES_API_KEY_2 }].filter(s => s.url && s.key); }

async function fetchFromManager(source, endpoint, method = 'GET', body = null, timeoutMs = 8000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const opts = { method, headers: { 'X-API-Key': source.key, 'Content-Type': 'application/json' }, signal: controller.signal };
    if (body && method !== 'GET') opts.body = JSON.stringify(body);
    const resp = await fetch(`${source.url}${endpoint}`, opts);
    clearTimeout(timeout);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();
    try { return JSON.parse(text); } catch { return { success: true, message: text }; }
  } catch (err) { clearTimeout(timeout); throw err; }
}

async function proxyToManager(endpoint, method = 'GET', body = null) {
  const sources = getApiSources();
  for (const src of sources) { try { return await fetchFromManager(src, endpoint, method, body); } catch {} }
  throw new Error('All API sources failed');
}

async function proxyToAllManagers(endpoint, method = 'GET', body = null) {
  const sources = getApiSources();
  const results = [], errors = [];
  await Promise.all(sources.map(async (src) => { try { results.push({ source: src.id, result: await fetchFromManager(src, endpoint, method, body) }); } catch (e) { errors.push({ source: src.id, error: e.message }); } }));
  return { results, errors };
}

async function proxyToSpecificManager(num, endpoint, method = 'GET', body = null) {
  const sources = getApiSources();
  const src = sources.find(s => s.id === (num === 2 ? 'manager2' : 'manager1'));
  if (!src) throw new Error(`Manager ${num} not configured`);
  return fetchFromManager(src, endpoint, method, body);
}

app.get('/api/player/:guid/ban-status', async (req, res) => {
  try {
    const upperGuid = req.params.guid.toUpperCase();
    const sources = getApiSources();
    let banInfo = null;
    for (const src of sources) {
      if (banInfo) break;
      try {
        const servers = await fetchFromManager(src, '/servers');
        if (!Array.isArray(servers)) continue;
        for (const srv of servers) {
          try {
            const bans = await fetchFromManager(src, `/servers/${srv.id || srv.Id}/bans`);
            const ban = Array.isArray(bans) && bans.find(b => (b.playerGuid || b.PlayerGuid || '').toUpperCase() === upperGuid);
            if (ban) {
              banInfo = { isBanned: true, playerGuid: upperGuid, playerName: ban.playerName || ban.PlayerName || 'Unknown', reason: ban.reason || ban.Reason || 'No reason', bannedAt: ban.bannedAt || ban.BannedAt, expiresAt: ban.expiresAt || ban.ExpiresAt, bannedBy: ban.bannedBy || ban.BannedBy || 'Admin', isGlobal: ban.isGlobal ?? ban.IsGlobal ?? false, isActive: ban.isActive ?? ban.IsActive ?? true, serverName: (ban.isGlobal ?? ban.IsGlobal) ? null : (srv.name || srv.Name) };
              break;
            }
          } catch {}
        }
      } catch {}
    }
    if (banInfo && db) { try { const h = await db.getBanHistory(upperGuid); const b = h?.find(x => x.action === 'ban'); if (b?.performedBy && !['System', 'WebAPI', 'WEBAPI'].includes(b.performedBy)) banInfo.bannedBy = b.performedBy; if (b?.isGlobal !== undefined) banInfo.isGlobal = b.isGlobal; if (b?.evidenceUrl) banInfo.evidenceUrl = b.evidenceUrl; } catch {} }
    res.json(banInfo || { isBanned: false });
  } catch { res.json({ isBanned: false }); }
});

app.get('/api/player/:guid/warnings', async (req, res) => { try { res.json(await db.getPlayerWarnings(req.params.guid.toUpperCase())); } catch (err) { res.status(500).json({ error: 'Failed to fetch warnings' }); } });
app.get('/api/player/:guid/warnings/unacknowledged', async (req, res) => { try { res.json(await db.getUnacknowledgedWarnings(req.params.guid.toUpperCase())); } catch (err) { res.status(500).json({ error: 'Failed to fetch warnings' }); } });

app.post('/api/player/:guid/warnings/:warningId/acknowledge', requireAuth, async (req, res) => {
  try {
    const upperGuid = req.params.guid.toUpperCase();
    const doc = await firebaseAdmin.firestore().collection('users').doc(req.userId).get();
    if (!doc.exists) return res.status(403).json({ error: 'User not found' });
    const linkedGuid = doc.data().linkedPlayerGuid?.toUpperCase();
    if (!linkedGuid || linkedGuid !== upperGuid) return res.status(403).json({ error: 'Not your account' });
    const warning = await db.acknowledgeWarning(req.params.warningId, upperGuid);
    if (!warning) return res.status(404).json({ error: 'Warning not found' });
    const sources = getApiSources();
    const results = [];
    for (const src of sources) { try { const servers = await fetchFromManager(src, '/servers'); if (Array.isArray(servers) && servers.length) { try { await fetchFromManager(src, `/servers/${servers[0].id || servers[0].Id}/full-unban`, 'POST', { PlayerGuid: upperGuid, SendUnbanMessage: false }); results.push({ source: src.id, success: true }); } catch { try { await fetchFromManager(src, `/servers/${servers[0].id || servers[0].Id}/unban`, 'POST', { playerGuid: upperGuid }); results.push({ source: src.id, success: true }); } catch (e) { results.push({ source: src.id, success: false, error: e.message }); } } } } catch {} }
    try { await db.pool.query('UPDATE players SET "isBanned" = false, "banReason" = NULL WHERE guid = $1', [upperGuid]); } catch {}
    res.json({ success: true, warning, unbanResults: results });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/warn', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { playerGuid, playerName, reason, reportId } = req.body;
    if (!playerGuid || !reason) return res.status(400).json({ error: 'GUID and reason required' });
    const upperGuid = playerGuid.toUpperCase();
    const adminName = req.userProfile?.displayName || req.user?.email;
    const warning = await db.createWarning({ playerGuid: upperGuid, playerName: playerName || 'Unknown', reason, warnedBy: adminName, warnedByGuid: req.userProfile?.linkedPlayerGuid, reportId });
    const templates = await db.getMessageTemplates();
    const fmt = (t) => t.replace(/{name}/g, playerName || 'Unknown').replace(/{reason}/g, reason).slice(0, 99);
    const sources = getApiSources();
    const allServers = [];
    for (const src of sources) { try { const servers = await fetchFromManager(src, '/servers'); if (Array.isArray(servers)) servers.forEach(s => allServers.push({ source: src, serverId: s.id || s.Id, serverName: s.name || s.Name })); } catch {} }
    const privateMsg = templates.warningMessageEnabled && templates.warningMessageTemplate ? fmt(templates.warningMessageTemplate) : null;
    const globalMsg = templates.warningGlobalMessageEnabled && templates.warningGlobalMessageTemplate ? fmt(templates.warningGlobalMessageTemplate) : null;
    for (const s of allServers) { if (privateMsg) try { await fetchFromManager(s.source, `/servers/${s.serverId}/message`, 'POST', { message: privateMsg, targetGuid: upperGuid }); } catch {} if (globalMsg) try { await fetchFromManager(s.source, `/servers/${s.serverId}/message`, 'POST', { message: globalMsg }); } catch {} }
    await new Promise(r => setTimeout(r, 200));
    const banReason = `Warning: ${reason} - Acknowledge at cbrservers.com`;
    for (const src of sources) { const s = allServers.find(x => x.source.id === src.id); if (s) try { await fetchFromManager(src, `/servers/${s.serverId}/full-ban`, 'POST', { PlayerGuid: upperGuid, PlayerName: playerName || 'Unknown', Reason: banReason, Duration: 0, DurationType: 5, IsGlobal: true, SendPrivateMessage: false, SendGlobalMessage: false }); } catch {} }
    try { await db.pool.query('UPDATE players SET "isBanned" = true, "banReason" = $1 WHERE guid = $2', [banReason, upperGuid]); } catch {}
    await db.addBanHistory({ playerGuid: upperGuid, playerName: playerName || 'Unknown', action: 'ban', reason: banReason, isGlobal: true, isPermanent: true, performedBy: adminName, sourceManager: 'Website (Warning)' });
    res.json({ success: true, warning });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/warnings/:id', requireAuth, requireAdmin, async (req, res) => { try { const d = await db.deleteWarning(req.params.id); d ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/warnings/acknowledged', requireAuth, requireModerator, async (req, res) => { try { res.json(await db.getRecentAcknowledgedWarnings(parseInt(req.query.limit) || 50)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/warnings', requireAuth, requireModerator, async (req, res) => { try { res.json((await db.pool.query('SELECT * FROM player_warnings ORDER BY "createdAt" DESC LIMIT 100')).rows); } catch (err) { res.status(500).json({ error: err.message }); } });

app.get('/api/admin/bans', requireAuth, requireModerator, async (req, res) => {
  try {
    const sources = getApiSources();
    const bansMap = new Map();
    await Promise.all(sources.map(async (src) => {
      try {
        const servers = await fetchFromManager(src, '/servers');
        if (!Array.isArray(servers)) return;
        for (const srv of servers) {
          try {
            const bans = await fetchFromManager(src, `/servers/${srv.id || srv.Id}/bans`);
            if (!Array.isArray(bans)) continue;
            for (const b of bans) {
              const guid = (b.playerGuid || b.PlayerGuid || '').toUpperCase();
              if (!guid) continue;
              const ban = { id: b.id || b.Id, playerGuid: guid, playerName: b.playerName || b.PlayerName || 'Unknown', reason: b.reason || b.Reason || 'No reason', bannedAt: b.bannedAt || b.BannedAt, expiresAt: b.expiresAt || b.ExpiresAt, bannedBy: b.bannedBy || b.BannedBy || 'System', isGlobal: b.isGlobal ?? b.IsGlobal ?? true, isActive: b.isActive ?? b.IsActive ?? true, sourceManager: src.id, serverName: srv.name || srv.Name };
              const existing = bansMap.get(guid);
              if (!existing || new Date(ban.bannedAt || 0) > new Date(existing.bannedAt || 0)) bansMap.set(guid, ban);
            }
          } catch {}
        }
      } catch {}
    }));
    const bans = Array.from(bansMap.values());
    for (const ban of bans) { try { const h = await db.getBanHistory(ban.playerGuid); const b = h?.filter(x => x.action === 'ban')?.[0]; if (b?.performedBy && !['System', 'WebAPI', 'WEBAPI'].includes(b.performedBy)) ban.bannedBy = b.performedBy; } catch {} }
    res.json({ bans, totalUnique: bans.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/servers/:serverId/bans', requireAuth, requireModerator, async (req, res) => { try { for (const src of getApiSources()) { try { return res.json(await fetchFromManager(src, `/servers/${req.params.serverId}/bans`)); } catch {} } res.json([]); } catch (err) { res.status(500).json({ error: err.message }); } });

app.post('/api/admin/ban', requireAuth, requireAdmin, async (req, res) => {
  try {
    const banData = req.body;
    const sources = getApiSources();
    const adminName = req.userProfile?.displayName || req.user?.email || 'Admin';
    const isGlobal = banData.isGlobal !== false;
    const isPermanent = banData.durationType === 'Permanent' || !banData.duration;
    let expiresAt = null;
    if (!isPermanent && banData.duration) {
      const ms = { 'Minutes': 60000, 'Hours': 3600000, 'Days': 86400000, 'Months': 2592000000, 'Years': 31536000000 }[banData.durationType] || 3600000;
      expiresAt = Date.now() + banData.duration * ms;
    }
    const templates = await db.getMessageTemplates();
    const durStr = isPermanent ? 'permanently' : `${banData.duration} ${banData.durationType?.toLowerCase() || 'hours'}`;
    const fmt = (t) => t.replace(/{name}/g, banData.playerName || 'Unknown').replace(/{reason}/g, banData.reason || 'No reason').replace(/{duration}/g, durStr).slice(0, 99);
    const allServers = [];
    for (const src of sources) { try { const servers = await fetchFromManager(src, '/servers'); if (Array.isArray(servers)) servers.forEach(s => allServers.push({ source: src, serverId: s.id || s.Id, serverName: s.name || s.Name })); } catch {} }
    const privateMsg = templates.banPrivateMessageEnabled && templates.banPrivateMessageTemplate ? fmt(templates.banPrivateMessageTemplate) : null;
    const globalMsg = templates.banGlobalMessageEnabled && templates.banGlobalMessageTemplate ? fmt(templates.banGlobalMessageTemplate) : null;
    for (const s of allServers) { if (privateMsg) try { await fetchFromManager(s.source, `/servers/${s.serverId}/message`, 'POST', { message: privateMsg, targetGuid: banData.playerGuid }); } catch {} if (globalMsg) try { await fetchFromManager(s.source, `/servers/${s.serverId}/message`, 'POST', { message: globalMsg }); } catch {} }
    const results = [], errors = [];
    for (const src of sources) { const s = allServers.find(x => x.source.id === src.id); if (!s) continue; try { await fetchFromManager(src, `/servers/${s.serverId}/full-ban`, 'POST', { ...banData, isGlobal, bannedBy: adminName, SendPrivateMessage: false, SendGlobalMessage: false }); results.push({ source: src.id }); } catch (e) { try { await fetchFromManager(src, `/servers/${s.serverId}/ban`, 'POST', { ...banData, isGlobal }); results.push({ source: src.id }); } catch (e2) { errors.push({ source: src.id, error: e2.message }); } } }
    if (results.length) { try { await db.addBanHistory({ playerGuid: banData.playerGuid, playerName: banData.playerName, action: 'ban', reason: banData.reason, duration: banData.duration, durationType: banData.durationType, isGlobal: true, isPermanent, expiresAt, performedBy: adminName, sourceManager: results.map(r => r.source).join(','), evidenceUrl: banData.evidenceUrl }); await db.reduceSafetyRating(banData.playerGuid, 120); } catch {} }
    res.json({ success: results.length > 0, results, errors, message: results.length ? `Banned on ${results.length} manager(s)` : 'Ban failed' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/servers/:serverId/ban', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const banData = req.body;
    const sources = getApiSources();
    const adminName = req.userProfile?.displayName || req.user?.email || 'Admin';
    const isGlobal = banData.isGlobal === true;
    const isPermanent = banData.durationType === 'Permanent' || !banData.duration;
    let expiresAt = null, serverName = null, targetSource = null;
    if (!isPermanent && banData.duration) { const ms = { 'Minutes': 60000, 'Hours': 3600000, 'Days': 86400000, 'Months': 2592000000, 'Years': 31536000000 }[banData.durationType] || 3600000; expiresAt = Date.now() + banData.duration * ms; }
    for (const src of sources) { try { const servers = await fetchFromManager(src, '/servers'); const srv = Array.isArray(servers) && servers.find(s => (s.id || s.Id) === serverId); if (srv) { targetSource = src; serverName = srv.name || srv.Name; break; } } catch {} }
    if (!targetSource) return res.status(400).json({ error: 'Server not found' });
    const templates = await db.getMessageTemplates();
    const durStr = isPermanent ? 'permanently' : `${banData.duration} ${banData.durationType?.toLowerCase() || 'hours'}`;
    const fmt = (t) => t.replace(/{name}/g, banData.playerName || 'Unknown').replace(/{reason}/g, banData.reason || 'No reason').replace(/{duration}/g, durStr).slice(0, 99);
    if (templates.banPrivateMessageEnabled && templates.banPrivateMessageTemplate) try { await fetchFromManager(targetSource, `/servers/${serverId}/message`, 'POST', { message: fmt(templates.banPrivateMessageTemplate), targetGuid: banData.playerGuid }); } catch {}
    if (templates.banGlobalMessageEnabled && templates.banGlobalMessageTemplate) try { await fetchFromManager(targetSource, `/servers/${serverId}/message`, 'POST', { message: fmt(templates.banGlobalMessageTemplate) }); } catch {}
    try { await fetchFromManager(targetSource, `/servers/${serverId}/full-ban`, 'POST', { ...banData, isGlobal, bannedBy: adminName, SendPrivateMessage: false, SendGlobalMessage: false }); } catch { await fetchFromManager(targetSource, `/servers/${serverId}/ban`, 'POST', { ...banData, isGlobal }); }
    try { await db.addBanHistory({ playerGuid: banData.playerGuid, playerName: banData.playerName, action: 'ban', reason: banData.reason, duration: banData.duration, durationType: banData.durationType, isGlobal: false, isPermanent, expiresAt, performedBy: adminName, sourceManager: targetSource.id, serverName, evidenceUrl: banData.evidenceUrl }); await db.reduceSafetyRating(banData.playerGuid, 120); } catch {}
    res.json({ success: true, message: `Banned on ${serverName}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/unban', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { playerGuid, playerName } = req.body;
    const sources = getApiSources();
    const adminName = req.userProfile?.displayName || req.user?.email || 'Admin';
    const templates = await db.getMessageTemplates();
    const allServers = [];
    for (const src of sources) { try { const servers = await fetchFromManager(src, '/servers'); if (Array.isArray(servers)) servers.forEach(s => allServers.push({ source: src, serverId: s.id || s.Id, serverName: s.name || s.Name })); } catch {} }
    if (templates.unbanMessageEnabled && templates.unbanMessageTemplate) { const msg = templates.unbanMessageTemplate.replace(/{name}/g, playerName || 'Unknown').slice(0, 99); for (const s of allServers) try { await fetchFromManager(s.source, `/servers/${s.serverId}/message`, 'POST', { message: msg }); } catch {} }
    const results = [];
    for (const src of sources) { const s = allServers.find(x => x.source.id === src.id); if (!s) continue; try { await fetchFromManager(src, `/servers/${s.serverId}/full-unban`, 'POST', { playerGuid, SendUnbanMessage: false }).catch(() => fetchFromManager(src, `/servers/${s.serverId}/unban`, 'POST', { playerGuid })); results.push({ source: src.id }); } catch {} }
    if (results.length) try { await db.addBanHistory({ playerGuid, playerName: playerName || 'Unknown', action: 'unban', reason: null, isGlobal: true, performedBy: adminName, sourceManager: results.map(r => r.source).join(',') }); } catch {}
    res.json({ success: results.length > 0, message: `Unbanned from ${results.length} manager(s)`, results });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/servers/:serverId/unban', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/unban`, 'POST', { playerGuid: req.body.playerGuid })); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/ban-history', requireAuth, requireAdmin, async (req, res) => { try { res.json(await db.getAllBanHistory(200)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/ban-history/:playerGuid', requireAuth, requireAdmin, async (req, res) => { try { res.json(await db.getBanHistory(req.params.playerGuid)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/ban-history/entry/:entryId', requireAuth, requireAdmin, async (req, res) => { try { const d = await db.deleteBanHistoryEntry(req.params.entryId); d ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });

app.post('/api/admin/sync-bans', requireAuth, requireAdmin, async (req, res) => {
  try {
    const sources = getApiSources();
    if (sources.length < 2) return res.json({ success: true, message: 'Only one manager', synced: 0 });
    const managerBans = {};
    for (const src of sources) { try { const servers = await fetchFromManager(src, '/servers'); if (Array.isArray(servers) && servers.length) { const bans = await fetchFromManager(src, `/servers/${servers[0].id || servers[0].Id}/bans`); managerBans[src.id] = { source: src, serverId: servers[0].id || servers[0].Id, bans: Array.isArray(bans) ? bans : [] }; } } catch {} }
    const ids = Object.keys(managerBans);
    if (ids.length < 2) return res.json({ success: false, error: 'Could not reach managers' });
    const results = [];
    for (const srcId of ids) {
      for (const tgtId of ids) {
        if (srcId === tgtId) continue;
        const srcBans = managerBans[srcId].bans;
        const tgtGuids = new Set(managerBans[tgtId].bans.map(b => (b.playerGuid || b.PlayerGuid || '').toUpperCase()));
        for (const ban of srcBans) {
          const guid = (ban.playerGuid || ban.PlayerGuid || '').toUpperCase();
          if (!guid || tgtGuids.has(guid)) continue;
          try { await fetchFromManager(managerBans[tgtId].source, `/servers/${managerBans[tgtId].serverId}/ban`, 'POST', { PlayerName: ban.playerName || ban.PlayerName, PlayerGuid: guid, Reason: ban.reason || ban.Reason || 'Synced', Duration: 0, DurationType: 'Permanent', IsGlobal: true }); results.push({ from: srcId, to: tgtId, playerGuid: guid, success: true }); } catch (e) { results.push({ from: srcId, to: tgtId, playerGuid: guid, success: false, error: e.message }); }
        }
      }
    }
    res.json({ success: true, synced: results.filter(r => r.success).length, total: results.length, results });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/servers/:serverId/kick', requireAuth, requireModerator, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { playerGuid, playerName, reason } = req.body;
    const templates = await db.getMessageTemplates();
    const fmt = (t) => t.replace(/{name}/g, playerName || 'Unknown').replace(/{reason}/g, reason || 'No reason').slice(0, 99);
    if (templates.kickPrivateMessageEnabled && templates.kickPrivateMessageTemplate) try { await proxyToManager(`/servers/${serverId}/message`, 'POST', { message: fmt(templates.kickPrivateMessageTemplate), targetGuid: playerGuid }); } catch {}
    if (templates.kickGlobalMessageEnabled && templates.kickGlobalMessageTemplate) try { await proxyToManager(`/servers/${serverId}/message`, 'POST', { message: fmt(templates.kickGlobalMessageTemplate) }); } catch {}
    await new Promise(r => setTimeout(r, 100));
    res.json(await proxyToManager(`/servers/${serverId}/kick`, 'POST', { playerGuid, playerName, reason, SendPrivateMessage: false, SendGlobalMessage: false }));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/servers/:serverId/start', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/start`, 'POST')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/stop', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/stop`, 'POST')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/restart', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/restart`, 'POST')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/message', requireAuth, requireModerator, async (req, res) => { try { const { message, targetGuid } = req.body; res.json(await proxyToManager(`/servers/${req.params.serverId}/message`, 'POST', targetGuid ? { message, targetGuid } : { message })); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/config', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/config`, 'POST', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/servers/:serverId', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToSpecificManager(parseInt(req.query.source) || 1, `/servers/${req.params.serverId}`, 'DELETE')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager('/servers', 'POST', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/reset-track', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/reset-track`, 'POST')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/start-session', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/start-session`, 'POST', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/blackflag', requireAuth, requireModerator, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/blackflag`, 'POST', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/makeadmin', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/makeadmin`, 'POST', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/remoteadmin/command', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/remoteadmin/command`, 'POST', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/servers/:serverId/admins', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/admins`, 'GET')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/admins', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/admins`, 'POST', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/servers/:serverId/admins/:adminId', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/admins/${req.params.adminId}`, 'DELETE')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/servers/:serverId/whitelist', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/whitelist`, 'GET')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/whitelist', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/whitelist`, 'POST', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/api/admin/servers/:serverId/whitelist/:entryIndex', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/whitelist/${req.params.entryIndex}`, 'PUT', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/servers/:serverId/whitelist/:entryId', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/whitelist/${req.params.entryId}`, 'DELETE')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/whitelist/reload', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/whitelist/reload`, 'POST')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/tracks', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToSpecificManager(parseInt(req.query.source) || 1, '/tracks', 'GET')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/servers/:serverId/config', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/config`, 'GET')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/api/admin/servers/:serverId/config', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToManager(`/servers/${req.params.serverId}/config`, 'PUT', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/create', requireAuth, requireAdmin, async (req, res) => { try { res.json(await proxyToSpecificManager(parseInt(req.query.source) || 1, '/servers/create', 'POST', req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });

const analyticsCache = { pageViews: [], activeVisitors: new Map(), lastFlush: Date.now() };
function getDeviceType(ua) { if (!ua) return 'unknown'; const l = ua.toLowerCase(); if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/i.test(l)) return 'mobile'; if (/ipad|tablet|playbook|silk/i.test(l)) return 'tablet'; return 'desktop'; }

app.post('/api/analytics/track', express.text({ type: '*/*' }), async (req, res) => {
  try {
    let data; try { data = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; } catch { return res.status(400).json({ error: 'Invalid JSON' }); }
    const { visitorId, sessionId, userId, page, type, timestamp, userAgent, screenWidth } = data;
    if (!visitorId || !sessionId) return res.status(400).json({ error: 'Missing fields' });
    analyticsCache.activeVisitors.set(visitorId, { lastSeen: Date.now(), sessionId, page });
    if (type !== 'session_end') analyticsCache.pageViews.push({ visitorId, sessionId, userId, page: page || '/', deviceType: getDeviceType(userAgent), screenWidth, timestamp: timestamp || new Date().toISOString() });
    const now = Date.now(); for (const [id, v] of analyticsCache.activeVisitors) if (now - v.lastSeen > 300000) analyticsCache.activeVisitors.delete(id);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Track failed' }); }
});

async function flushAnalyticsToFirestore() {
  if (!firebaseAdmin || !analyticsCache.pageViews.length) return;
  try {
    const fs = firebaseAdmin.firestore();
    const batch = fs.batch();
    const today = new Date().toISOString().split('T')[0];
    const dailyRef = fs.collection('analytics_daily').doc(today);
    const dailyDoc = await dailyRef.get();
    let d = dailyDoc.exists ? dailyDoc.data() : { date: today, uniqueVisitors: 0, pageViews: 0, visitors: [], pageViewsByPage: {}, deviceBreakdown: { desktop: 0, mobile: 0, tablet: 0 }, hourlyActivity: Array(24).fill(0) };
    if (!d.hourlyActivity) d.hourlyActivity = Array(24).fill(0);
    const visitors = new Set(d.visitors || []);
    for (const pv of analyticsCache.pageViews) {
      d.pageViews++;
      if (!visitors.has(pv.visitorId)) { visitors.add(pv.visitorId); d.uniqueVisitors++; }
      d.pageViewsByPage[pv.page] = (d.pageViewsByPage[pv.page] || 0) + 1;
      if (pv.deviceType && d.deviceBreakdown[pv.deviceType] !== undefined) d.deviceBreakdown[pv.deviceType]++;
      const hour = new Date(pv.timestamp).getUTCHours();
      d.hourlyActivity[hour] = (d.hourlyActivity[hour] || 0) + 1;
    }
    d.visitors = Array.from(visitors);
    d.lastUpdated = new Date().toISOString();
    batch.set(dailyRef, d, { merge: true });
    batch.set(fs.collection('analytics_totals').doc('summary'), { totalPageViews: admin.firestore.FieldValue.increment(analyticsCache.pageViews.length), lastUpdated: new Date().toISOString() }, { merge: true });
    await batch.commit();
    analyticsCache.pageViews = [];
    analyticsCache.lastFlush = Date.now();
  } catch (err) { console.error('[ANALYTICS] Flush error:', err.message); }
}
setInterval(flushAnalyticsToFirestore, 60000);

app.get('/api/admin/analytics', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (!firebaseAdmin) return res.status(503).json({ error: 'Analytics unavailable' });
    const range = req.query.range || '7d';
    const days = range === '90d' ? 90 : range === '30d' ? 30 : 7;
    const startDate = new Date(); startDate.setDate(startDate.getDate() - days);
    const fs = firebaseAdmin.firestore();
    const snap = await fs.collection('analytics_daily').where('date', '>=', startDate.toISOString().split('T')[0]).orderBy('date', 'asc').get();
    const dailyStats = []; let totalPageViews = 0; const allVisitors = new Set(); const pageViewsByPage = {}; const deviceBreakdown = { desktop: 0, mobile: 0, tablet: 0 }; const hourlyActivity = Array(24).fill(0);
    snap.forEach(doc => {
      const d = doc.data();
      dailyStats.push({ date: d.date, uniqueVisitors: d.uniqueVisitors || 0, pageViews: d.pageViews || 0 });
      totalPageViews += d.pageViews || 0;
      (d.visitors || []).forEach(v => allVisitors.add(v));
      for (const [p, c] of Object.entries(d.pageViewsByPage || {})) pageViewsByPage[p] = (pageViewsByPage[p] || 0) + c;
      if (d.deviceBreakdown) { deviceBreakdown.desktop += d.deviceBreakdown.desktop || 0; deviceBreakdown.mobile += d.deviceBreakdown.mobile || 0; deviceBreakdown.tablet += d.deviceBreakdown.tablet || 0; }
      if (d.hourlyActivity) for (let i = 0; i < 24; i++) hourlyActivity[i] += d.hourlyActivity[i] || 0;
    });
    const today = new Date().toISOString().split('T')[0];
    const todayDoc = await fs.collection('analytics_daily').doc(today).get();
    const todayData = todayDoc.exists ? todayDoc.data() : { uniqueVisitors: 0, pageViews: 0 };
    const totalsDoc = await fs.collection('analytics_totals').doc('summary').get();
    const totalsData = totalsDoc.exists ? totalsDoc.data() : { totalPageViews: 0 };
    res.json({ dailyStats, topPages: Object.entries(pageViewsByPage).map(([page, views]) => ({ page, views })).sort((a, b) => b.views - a.views).slice(0, 10), deviceBreakdown, hourlyActivity: hourlyActivity.map((v, h) => ({ hour: h, visitors: v })), summary: { totalVisitors: allVisitors.size, todayVisitors: todayData.uniqueVisitors || 0, totalPageViews: totalsData.totalPageViews || totalPageViews, activeNow: analyticsCache.activeVisitors.size, avgSessionDuration: 180, bounceRate: 35, newVisitors: Math.round(allVisitors.size * 0.4), returningVisitors: Math.round(allVisitors.size * 0.6) } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/settings/messages', requireAuth, requireAdmin, async (req, res) => { try { res.json(await db.getMessageTemplates()); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/api/admin/settings/messages', requireAuth, requireAdmin, async (req, res) => { try { res.json(await db.updateMessageTemplates(req.body)); } catch (err) { res.status(500).json({ error: err.message }); } });

app.get('/api/admin/servers/:serverId/automatedmessages', requireAuth, requireModerator, async (req, res) => { try { res.json(await db.getAutomatedMessagesByServer(req.params.serverId)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/servers/:serverId/automatedmessages', requireAuth, requireAdmin, async (req, res) => { try { const { message, intervalMinutes, isEnabled, isGlobal, serverName } = req.body; if (!message) return res.status(400).json({ error: 'Message required' }); res.json(await db.createAutomatedMessage({ message: message.slice(0, 99), intervalMinutes: intervalMinutes || 5, isEnabled: isEnabled !== false, isGlobal: isGlobal || false, serverId: isGlobal ? null : req.params.serverId, serverName: isGlobal ? null : serverName })); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/api/admin/servers/:serverId/automatedmessages/:messageId', requireAuth, requireAdmin, async (req, res) => { try { const { message, intervalMinutes, isEnabled, isGlobal } = req.body; const r = await db.updateAutomatedMessage(req.params.messageId, { message: message?.slice(0, 99), intervalMinutes, isEnabled, isGlobal }); r ? res.json(r) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/servers/:serverId/automatedmessages/:messageId', requireAuth, requireAdmin, async (req, res) => { try { const d = await db.deleteAutomatedMessage(req.params.messageId); d ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/settings/automatedmessages', requireAuth, requireModerator, async (req, res) => { try { res.json({ messages: await db.getAllAutomatedMessages(), errors: [] }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/settings/automatedmessages', requireAuth, requireAdmin, async (req, res) => { try { const { serverId, serverName, message, intervalMinutes, isEnabled, isGlobal } = req.body; if (!message) return res.status(400).json({ error: 'Message required' }); res.json(await db.createAutomatedMessage({ message: message.slice(0, 99), intervalMinutes: intervalMinutes || 5, isEnabled: isEnabled !== false, isGlobal: isGlobal || false, serverId: isGlobal ? null : serverId, serverName: isGlobal ? null : serverName })); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/admin/settings/automatedmessages/:messageId', requireAuth, requireAdmin, async (req, res) => { try { const d = await db.deleteAutomatedMessage(req.params.messageId); d ? res.json({ success: true }) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/api/admin/settings/automatedmessages/:messageId', requireAuth, requireAdmin, async (req, res) => { try { const { message, intervalMinutes, isEnabled, isGlobal } = req.body; const r = await db.updateAutomatedMessage(req.params.messageId, { message: message?.slice(0, 99), intervalMinutes, isEnabled, isGlobal }); r ? res.json(r) : res.status(404).json({ error: 'Not found' }); } catch (err) { res.status(500).json({ error: err.message }); } });

let autoMsgInterval = null;
async function processAutomatedMessages() {
  try {
    const due = await db.getDueAutomatedMessages();
    if (!due.length) return;
    const sources = getApiSources();
    if (!sources.length) return;
    const allServers = [];
    for (const src of sources) { try { const servers = await fetchFromManager(src, '/servers'); if (Array.isArray(servers)) servers.forEach(s => allServers.push({ ...s, source: src, serverId: s.id || s.Id, playerCount: s.currentPlayerCount || s.CurrentPlayerCount || s.playersOnline || 0 })); } catch {} }
    if (!allServers.length) return;
    const withPlayers = allServers.filter(s => s.playerCount > 0);
    for (const msg of due) {
      try {
        if (msg.isGlobal) { let sent = 0; for (let i = 0; i < withPlayers.length; i++) { try { await fetchFromManager(withPlayers[i].source, `/servers/${withPlayers[i].serverId}/message`, 'POST', { message: msg.message }); sent++; if (i < withPlayers.length - 1) await new Promise(r => setTimeout(r, 3000)); } catch {} } if (sent) console.log(`[AUTO-MSG] Global "${msg.message.slice(0, 30)}..." to ${sent} servers`); }
        else if (msg.serverId) { const srv = allServers.find(s => s.serverId === msg.serverId); if (srv && srv.playerCount > 0) { await fetchFromManager(srv.source, `/servers/${srv.serverId}/message`, 'POST', { message: msg.message }); console.log(`[AUTO-MSG] "${msg.message.slice(0, 30)}..." to ${msg.serverName || msg.serverId}`); } }
        await db.updateAutomatedMessageLastSent(msg.id);
      } catch {}
    }
  } catch (err) { console.error('[AUTO-MSG] Error:', err.message); }
}

function startAutomatedMessagesLoop() { if (autoMsgInterval) return; console.log('[AUTO-MSG] Starting (30s interval)'); processAutomatedMessages(); autoMsgInterval = setInterval(processAutomatedMessages, 30000); }
function stopAutomatedMessagesLoop() { if (autoMsgInterval) { clearInterval(autoMsgInterval); autoMsgInterval = null; } }

// Stripe donation endpoints
app.post('/api/donations/create-checkout', async (req, res) => {
  try {
    if (!stripe) return res.status(503).json({ error: 'Payments not configured' });
    const { amount, message, isAnonymous } = req.body;
    if (!amount || amount < 100) return res.status(400).json({ error: 'Minimum donation is $1' });
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card', 'link'],
      line_items: [{
        price_data: { currency: 'usd', product_data: { name: 'Donation to CBR Servers', description: 'Thank you for supporting us' }, unit_amount: amount },
        quantity: 1
      }],
      mode: 'payment',
      success_url: `${req.headers.origin || 'https://cbrservers.com'}/support-us?success=true`,
      cancel_url: `${req.headers.origin || 'https://cbrservers.com'}/support-us?canceled=true`,
      metadata: { message: message || '', isAnonymous: isAnonymous ? 'true' : 'false' }
    });
    res.json({ sessionId: session.id, url: session.url });
  } catch (err) { console.error('[STRIPE] Checkout error:', err.message); res.status(500).json({ error: err.message }); }
});

app.post('/api/donations/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !env.STRIPE_WEBHOOK_SECRET) return res.status(503).send('Webhooks not configured');
  const sig = req.headers['stripe-signature'];
  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, env.STRIPE_WEBHOOK_SECRET);
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      await db.createDonation({
        stripePaymentId: session.payment_intent,
        stripeCustomerId: session.customer,
        email: session.customer_details?.email,
        name: session.customer_details?.name,
        amount: session.amount_total,
        currency: session.currency,
        status: 'completed',
        message: session.metadata?.message || null,
        isAnonymous: session.metadata?.isAnonymous === 'true'
      });
      console.log(`[STRIPE] Donation received: $${(session.amount_total / 100).toFixed(2)}`);
    }
    res.json({ received: true });
  } catch (err) { console.error('[STRIPE] Webhook error:', err.message); res.status(400).send(`Webhook Error: ${err.message}`); }
});

app.get('/api/admin/donations', requireAuth, requireRoot, async (req, res) => {
  try {
    const [donations, stats] = await Promise.all([db.getAllDonations(), db.getDonationStats()]);
    res.json({ donations, stats });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, async () => {
  console.log(`[SERVER] Running on port ${PORT}`);
  const machineId = process.env.FLY_MACHINE_ID || 'local';
  await db.initLeaderTable();
  startBannedGuidsSyncLoop();
  startBulkCacheLoop();
  let isLeader = false, updateLoopInterval = null, cycleRunning = false, cycleStartTime = 0, consecutiveSkips = 0;
  const startUpdateLoop = async () => {
    if (updateLoopInterval) return;
    console.log(`[SERVER] Starting update loop`);
    await stateManager.recoverStateFromDatabase();
    try { await stateManager.runUpdateCycle(); } catch (err) { console.error('[SERVER] Initial fetch error:', err.message); }
    updateLoopInterval = setInterval(async () => {
      if (cycleRunning) { const age = Date.now() - cycleStartTime; consecutiveSkips++; if (age > 20000 || consecutiveSkips >= 8) { if (stateManager.currentAbortController) stateManager.currentAbortController.abort(); cycleRunning = false; consecutiveSkips = 0; } else return; }
      try { if (!await db.isLeader(machineId)) { stopUpdateLoop(); isLeader = false; return; } } catch {}
      cycleRunning = true; cycleStartTime = Date.now(); consecutiveSkips = 0;
      try { await stateManager.runUpdateCycle(); } catch {} finally { cycleRunning = false; }
    }, 5000);
  };
  const stopUpdateLoop = () => { if (updateLoopInterval) { clearInterval(updateLoopInterval); updateLoopInterval = null; } };
  setInterval(async () => { if (isLeader) await db.sendLeaderHeartbeat(machineId); }, 5000);
  const checkLeadership = async () => {
    let acquired = false;
    try { acquired = await db.tryAcquireLeadership(machineId, 15000); } catch { return; }
    if (acquired && !isLeader) { isLeader = true; console.log(`[SERVER] Leader acquired`); await startUpdateLoop(); startAvatarSyncLoop(); startAutomatedMessagesLoop(); }
    else if (!acquired && isLeader) { isLeader = false; console.log(`[SERVER] Lost leadership`); stopUpdateLoop(); stopAutomatedMessagesLoop(); }
  };
  await checkLeadership();
  setInterval(checkLeadership, 3000);
  console.log(`[SERVER] Started as ${isLeader ? 'PRIMARY' : 'SECONDARY'}`);
  const shutdown = async () => { console.log('[SERVER] Shutting down...'); if (isLeader) await db.releaseLeadership(machineId); process.exit(0); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
});
