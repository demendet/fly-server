import 'dotenv/config';
import express from 'express';
import compression from 'compression';
import cors from 'cors';
import admin from 'firebase-admin';
import { PostgresDatabaseManager } from './database-postgres.js';
import { StateManager } from './state-manager.js';
let firebaseAdmin = null;
try {
  const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (serviceAccount) {
    const credentials = JSON.parse(serviceAccount);
    admin.initializeApp({
      credential: admin.credential.cert(credentials)
    });
    firebaseAdmin = admin;
    console.log('[INIT] Firebase Admin SDK initialized');
  } else {
    console.log('[INIT] Firebase Admin SDK not configured (FIREBASE_SERVICE_ACCOUNT not set)');
  }
} catch (err) {
  console.error('[INIT] Firebase Admin SDK initialization failed:', err.message);
}

const ADMIN_ROLES = ['admin', 'superadmin', 'root'];
const MODERATOR_ROLES = ['moderator', 'admin', 'superadmin', 'root'];

const mxbmrp3Stats = {
  totalRequests: 0,
  requestsToday: 0,
  lastReset: Date.now(),
  recentRequests: [],
  byTrack: {},
  byIP: {}
};

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  if (!firebaseAdmin) {
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }

  const token = authHeader.split('Bearer ')[1];
  try {
    const decoded = await firebaseAdmin.auth().verifyIdToken(token);
    req.user = decoded;
    req.userId = decoded.uid;
    next();
  } catch (err) {
    console.error('[AUTH] Token verification failed:', err.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function requireRole(allowedRoles) {
  return async (req, res, next) => {
    if (!req.userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
      const userDoc = await firebaseAdmin.firestore().collection('users').doc(req.userId).get();
      if (!userDoc.exists) {
        return res.status(403).json({ error: 'User profile not found' });
      }

      const userData = userDoc.data();
      const userRole = userData.role || 'user';

      if (!allowedRoles.includes(userRole)) {
        console.log(`[AUTH] Access denied for ${req.userId} (role: ${userRole}, required: ${allowedRoles.join('/')})`);
        return res.status(403).json({ error: 'Insufficient permissions' });
      }

      req.userRole = userRole;
      req.userProfile = userData;
      next();
    } catch (err) {
      console.error('[AUTH] Role check failed:', err.message);
      return res.status(500).json({ error: 'Failed to verify permissions' });
    }
  };
}

async function requireAdmin(req, res, next) {
  if (!req.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const userDoc = await firebaseAdmin.firestore().collection('users').doc(req.userId).get();
    if (!userDoc.exists) {
      return res.status(403).json({ error: 'User profile not found' });
    }

    const userData = userDoc.data();
    const userRole = userData.role || 'user';

    if (!ADMIN_ROLES.includes(userRole)) {
      console.log(`[AUTH] Admin access denied for ${req.userId} (role: ${userRole})`);
      return res.status(403).json({ error: 'Admin access required' });
    }

    req.userRole = userRole;
    req.userProfile = userData;
    next();
  } catch (err) {
    console.error('[AUTH] Admin check failed:', err.message);
    return res.status(500).json({ error: 'Failed to verify permissions' });
  }
}

async function requireRoot(req, res, next) {
  if (!req.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const userDoc = await firebaseAdmin.firestore().collection('users').doc(req.userId).get();
    if (!userDoc.exists) {
      return res.status(403).json({ error: 'User profile not found' });
    }

    const userData = userDoc.data();
    const userRole = userData.role || 'user';

    if (userRole !== 'root') {
      return res.status(403).json({ error: 'Root access required' });
    }

    req.userRole = userRole;
    req.userProfile = userData;
    next();
  } catch (err) {
    console.error('[AUTH] Root check failed:', err.message);
    return res.status(500).json({ error: 'Failed to verify permissions' });
  }
}

async function requireModerator(req, res, next) {
  if (!req.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const userDoc = await firebaseAdmin.firestore().collection('users').doc(req.userId).get();
    if (!userDoc.exists) {
      return res.status(403).json({ error: 'User profile not found' });
    }

    const userData = userDoc.data();
    const userRole = userData.role || 'user';

    if (!MODERATOR_ROLES.includes(userRole)) {
      console.log(`[AUTH] Moderator access denied for ${req.userId} (role: ${userRole})`);
      return res.status(403).json({ error: 'Moderator access required' });
    }

    req.userRole = userRole;
    req.userProfile = userData;
    next();
  } catch (err) {
    console.error('[AUTH] Moderator check failed:', err.message);
    return res.status(500).json({ error: 'Failed to verify permissions' });
  }
}

const app = express();
const PORT = process.env.PORT || 8080;

const env = {
  DATABASE_URL: process.env.DATABASE_URL,
  MXBIKES_API_URL_1: process.env.MXBIKES_API_URL_1,
  MXBIKES_API_URL_2: process.env.MXBIKES_API_URL_2,
  MXBIKES_API_KEY_1: process.env.MXBIKES_API_KEY_1,
  MXBIKES_API_KEY_2: process.env.MXBIKES_API_KEY_2,
  STEAM_API_KEY: process.env.STEAM_API_KEY,
};

function guidToSteam64(guid) {
  if (!guid || guid.length !== 18) return null;
  try {
    const steamHex = guid.substring(2);
    return BigInt('0x' + steamHex).toString();
  } catch (e) {
    return null;
  }
}

function steam64ToGuid(steam64) {
  if (!steam64) return null;
  try {
    const steamHex = BigInt(steam64).toString(16).toUpperCase().padStart(16, '0');
    return 'FF' + steamHex;
  } catch (e) {
    return null;
  }
}

async function fetchSteamProfile(steam64) {
  if (!env.STEAM_API_KEY) {
    throw new Error('Steam API key not configured');
  }

  const response = await fetch(
    `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${env.STEAM_API_KEY}&steamids=${steam64}`
  );

  if (!response.ok) {
    throw new Error('Failed to fetch Steam profile');
  }

  const data = await response.json();

  if (!data.response?.players?.length) {
    return null;
  }

  const player = data.response.players[0];
  return {
    steamId: player.steamid,
    displayName: player.personaname,
    profileUrl: player.profileurl,
    avatar: player.avatar,
    avatarMedium: player.avatarmedium,
    avatarFull: player.avatarfull,
    profileState: player.profilestate,
    countryCode: player.loccountrycode
  };
}

let db;
let stateManager;

// Banned GUIDs cache - background sync every 60 seconds, ALWAYS serve from cache
let bannedGuidsCache = { guids: [], lastUpdated: 0, syncing: false };
const BANNED_CACHE_SYNC_INTERVAL = 60000; // Sync every 60 seconds in background

// ALWAYS returns from cache instantly - never blocks on network requests
function getAllBannedGuids() {
  return bannedGuidsCache.guids;
}

// Background sync function - runs independently, never blocks API requests
async function syncBannedGuidsBackground() {
  if (bannedGuidsCache.syncing) {
    return; // Already syncing
  }

  bannedGuidsCache.syncing = true;
  const startTime = Date.now();

  try {
    const bannedGuids = new Set();
    const sources = getApiSources();

    // Fetch from all managers in parallel for speed
    await Promise.all(sources.map(async (source) => {
      try {
        const managerServersResp = await fetchFromManager(source, '/servers');
        const managerServers = Array.isArray(managerServersResp) ? managerServersResp : [];

        // Fetch bans from all servers in parallel
        await Promise.all(managerServers.map(async (server) => {
          const serverId = server.id || server.Id;
          try {
            const bans = await fetchFromManager(source, `/servers/${serverId}/bans`);
            if (Array.isArray(bans)) {
              for (const ban of bans) {
                const isActive = ban.isActive ?? ban.IsActive ?? true;
                if (isActive) {
                  const guid = (ban.playerGuid || ban.PlayerGuid || '').toUpperCase();
                  if (guid) bannedGuids.add(guid);
                }
              }
            }
          } catch (err) {
            // Ignore individual server errors
          }
        }));
      } catch (err) {
        // Ignore manager errors
      }
    }));

    const newGuids = Array.from(bannedGuids);
    const elapsed = Date.now() - startTime;

    // Only log if there's a change or it's been a while
    if (newGuids.length !== bannedGuidsCache.guids.length) {
      console.log(`[BAN-SYNC] Updated: ${newGuids.length} banned GUIDs (took ${elapsed}ms)`);
    }

    bannedGuidsCache = { guids: newGuids, lastUpdated: Date.now(), syncing: false };
  } catch (err) {
    console.error('[BAN-SYNC] Error:', err.message);
    bannedGuidsCache.syncing = false;
  }
}

// Start background ban sync loop
function startBannedGuidsSyncLoop() {
  console.log('[BAN-SYNC] Starting background sync (every 60s)...');

  // Initial sync
  syncBannedGuidsBackground();

  // Schedule recurring sync
  setInterval(syncBannedGuidsBackground, BANNED_CACHE_SYNC_INTERVAL);
}

try {
  db = new PostgresDatabaseManager(env.DATABASE_URL);
  await db.initializeTables();
  stateManager = new StateManager(db, env);
  console.log('[INIT] PostgreSQL Database and StateManager initialized');
} catch (err) {
  console.error('[INIT] Failed to initialize:', err.message);
  process.exit(1);
}

const allowedOrigins = ['https://cbrservers.com', 'http://localhost:3000', 'http://localhost:3001', 'http://localhost:5173', 'https://api1.cbrservers.com', 'https://api2.cbrservers.com'];
app.use(compression());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, 'https://cbrservers.com');
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());

// Rate limiting - 500 requests per minute per IP (high limit for normal use)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 500; // 500 requests per minute

// Clean up old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of rateLimitMap.entries()) {
    if (now - data.start > RATE_LIMIT_WINDOW * 2) {
      rateLimitMap.delete(ip);
    }
  }
}, 300000);

// Origin/Referer check - only allow requests from our domains or with valid API key
app.use('/api/', (req, res, next) => {
  // MXBMRP3 public endpoint - skip origin check
  if (req.path === '/records/top') return next();
  // Analytics tracking - public endpoint for sendBeacon
  if (req.path === '/analytics/track') return next();
  // CBR overlay plugin - player lookup by GUID
  if (req.path.match(/^\/player\/[A-Za-z0-9]+$/) && req.method === 'GET') return next();

  const origin = req.headers.origin || '';
  const referer = req.headers.referer || req.headers.referrer || '';
  const validOrigins = ['https://cbrservers.com', 'http://localhost:3000', 'http://localhost:5173', 'http://localhost', 'https://api1.cbrservers.com', 'https://api2.cbrservers.com'];

  // Check if request came through Cloudflare Tunnel (has CF headers)
  const isTunneled = req.headers['cf-connecting-ip'] || req.headers['cf-ray'];

  // Get real IP - use Cloudflare's header if tunneled, otherwise req.ip
  const realIp = req.headers['cf-connecting-ip'] || req.ip || '';

  // Only allow localhost bypass for NON-tunneled requests (actual local requests)
  const isRealLocalhost = !isTunneled && (realIp === '::1' || realIp === '127.0.0.1' || realIp === '::ffff:127.0.0.1');

  // Check Origin header (sent by browsers for cross-origin requests)
  const isValidOrigin = validOrigins.some(o => origin === o || origin.startsWith(o));

  // Check Referer header (fallback)
  const isValidReferer = validOrigins.some(r => referer.startsWith(r));

  // Check for valid API key (for server-to-server calls from Manager API)
  const apiKey = req.headers['x-api-key'];
  const hasValidApiKey = apiKey && (apiKey === env.MXBIKES_API_KEY_1 || apiKey === env.MXBIKES_API_KEY_2);

  // Allow if origin OR referer matches, OR it's real localhost, OR has valid API key
  const isValid = isRealLocalhost || isValidOrigin || isValidReferer || hasValidApiKey;

  if (!isValid) {
    console.log(`[BLOCKED] ${realIp} - Origin: ${origin || 'none'} - Referer: ${referer || 'none'} - Tunneled: ${!!isTunneled}`);
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});

// Rate limiting - 500 requests per minute per IP
app.use('/api/', (req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
  const now = Date.now();

  let client = rateLimitMap.get(ip);

  if (!client || now - client.start > RATE_LIMIT_WINDOW) {
    client = { count: 1, start: now };
  } else {
    client.count++;
  }

  rateLimitMap.set(ip, client);

  // Add rate limit headers
  res.setHeader('X-RateLimit-Limit', RATE_LIMIT_MAX);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, RATE_LIMIT_MAX - client.count));

  if (client.count > RATE_LIMIT_MAX) {
    console.log(`[RATE LIMIT] Blocked ${ip} - ${client.count} requests in window`);
    return res.status(429).json({
      error: 'Too many requests',
      retryAfter: Math.ceil((client.start + RATE_LIMIT_WINDOW - now) / 1000)
    });
  }

  next();
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/', (req, res) => {
  res.send('CBRServers API');
});

// =============================================================================
// ALL SESSIONS CACHE (for Recent Sessions page - refreshes every 30 seconds)
// =============================================================================
let allSessionsCache = { data: null, timestamp: 0, generating: false };
const ALL_SESSIONS_REFRESH_INTERVAL = 30000; // 30 seconds - historical data

async function regenerateAllSessionsCache() {
  if (allSessionsCache.generating) return;
  allSessionsCache.generating = true;
  try {
    const sessions = await db.getAllFinalizedSessions();
    allSessionsCache = { data: sessions, timestamp: Date.now(), generating: false };
  } catch (err) {
    console.error('[ALL-SESSIONS-CACHE] Error:', err.message);
    allSessionsCache.generating = false;
  }
}

// =============================================================================
// ALL PLAYERS CACHE (for Players page - refreshes every 30 seconds)
// =============================================================================
let allPlayersCache = { data: null, timestamp: 0, generating: false };
const ALL_PLAYERS_REFRESH_INTERVAL = 30000; // 30 seconds

async function regenerateAllPlayersCache() {
  if (allPlayersCache.generating) return;
  allPlayersCache.generating = true;
  try {
    const players = await db.getAllPlayers();
    allPlayersCache = { data: players, timestamp: Date.now(), generating: false };
  } catch (err) {
    console.error('[ALL-PLAYERS-CACHE] Error:', err.message);
    allPlayersCache.generating = false;
  }
}

// =============================================================================
// BULK ENDPOINT WITH BACKGROUND PRE-GENERATION
// The response is always ready in memory - ZERO wait time for DB queries
// =============================================================================
let bulkResponseCache = { data: null, timestamp: 0, generating: false };
const BULK_REFRESH_INTERVAL = 3000; // Regenerate every 3 seconds

// Background function to pre-generate bulk response
async function regenerateBulkCache() {
  if (bulkResponseCache.generating) return;
  bulkResponseCache.generating = true;

  try {
    const startTime = Date.now();

    const [players, sessions, servers, leaderboardMMR, leaderboardSR, records, stats, bannedGuids] = await Promise.all([
      db.getAllPlayersSlim(),                // ALL players slim (guid, name, mmr, sr, avatar) - fast
      db.getRecentSessions(50),              // 50 recent for fast Dashboard/Live
      Promise.resolve(stateManager.getCachedServerData()),
      db.getTopPlayersByMMR(100),
      db.getTopPlayersBySR(100),
      db.getAllTrackRecords(),               // ALL records - no compromise
      db.getTotalFinalizedSessionsCount().then(count => ({ totalRaces: count })),
      Promise.resolve(getAllBannedGuids())
    ]);

    const queryTime = Date.now() - startTime;

    bulkResponseCache = {
      data: {
        players,
        sessions,
        servers,
        leaderboards: { mmr: leaderboardMMR, sr: leaderboardSR },
        records,
        stats,
        bannedGuids
      },
      timestamp: Date.now(),
      generating: false
    };

    // Only log occasionally to avoid spam
    if (queryTime > 1000) {
      console.log(`[BULK-CACHE] Regenerated in ${queryTime}ms (${players.length} players, ${records.length} records)`);
    }
  } catch (err) {
    console.error('[BULK-CACHE] Error regenerating:', err.message);
    bulkResponseCache.generating = false;
  }
}

// Start background bulk cache regeneration loop
function startBulkCacheLoop() {
  console.log('[BULK-CACHE] Starting background pre-generation (every 3s)...');
  console.log('[ALL-SESSIONS-CACHE] Starting background pre-generation (every 30s)...');
  console.log('[ALL-PLAYERS-CACHE] Starting background pre-generation (every 30s)...');

  // Initial generation
  regenerateBulkCache();
  regenerateAllSessionsCache();
  regenerateAllPlayersCache();

  // Schedule recurring regeneration
  setInterval(regenerateBulkCache, BULK_REFRESH_INTERVAL);
  setInterval(regenerateAllSessionsCache, ALL_SESSIONS_REFRESH_INTERVAL);
  setInterval(regenerateAllPlayersCache, ALL_PLAYERS_REFRESH_INTERVAL);
}

// All sessions endpoint - cached separately, refreshes every 30s
app.get('/api/sessions/all', async (req, res) => {
  try {
    if (allSessionsCache.data) {
      return res.json(allSessionsCache.data);
    }
    // Fallback if cache not ready
    await regenerateAllSessionsCache();
    res.json(allSessionsCache.data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// All players endpoint - full player data, cached separately, refreshes every 30s
app.get('/api/players/all', async (req, res) => {
  try {
    if (allPlayersCache.data) {
      return res.json(allPlayersCache.data);
    }
    // Fallback if cache not ready
    await regenerateAllPlayersCache();
    res.json(allPlayersCache.data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/bulk', async (req, res) => {
  try {
    // INSTANT response from pre-generated cache
    if (bulkResponseCache.data) {
      return res.json(bulkResponseCache.data);
    }

    // Fallback: Generate on-demand if cache not ready yet (only on first request after startup)
    console.log('[BULK] Cache not ready, generating on-demand...');
    await regenerateBulkCache();
    res.json(bulkResponseCache.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint to get all banned player GUIDs
app.get('/api/banned-guids', async (req, res) => {
  try {
    const bannedGuids = await getAllBannedGuids();
    res.json({ bannedGuids });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/players', async (req, res) => {
  try {
    const players = await db.getAllPlayers();
    res.json(players);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Search players by name - for finding older/inactive players
app.get('/api/players/search', async (req, res) => {
  try {
    const query = req.query.q || '';
    if (query.length < 2) {
      return res.json([]);
    }
    const players = await db.searchPlayers(query, 100);
    res.json(players);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sessions', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const sessions = await db.getRecentSessions(limit);
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/session/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = await db.getSession(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    res.json(session);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Search sessions by player GUID - find all sessions a player participated in
app.get('/api/sessions/player/:playerGuid', async (req, res) => {
  try {
    const { playerGuid } = req.params;
    const limit = parseInt(req.query.limit) || 100;
    const sessions = await db.searchSessionsByPlayer(playerGuid, limit);
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/cleanup-rotation-servers', async (req, res) => {
  try {
    const { secretKey } = req.body;
    if (secretKey !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const results = { sessions: 0, playerSessions: 0, contacts: 0, holeshots: 0, trackRecords: 0 };

    const ROTATION_SERVERS = [
      '%PunkerJeffy Rotation 1%',
      '%PunkerJeffy Rotation 2%',
      '%ARK SX ROTATING%',
      '%KMX Rotation%',
      '%Kellz Rotation%',
    ];

    for (const serverPattern of ROTATION_SERVERS) {
      const sessions = await db.client.execute({
        sql: 'SELECT id FROM sessions WHERE serverName LIKE ?',
        args: [serverPattern]
      });

      for (const row of sessions.rows) {
        const sessionId = row.id;
        const ps = await db.client.execute({ sql: 'DELETE FROM player_sessions WHERE sessionId = ?', args: [sessionId] });
        const c = await db.client.execute({ sql: 'DELETE FROM contacts WHERE sessionId = ?', args: [sessionId] });
        const h = await db.client.execute({ sql: 'DELETE FROM holeshots WHERE sessionId = ?', args: [sessionId] });
        results.playerSessions += ps.rowsAffected || 0;
        results.contacts += c.rowsAffected || 0;
        results.holeshots += h.rowsAffected || 0;
      }

      const s = await db.client.execute({
        sql: 'DELETE FROM sessions WHERE serverName LIKE ?',
        args: [serverPattern]
      });
      results.sessions += s.rowsAffected || 0;
    }

    const ROTATION_TRACKS = [
      'Temecula Creek', 'Across The Sea', '2025.ARKsxRD1', 'Country Side',
      'KeLLz - RedBud 2023', 'KeLLz - Unadilla 2022', 'KeLLz - Washougal 2023',
      'KeLLz - Ponca City', 'KMX - Ponca City'
    ];

    for (const trackName of ROTATION_TRACKS) {
      const tr = await db.client.execute({
        sql: 'DELETE FROM track_records WHERE trackName = ?',
        args: [trackName]
      });
      results.trackRecords += tr.rowsAffected || 0;
    }

    console.log('[ADMIN] Rotation server cleanup:', results);
    res.json({ success: true, deleted: results });
  } catch (err) {
    console.error('[ADMIN] Cleanup error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Simple player lookup by GUID - used by CBR overlay plugin
app.get('/api/player/:guid', async (req, res) => {
  try {
    const { guid } = req.params;
    const player = await db.getPlayer(guid.toUpperCase());
    if (!player) {
      return res.status(404).json({ error: 'Player not found' });
    }
    // Return basic info for overlay
    res.json({
      guid: player.guid,
      displayName: player.displayName,
      mmr: player.mmr || 1000,
      safetyRating: player.safetyRating || 0.5,
      totalRaces: player.totalRaces || 0,
      wins: player.wins || 0,
      podiums: player.podiums || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/player/:guid/sessions', async (req, res) => {
  try {
    const { guid } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const sessions = await db.getPlayerSessions(guid.toUpperCase(), limit);
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/leaderboards', async (req, res) => {
  try {
    const [mmr, safetyRating] = await Promise.all([
      db.getTopPlayersByMMR(100),
      db.getTopPlayersBySR(100)
    ]);
    res.json({ mmr, safetyRating });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/records', async (req, res) => {
  try {
    const records = await db.getAllTrackRecords();
    res.json(records);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// MXBMRP3 Plugin - Thomas. CBR reserves the right to revoke this endpoint at any time without reasoning.
app.get('/api/records/top', async (req, res) => {
  try {
    const { track, limit = 10, category } = req.query;
    const limitNum = Math.min(Math.max(parseInt(limit) || 10, 1), 50);
    const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';

    const now = Date.now();
    if (now - mxbmrp3Stats.lastReset > 86400000) {
      mxbmrp3Stats.requestsToday = 0;
      mxbmrp3Stats.lastReset = now;
    }
    mxbmrp3Stats.totalRequests++;
    mxbmrp3Stats.requestsToday++;
    mxbmrp3Stats.byTrack[track || 'all'] = (mxbmrp3Stats.byTrack[track || 'all'] || 0) + 1;
    mxbmrp3Stats.byIP[ip] = (mxbmrp3Stats.byIP[ip] || 0) + 1;
    mxbmrp3Stats.recentRequests.unshift({ time: now, track: track || 'all', ip });
    if (mxbmrp3Stats.recentRequests.length > 100) mxbmrp3Stats.recentRequests.pop();

    let records;
    if (track) {
      records = await db.getTrackRecords(track, limitNum, category);
    } else {
      records = await db.getTopTrackRecords(limitNum, category);
    }

    const formattedRecords = records.map(r => ({
      track: r.trackName,
      laptime: Math.round(r.lapTime * 1000),
      player: r.playerName,
      bike: r.bikeName || 'Unknown',
      category: r.bikeCategory || null,
      timestamp: r.setAt ? new Date(r.setAt).toISOString() : null
    }));

    res.json({
      notice: "MXBMRP3 Plugin - Thomas. Eskimo / CBR reserves the right to revoke this endpoint at any time without reasoning.",
      records: formattedRecords
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const totalRaces = await db.getTotalFinalizedSessionsCount();
    res.json({ totalRaces });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/mxbmrp3-stats', requireAuth, requireRoot, async (req, res) => {
  try {
    res.json({
      totalRequests: mxbmrp3Stats.totalRequests,
      requestsToday: mxbmrp3Stats.requestsToday,
      lastReset: mxbmrp3Stats.lastReset,
      recentRequests: mxbmrp3Stats.recentRequests.slice(0, 50),
      byTrack: mxbmrp3Stats.byTrack,
      byIP: mxbmrp3Stats.byIP
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/servers', async (req, res) => {
  try {
    let serverData = stateManager.getCachedServerData();
    if (!serverData) {
      serverData = await stateManager.fetchServersFromAPI();
    }
    res.json(serverData);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/players/link', async (req, res) => {
  try {
    const { playerGuid, displayName } = req.body;

    const guidRegex = /^[0-9a-f]{18}$/i;
    if (!playerGuid || !guidRegex.test(playerGuid)) {
      return res.status(400).json({ error: 'Invalid Player GUID format' });
    }

    if (displayName && (displayName.length > 50 || displayName.length < 1)) {
      return res.status(400).json({ error: 'Display name must be 1-50 characters' });
    }

    const normalizedGuid = playerGuid.toUpperCase();
    const existingPlayer = await db.getPlayer(normalizedGuid);

    if (existingPlayer) {
      return res.json({ success: true, player: existingPlayer, existed: true });
    }

    await db.upsertPlayer({
      guid: normalizedGuid,
      displayName: displayName || `Player_${normalizedGuid.slice(-8)}`,
      mmr: 1000,
      safetyRating: 0.5,
      totalRaces: 0,
      wins: 0,
      podiums: 0,
      autoGenerated: false,
      lastSeen: Date.now(),
      firstSeen: Date.now()
    });

    const newPlayer = await db.getPlayer(normalizedGuid);
    res.json({ success: true, player: newPlayer, existed: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/players/connect', async (req, res) => {
  try {
    const { playerGuid, playerName, serverName, trackName, raceNumber, bikeName } = req.body;

    if (!playerGuid || !playerName) {
      return res.status(400).json({ error: 'Missing required fields: playerGuid, playerName' });
    }

    if (playerName.length > 100 || (serverName && serverName.length > 100) ||
        (trackName && trackName.length > 100) || (bikeName && bikeName.length > 100)) {
      return res.status(400).json({ error: 'Field length exceeded maximum' });
    }

    const normalizedGuid = playerGuid.toUpperCase();
    const now = Date.now();

    await db.upsertPlayer({
      guid: normalizedGuid,
      displayName: playerName,
      currentServer: serverName || null,
      currentTrack: trackName || null,
      raceNumber: raceNumber || null,
      bikeName: bikeName || null,
      lastSeen: now,
      firstSeen: now,
      autoGenerated: true
    });

    console.log(`[PLAYER-CONNECT] ${playerName} (${normalizedGuid})`);
    res.json({ success: true, playerGuid: normalizedGuid, playerName });
  } catch (err) {
    console.error('[PLAYER-CONNECT] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/check-pb', async (req, res) => {
  try {
    const { playerGuid, playerName, trackName, lapTime, sessionType, raceNumber, bikeName, bikeCategory, serverId } = req.body;

    let resolvedTrackName = trackName;
    if (!resolvedTrackName && serverId) {
      resolvedTrackName = stateManager.getTrackForServer(serverId);
      if (resolvedTrackName) {
        console.log(`[PB] Resolved track from serverTracks: ${resolvedTrackName} (serverId: ${serverId})`);
      }
    }

    if (!playerGuid || !resolvedTrackName || !lapTime) {
      console.log(`[PB] Missing fields - guid:${!!playerGuid}, track:${!!resolvedTrackName}, lap:${!!lapTime}, serverId:${serverId}`);
      return res.status(400).json({ error: 'Missing required fields: playerGuid, trackName, lapTime' });
    }

    if (typeof lapTime !== 'number' || lapTime < 10 || lapTime > 1800) {
      return res.status(400).json({ error: 'Invalid lap time' });
    }

    if (resolvedTrackName.length > 100 || (playerName && playerName.length > 100) ||
        (bikeName && bikeName.length > 100)) {
      return res.status(400).json({ error: 'Field length exceeded maximum' });
    }

    const result = await db.checkSinglePlayerPB({
      playerGuid: playerGuid.toUpperCase(),
      playerName,
      trackName: resolvedTrackName,
      lapTime,
      sessionType: sessionType || 'race',
      raceNumber: raceNumber || 0,
      bikeName: bikeName || null,
      bikeCategory: bikeCategory || null
    });

    console.log(`[PB] ${playerName}: isPB=${result.isPB}, time=${result.lapTime}`);
    res.json(result);
  } catch (err) {
    console.error('[PB] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/steam/profile/:steamId', async (req, res) => {
  try {
    const { steamId } = req.params;

    if (!steamId || !/^\d{17}$/.test(steamId)) {
      return res.status(400).json({ error: 'Invalid Steam64 ID format' });
    }

    const profile = await fetchSteamProfile(steamId);
    if (!profile) {
      return res.status(404).json({ error: 'Steam profile not found' });
    }

    res.json(profile);
  } catch (err) {
    console.error('[STEAM] Error fetching profile:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/steam/profile/guid/:guid', async (req, res) => {
  try {
    const { guid } = req.params;
    const normalizedGuid = guid.toUpperCase();

    const steam64 = guidToSteam64(normalizedGuid);
    if (!steam64) {
      return res.status(400).json({ error: 'Invalid GUID format' });
    }

    const profile = await fetchSteamProfile(steam64);
    if (!profile) {
      return res.status(404).json({ error: 'Steam profile not found' });
    }

    res.json({ ...profile, guid: normalizedGuid });
  } catch (err) {
    console.error('[STEAM] Error fetching profile by GUID:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/steam/convert/to-guid/:steamId', (req, res) => {
  const { steamId } = req.params;
  const guid = steam64ToGuid(steamId);

  if (!guid) {
    return res.status(400).json({ error: 'Invalid Steam64 ID' });
  }

  res.json({ steamId, guid });
});

app.get('/api/steam/convert/to-steam/:guid', (req, res) => {
  const { guid } = req.params;
  const steam64 = guidToSteam64(guid.toUpperCase());

  if (!steam64) {
    return res.status(400).json({ error: 'Invalid GUID' });
  }

  res.json({ guid: guid.toUpperCase(), steamId: steam64 });
});

app.post('/api/steam/verify', async (req, res) => {
  try {
    const params = req.body;

    const verifyParams = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      verifyParams.append(key, value);
    }
    verifyParams.set('openid.mode', 'check_authentication');

    const verifyResponse = await fetch('https://steamcommunity.com/openid/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: verifyParams.toString()
    });

    const verifyText = await verifyResponse.text();
    const isValid = verifyText.includes('is_valid:true');

    if (!isValid) {
      return res.status(401).json({ error: 'Steam authentication failed', verified: false });
    }

    const claimedId = params['openid.claimed_id'];
    const steamIdMatch = claimedId?.match(/\/id\/(\d+)$/);
    const steamId = steamIdMatch?.[1];

    if (!steamId) {
      return res.status(400).json({ error: 'Could not extract Steam ID' });
    }

    const profile = await fetchSteamProfile(steamId);
    if (!profile) {
      return res.status(404).json({ error: 'Steam profile not found' });
    }

    const guid = steam64ToGuid(steamId);

    const existingPlayer = await db.getPlayer(guid);

    let firebaseToken = null;
    let existingFirebaseUser = null;

    if (firebaseAdmin) {
      try {
        const usersSnapshot = await firebaseAdmin.firestore()
          .collection('users')
          .where('steamId', '==', steamId)
          .limit(1)
          .get();

        let firebaseUid;

        if (!usersSnapshot.empty) {
          const existingDoc = usersSnapshot.docs[0];
          firebaseUid = existingDoc.id;
          existingFirebaseUser = { id: existingDoc.id, ...existingDoc.data() };
          console.log(`[STEAM] Found existing user ${firebaseUid} with Steam linked`);
        } else {
          firebaseUid = `steam_${steamId}`;
          console.log(`[STEAM] New Steam user, using UID: ${firebaseUid}`);
        }

        firebaseToken = await firebaseAdmin.auth().createCustomToken(firebaseUid, {
          steamId: steamId,
          guid: guid,
          provider: 'steam'
        });
        console.log(`[STEAM] Generated Firebase token for ${profile.displayName} (${firebaseUid})`);
      } catch (tokenErr) {
        console.error('[STEAM] Failed to generate Firebase token:', tokenErr.message);
      }
    }

    res.json({
      verified: true,
      steamProfile: profile,
      guid,
      existingPlayer: existingPlayer || null,
      existingFirebaseUser: existingFirebaseUser,
      firebaseToken: firebaseToken
    });

  } catch (err) {
    console.error('[STEAM] Verification error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Server-side Steam avatar cache (1 hour TTL)
const steamAvatarCache = new Map();
const STEAM_AVATAR_CACHE_TTL = 60 * 60 * 1000; // 1 hour

function getCachedSteamAvatar(guid) {
  const cached = steamAvatarCache.get(guid);
  if (!cached) return undefined;
  if (Date.now() - cached.timestamp > STEAM_AVATAR_CACHE_TTL) {
    steamAvatarCache.delete(guid);
    return undefined;
  }
  return cached.data;
}

function setCachedSteamAvatar(guid, data) {
  steamAvatarCache.set(guid, { data, timestamp: Date.now() });
}

// ==========================================
// BACKGROUND STEAM AVATAR SYNC
// Fetches and caches Steam avatars in database
// ==========================================
let lastAvatarSyncTime = 0;
const AVATAR_SYNC_INTERVAL = 5000; // Run every 5 seconds for fast initial sync
const AVATAR_BATCH_SIZE = 100; // Steam API allows up to 100 per request

async function syncSteamAvatars() {
  try {
    // Get players needing avatar sync
    const guidsToSync = await db.getPlayersNeedingAvatarSync(AVATAR_BATCH_SIZE);
    if (guidsToSync.length === 0) {
      // All synced - slow down interval (checked in the caller)
      return { done: true };
    }

    console.log(`[AVATAR SYNC] Syncing ${guidsToSync.length} player avatars...`);

    // Convert GUIDs to Steam64 IDs
    const steam64s = guidsToSync
      .map(guid => ({ guid, steam64: guidToSteam64(guid) }))
      .filter(item => item.steam64);

    if (steam64s.length === 0) return;

    const steamIds = steam64s.map(s => s.steam64).join(',');
    const response = await fetch(
      `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${env.STEAM_API_KEY}&steamids=${steamIds}`,
      { signal: AbortSignal.timeout(15000) }
    );

    if (!response.ok) {
      console.error('[AVATAR SYNC] Steam API error:', response.status);
      return;
    }

    const data = await response.json();
    const players = data.response?.players || [];

    // Build avatar map
    const avatarMap = {};
    const playerMap = new Map();

    for (const player of players) {
      const guid = steam64ToGuid(player.steamid);
      if (guid) {
        playerMap.set(guid, player.avatarfull || player.avatarmedium || player.avatar);
      }
    }

    // Set avatar URLs (or null for players not found)
    for (const guid of guidsToSync) {
      avatarMap[guid] = playerMap.get(guid) || null;
    }

    // Batch update database
    await db.batchUpdateSteamAvatars(avatarMap);

    const found = Object.values(avatarMap).filter(v => v).length;
    console.log(`[AVATAR SYNC] Updated ${found}/${guidsToSync.length} avatars`);

  } catch (err) {
    console.error('[AVATAR SYNC] Error:', err.message);
  }
}

// Avatar sync loop - checks every 2 minutes for new players and stale avatars (12h)
let avatarSyncInterval = null;

function startAvatarSyncLoop() {
  if (avatarSyncInterval) return; // Already running

  console.log('[AVATAR SYNC] Starting sync loop (every 2 min)...');

  const runSync = async () => {
    try {
      const result = await syncSteamAvatars();
      if (!result?.done) {
        console.log('[AVATAR SYNC] Synced batch');
      }
    } catch (err) {
      console.error('[AVATAR SYNC] Error:', err.message);
    }
  };

  avatarSyncInterval = setInterval(runSync, 120000); // Every 2 minutes
}

app.post('/api/steam/avatars', async (req, res) => {
  try {
    const { guids } = req.body;

    if (!Array.isArray(guids) || guids.length === 0) {
      return res.status(400).json({ error: 'guids must be a non-empty array' });
    }

    const limitedGuids = guids.slice(0, 100);
    const avatars = {};
    const uncachedGuids = [];

    // Check cache first
    for (const guid of limitedGuids) {
      const normalized = guid.toUpperCase();
      const cached = getCachedSteamAvatar(normalized);
      if (cached !== undefined) {
        if (cached !== null) {
          avatars[normalized] = cached;
        }
      } else {
        uncachedGuids.push(normalized);
      }
    }

    // If all cached, return immediately
    if (uncachedGuids.length === 0) {
      return res.json({ avatars });
    }

    const steam64s = uncachedGuids
      .map(guid => ({ guid, steam64: guidToSteam64(guid) }))
      .filter(item => item.steam64);

    if (steam64s.length === 0) {
      // Cache null for invalid GUIDs
      uncachedGuids.forEach(guid => setCachedSteamAvatar(guid, null));
      return res.json({ avatars });
    }

    const steamIds = steam64s.map(s => s.steam64).join(',');
    const response = await fetch(
      `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${env.STEAM_API_KEY}&steamids=${steamIds}`,
      { signal: AbortSignal.timeout(8000) } // 8s timeout
    );

    if (!response.ok) {
      // Cache null for failed requests to prevent retry spam
      uncachedGuids.forEach(guid => setCachedSteamAvatar(guid, null));
      return res.json({ avatars }); // Return what we have from cache
    }

    const data = await response.json();
    const players = data.response?.players || [];

    // Build lookup map
    const playerMap = new Map();
    for (const player of players) {
      const guid = steam64ToGuid(player.steamid);
      if (guid) {
        const avatarData = {
          avatar: player.avatar,
          avatarMedium: player.avatarmedium,
          avatarFull: player.avatarfull,
          displayName: player.personaname
        };
        playerMap.set(guid, avatarData);
      }
    }

    // Update cache and response
    for (const guid of uncachedGuids) {
      const avatarData = playerMap.get(guid) || null;
      setCachedSteamAvatar(guid, avatarData);
      if (avatarData) {
        avatars[guid] = avatarData;
      }
    }

    res.json({ avatars });
  } catch (err) {
    // Silent failure - return what we have
    console.error('[STEAM] Batch avatars error:', err.message);
    res.json({ avatars: {} });
  }
});

// NOTE: Discord webhook constants removed - now using database-backed appeals/reports system

// ==========================================
// BAN APPEALS ENDPOINTS (Database-backed)
// ==========================================

// Submit a new ban appeal (requires auth)
app.post('/api/ban-appeals', requireAuth, async (req, res) => {
  try {
    const {
      playerGuid,
      playerName,
      banReason,
      banDate,
      banExpiry,
      isPermanent,
      serverName,
      isGlobal,
      appealReason,
      additionalInfo,
      videoUrl
    } = req.body;

    if (!playerGuid || !appealReason) {
      return res.status(400).json({ error: 'Missing required fields: playerGuid, appealReason' });
    }

    // Check if user can appeal (not in cooldown)
    const canAppeal = await db.canUserAppeal(req.userId, playerGuid.toUpperCase());
    if (!canAppeal.canAppeal) {
      return res.status(403).json({
        error: canAppeal.reason,
        cooldownUntil: canAppeal.cooldownUntil
      });
    }

    const appeal = await db.createBanAppeal({
      playerGuid: playerGuid.toUpperCase(),
      playerName: playerName || 'Unknown',
      userId: req.userId,
      banReason: banReason || 'Unknown',
      banDate: banDate || null,
      banExpiry: banExpiry || null,
      isPermanent: isPermanent !== false,
      serverName: serverName || null,
      isGlobal: isGlobal !== false,
      appealReason,
      additionalInfo: additionalInfo || null,
      videoUrl: videoUrl || null
    });

    console.log(`[BAN-APPEAL] New appeal #${appeal.appealIndex} from ${playerName} (${playerGuid})`);
    res.json({ success: true, appeal });

  } catch (err) {
    console.error('[BAN-APPEAL] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get user's own appeals
app.get('/api/ban-appeals/my', requireAuth, async (req, res) => {
  try {
    // Auto-resolve any expired ban appeals first
    await db.autoResolveExpiredAppeals();

    const appeals = await db.getUserAppeals(req.userId);
    res.json(appeals);
  } catch (err) {
    console.error('[BAN-APPEAL] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Check if user can appeal
app.get('/api/ban-appeals/can-appeal', requireAuth, async (req, res) => {
  try {
    const { playerGuid } = req.query;
    if (!playerGuid) {
      return res.status(400).json({ error: 'Missing playerGuid' });
    }
    const result = await db.canUserAppeal(req.userId, playerGuid.toUpperCase());
    res.json(result);
  } catch (err) {
    console.error('[BAN-APPEAL] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all appeals
app.get('/api/admin/ban-appeals', requireAuth, requireModerator, async (req, res) => {
  try {
    // Auto-resolve any expired ban appeals first
    await db.autoResolveExpiredAppeals();

    const { status } = req.query;
    const appeals = await db.getAllAppeals(status || null);
    res.json(appeals);
  } catch (err) {
    console.error('[ADMIN] Get appeals error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Claim an appeal
app.post('/api/admin/ban-appeals/:id/claim', requireAuth, requireModerator, async (req, res) => {
  try {
    const { id } = req.params;
    const adminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';
    const adminGuid = req.userProfile?.linkedPlayerGuid || null;

    const appeal = await db.claimAppeal(id, adminName, adminGuid);
    if (!appeal) {
      return res.status(404).json({ error: 'Appeal not found or already claimed' });
    }

    // Create notification for the user that their appeal is being reviewed
    try {
      await db.createNotification({
        userId: appeal.userId,
        type: 'appeal_claimed',
        title: 'Ban Appeal Under Review',
        message: `Your ban appeal is now being reviewed by ${adminName}.`,
        link: '/ban-appeal',
        relatedId: appeal.id
      });
    } catch (notifErr) {
      console.error('[ADMIN] Failed to create claim notification:', notifErr.message);
    }

    console.log(`[ADMIN] Appeal #${appeal.appealIndex} claimed by ${adminName}`);
    res.json({ success: true, appeal });
  } catch (err) {
    console.error('[ADMIN] Claim appeal error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Resolve an appeal (accept/deny)
app.post('/api/admin/ban-appeals/:id/resolve', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { accepted, resolution, cooldownHours } = req.body;
    const adminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';
    const adminGuid = req.userProfile?.linkedPlayerGuid || null;

    if (typeof accepted !== 'boolean') {
      return res.status(400).json({ error: 'Missing accepted (boolean)' });
    }

    const appeal = await db.resolveAppeal(id, adminName, adminGuid, accepted, resolution || '', cooldownHours || 24);
    if (!appeal) {
      return res.status(404).json({ error: 'Appeal not found' });
    }

    // If accepted, unban the player
    if (accepted) {
      try {
        const sources = getApiSources();
        for (const source of sources) {
          try {
            const serversResp = await fetchFromManager(source, '/servers');
            const servers = Array.isArray(serversResp) ? serversResp : [];
            if (servers.length > 0) {
              const serverId = servers[0].id || servers[0].Id;
              await fetchFromManager(source, `/servers/${serverId}/full-unban`, 'POST', { playerGuid: appeal.playerGuid })
                .catch(() => fetchFromManager(source, `/servers/${serverId}/unban`, 'POST', { playerGuid: appeal.playerGuid }));
            }
          } catch (err) {
            console.error(`[ADMIN] Unban via appeal failed on ${source.id}:`, err.message);
          }
        }

        // Store unban history
        await db.addBanHistory({
          playerGuid: appeal.playerGuid,
          playerName: appeal.playerName,
          action: 'unban',
          reason: `Appeal #${appeal.appealIndex} accepted`,
          isGlobal: true,
          performedBy: adminName,
          sourceManager: 'appeal'
        });
      } catch (unbanErr) {
        console.error('[ADMIN] Unban from appeal error:', unbanErr.message);
      }
    }

    // Create notification for the user
    try {
      await db.createNotification({
        userId: appeal.userId,
        type: accepted ? 'appeal_accepted' : 'appeal_denied',
        title: accepted ? 'Ban Appeal Accepted' : 'Ban Appeal Denied',
        message: accepted
          ? 'Your ban appeal was accepted. You have been unbanned.'
          : `Your ban appeal was denied. ${resolution || ''}`,
        link: '/ban-appeal',
        relatedId: appeal.id
      });
    } catch (notifErr) {
      console.error('[ADMIN] Notification error:', notifErr.message);
    }

    console.log(`[ADMIN] Appeal #${appeal.appealIndex} ${accepted ? 'ACCEPTED' : 'DENIED'} by ${adminName}`);
    res.json({ success: true, appeal, unbanned: accepted });
  } catch (err) {
    console.error('[ADMIN] Resolve appeal error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// PLAYER REPORTS ENDPOINTS (Database-backed)
// ==========================================

// Submit a new player report (requires auth)
app.post('/api/reports', requireAuth, async (req, res) => {
  try {
    const {
      reporterGuid,
      reporterName,
      offenderGuid,
      offenderName,
      serverName,
      reason,
      description,
      videoUrl
    } = req.body;

    if (!offenderGuid || !offenderName || !reason || !description || !videoUrl) {
      return res.status(400).json({ error: 'Missing required fields. Video URL is mandatory.' });
    }

    const report = await db.createReport({
      reporterGuid: (reporterGuid || '').toUpperCase(),
      reporterName: reporterName || 'Unknown',
      reporterUserId: req.userId,
      offenderGuid: offenderGuid.toUpperCase(),
      offenderName,
      serverName: serverName || null,
      reason,
      description,
      videoUrl
    });

    console.log(`[REPORT] New report #${report.reportIndex} - ${reporterName} reported ${offenderName} for ${reason}`);
    res.json({ success: true, report });

  } catch (err) {
    console.error('[REPORT] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get user's own reports
app.get('/api/reports/my', requireAuth, async (req, res) => {
  try {
    const reports = await db.getUserReports(req.userId);
    res.json(reports);
  } catch (err) {
    console.error('[REPORT] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all reports
app.get('/api/admin/reports', requireAuth, requireModerator, async (req, res) => {
  try {
    const { status } = req.query;
    const reports = await db.getAllReports(status || null);
    res.json(reports);
  } catch (err) {
    console.error('[ADMIN] Get reports error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Claim a report
app.post('/api/admin/reports/:id/claim', requireAuth, requireModerator, async (req, res) => {
  try {
    const { id } = req.params;
    const adminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';
    const adminGuid = req.userProfile?.linkedPlayerGuid || null;

    const report = await db.claimReport(id, adminName, adminGuid);
    if (!report) {
      return res.status(404).json({ error: 'Report not found or already claimed' });
    }

    // Create notification for the reporter that their report is being reviewed
    try {
      await db.createNotification({
        userId: report.reporterUserId,
        type: 'report_claimed',
        title: 'Player Report Under Review',
        message: `Your report against ${report.offenderName} is now being reviewed by ${adminName}.`,
        link: '/report',
        relatedId: report.id
      });
    } catch (notifErr) {
      console.error('[ADMIN] Failed to create claim notification:', notifErr.message);
    }

    console.log(`[ADMIN] Report #${report.reportIndex} claimed by ${adminName}`);
    res.json({ success: true, report });
  } catch (err) {
    console.error('[ADMIN] Claim report error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Resolve a report
app.post('/api/admin/reports/:id/resolve', requireAuth, requireModerator, async (req, res) => {
  try {
    const { id } = req.params;
    const { actionTaken, resolution, warningReason } = req.body;
    const adminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';
    const adminGuid = req.userProfile?.linkedPlayerGuid || null;

    if (!actionTaken) {
      return res.status(400).json({ error: 'Missing actionTaken' });
    }

    // If action is 'warned', require a warning reason
    if (actionTaken === 'warned' && !warningReason) {
      return res.status(400).json({ error: 'Warning reason is required when issuing a warning' });
    }

    const report = await db.resolveReport(id, adminName, adminGuid, actionTaken, resolution || '');
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // If action is 'warned', issue a full warning (DB record + in-game message + ban until acknowledged)
    if (actionTaken === 'warned' && warningReason) {
      try {
        const upperGuid = report.offenderGuid.toUpperCase();

        // 1. Create the warning record
        const warning = await db.createWarning({
          playerGuid: upperGuid,
          playerName: report.offenderName,
          reason: warningReason,
          warnedBy: adminName,
          reportId: report.id
        });
        console.log(`[ADMIN] Warning created for ${report.offenderName}: ${warningReason}`);

        // 2. Send warning message in-game via Manager
        const sources = getApiSources();
        for (const source of sources) {
          try {
            await fetchFromManager(source, '/warn', 'POST', {
              playerGuid: upperGuid,
              playerName: report.offenderName,
              reason: warningReason
            });
          } catch (msgErr) {
            // Player might not be online
          }
        }

        // Small delay before banning
        await new Promise(resolve => setTimeout(resolve, 200));

        // 3. Ban player on all servers until they acknowledge
        const banReason = `Warning: ${warningReason} - You must acknowledge this warning on your profile at mxb-mods.com to be unbanned`;
        for (const source of sources) {
          try {
            const serversResp = await fetchFromManager(source, '/servers');
            const servers = Array.isArray(serversResp) ? serversResp : [];
            for (const server of servers) {
              const serverId = server.id || server.Id;
              try {
                await fetchFromManager(source, `/servers/${serverId}/ban`, 'POST', {
                  playerGuid: upperGuid,
                  playerName: report.offenderName,
                  reason: banReason,
                  duration: 0,
                  isPermanent: true,
                  sendPrivateMessage: false,
                  sendGlobalMessage: false
                });
              } catch (banErr) { }
            }
          } catch (sourceErr) { }
        }

        // 4. Update player DB record
        await db.updatePlayer(upperGuid, { isBanned: true, banReason: banReason });

        // 5. Log to ban history
        await db.addBanHistory({
          playerGuid: upperGuid,
          playerName: report.offenderName,
          action: 'ban',
          reason: banReason,
          isGlobal: true,
          isPermanent: true,
          performedBy: adminName,
          sourceManager: 'Website (Warning)'
        });

        console.log(`[ADMIN] Warning issued and player banned: ${report.offenderName}`);
      } catch (warnErr) {
        console.error('[ADMIN] Warning flow error:', warnErr.message);
      }
    }

    // For pending_ban, don't notify the reporter yet - wait for admin review
    if (actionTaken === 'pending_ban') {
      console.log(`[ADMIN] Report #${report.reportIndex} marked as pending ban by ${adminName} - awaiting admin review`);
      return res.json({ success: true, report });
    }

    // Create notification for the reporter (only for final resolutions)
    try {
      const actionText = actionTaken === 'banned' ? 'action was taken'
        : actionTaken === 'warned' ? 'a warning was issued'
        : 'no action was taken';

      await db.createNotification({
        userId: report.reporterUserId,
        type: 'report_resolved',
        title: 'Player Report Resolved',
        message: `Your report against ${report.offenderName} has been reviewed and ${actionText}.`,
        link: '/report',
        relatedId: report.id
      });
    } catch (notifErr) {
      console.error('[ADMIN] Notification error:', notifErr.message);
    }

    console.log(`[ADMIN] Report #${report.reportIndex} resolved by ${adminName} - action: ${actionTaken}`);
    res.json({ success: true, report });
  } catch (err) {
    console.error('[ADMIN] Resolve report error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Transfer a report to another admin
app.post('/api/admin/reports/:id/transfer', requireAuth, requireModerator, async (req, res) => {
  try {
    const { id } = req.params;
    const { newAdminGuid, newAdminName } = req.body;
    const currentAdminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';

    if (!newAdminGuid || !newAdminName) {
      return res.status(400).json({ error: 'Missing newAdminGuid or newAdminName' });
    }

    const report = await db.transferReport(id, newAdminGuid, newAdminName);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // Create notification for new assignee
    try {
      // Get user ID from the new admin's guid by querying Firestore
      const usersSnapshot = await firebaseAdmin.firestore()
        .collection('users')
        .where('linkedPlayerGuid', '==', newAdminGuid.toUpperCase())
        .limit(1)
        .get();

      if (!usersSnapshot.empty) {
        const newAdminUserId = usersSnapshot.docs[0].id;
        await db.createNotification({
          userId: newAdminUserId,
          type: 'report_transferred',
          title: 'Report Transferred to You',
          message: `Report #${report.reportIndex} against ${report.offenderName} has been transferred to you by ${currentAdminName}.`,
          link: '/admin/reports',
          relatedId: report.id
        });
      }
    } catch (notifErr) {
      console.error('[ADMIN] Failed to create transfer notification:', notifErr.message);
    }

    console.log(`[ADMIN] Report #${report.reportIndex} transferred from ${currentAdminName} to ${newAdminName}`);
    res.json({ success: true, report });
  } catch (err) {
    console.error('[ADMIN] Transfer report error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Transfer an appeal to another admin
app.post('/api/admin/ban-appeals/:id/transfer', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { newAdminGuid, newAdminName } = req.body;
    const currentAdminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';

    if (!newAdminGuid || !newAdminName) {
      return res.status(400).json({ error: 'Missing newAdminGuid or newAdminName' });
    }

    const appeal = await db.transferAppeal(id, newAdminGuid, newAdminName);
    if (!appeal) {
      return res.status(404).json({ error: 'Appeal not found' });
    }

    // Create notification for new assignee
    try {
      // Get user ID from the new admin's guid by querying Firestore
      const usersSnapshot = await firebaseAdmin.firestore()
        .collection('users')
        .where('linkedPlayerGuid', '==', newAdminGuid.toUpperCase())
        .limit(1)
        .get();

      if (!usersSnapshot.empty) {
        const newAdminUserId = usersSnapshot.docs[0].id;
        await db.createNotification({
          userId: newAdminUserId,
          type: 'appeal_transferred',
          title: 'Appeal Transferred to You',
          message: `Appeal #${appeal.appealIndex} from ${appeal.playerName} has been transferred to you by ${currentAdminName}.`,
          link: '/admin/reports',
          relatedId: appeal.id
        });
      }
    } catch (notifErr) {
      console.error('[ADMIN] Failed to create transfer notification:', notifErr.message);
    }

    console.log(`[ADMIN] Appeal #${appeal.appealIndex} transferred from ${currentAdminName} to ${newAdminName}`);
    res.json({ success: true, appeal });
  } catch (err) {
    console.error('[ADMIN] Transfer appeal error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Delete a report (SuperAdmin only for now - testing)
app.delete('/api/admin/reports/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const adminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';

    const deleted = await db.deleteReport(id);
    if (!deleted) {
      return res.status(404).json({ error: 'Report not found' });
    }

    console.log(`[ADMIN] Report ${id} deleted by ${adminName}`);
    res.json({ success: true });
  } catch (err) {
    console.error('[ADMIN] Delete report error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Delete an appeal (SuperAdmin only for now - testing)
app.delete('/api/admin/ban-appeals/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const adminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';

    const deleted = await db.deleteAppeal(id);
    if (!deleted) {
      return res.status(404).json({ error: 'Appeal not found' });
    }

    console.log(`[ADMIN] Appeal ${id} deleted by ${adminName}`);
    res.json({ success: true });
  } catch (err) {
    console.error('[ADMIN] Delete appeal error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// NOTIFICATIONS ENDPOINTS
// ==========================================

// Get user's notifications
app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const notifications = await db.getUserNotifications(req.userId, limit);
    res.json(notifications);
  } catch (err) {
    console.error('[NOTIFICATIONS] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get unread notification count
app.get('/api/notifications/unread-count', requireAuth, async (req, res) => {
  try {
    const count = await db.getUnreadNotificationCount(req.userId);
    res.json({ count });
  } catch (err) {
    console.error('[NOTIFICATIONS] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get unread notification counts by type (for sidebar badges)
app.get('/api/notifications/unread-by-type', requireAuth, async (req, res) => {
  try {
    const counts = await db.getUnreadNotificationCountsByType(req.userId);
    res.json(counts);
  } catch (err) {
    console.error('[NOTIFICATIONS] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get open appeals and reports count (for sidebar badges)
app.get('/api/admin/pending-counts', requireAuth, requireModerator, async (req, res) => {
  try {
    const counts = await db.getAdminPendingCounts();
    res.json(counts);
  } catch (err) {
    console.error('[ADMIN] Pending counts error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Mark a notification as read
app.post('/api/notifications/:id/read', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const notification = await db.markNotificationRead(id);
    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('[NOTIFICATIONS] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Mark all notifications as read
app.post('/api/notifications/read-all', requireAuth, async (req, res) => {
  try {
    await db.markAllNotificationsRead(req.userId);
    res.json({ success: true });
  } catch (err) {
    console.error('[NOTIFICATIONS] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============ ANNOUNCEMENTS ============

// Get active announcements (public)
app.get('/api/announcements', async (req, res) => {
  try {
    const announcements = await db.getActiveAnnouncements();
    res.json(announcements);
  } catch (err) {
    console.error('[ANNOUNCEMENTS] Error fetching:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all announcements (including inactive)
app.get('/api/admin/announcements', requireAuth, requireModerator, async (req, res) => {
  try {
    const announcements = await db.getAllAnnouncements();
    res.json(announcements);
  } catch (err) {
    console.error('[ANNOUNCEMENTS] Error fetching all:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Create announcement
app.post('/api/admin/announcements', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { title, message, type, expiresAt } = req.body;

    if (!title || !message) {
      return res.status(400).json({ error: 'Title and message are required' });
    }

    const announcement = await db.createAnnouncement({
      title,
      message,
      type: type || 'info',
      createdBy: req.userId,
      createdByName: req.userProfile?.displayName || 'Admin',
      expiresAt: expiresAt || null
    });

    console.log(`[ANNOUNCEMENTS] Created by ${req.userProfile?.displayName}: "${title}"`);
    res.json({ success: true, announcement });
  } catch (err) {
    console.error('[ANNOUNCEMENTS] Error creating:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Update announcement
app.put('/api/admin/announcements/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, message, type, active, expiresAt } = req.body;

    const announcement = await db.updateAnnouncement(id, {
      title,
      message,
      type,
      active,
      expiresAt
    });

    if (!announcement) {
      return res.status(404).json({ error: 'Announcement not found' });
    }

    console.log(`[ANNOUNCEMENTS] Updated ${id} by ${req.userProfile?.displayName}`);
    res.json({ success: true, announcement });
  } catch (err) {
    console.error('[ANNOUNCEMENTS] Error updating:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Toggle announcement active status
app.post('/api/admin/announcements/:id/toggle', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const announcement = await db.toggleAnnouncementActive(id);

    if (!announcement) {
      return res.status(404).json({ error: 'Announcement not found' });
    }

    console.log(`[ANNOUNCEMENTS] Toggled ${id} to ${announcement.active ? 'active' : 'inactive'}`);
    res.json({ success: true, announcement });
  } catch (err) {
    console.error('[ANNOUNCEMENTS] Error toggling:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Delete announcement
app.delete('/api/admin/announcements/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await db.deleteAnnouncement(id);

    if (!deleted) {
      return res.status(404).json({ error: 'Announcement not found' });
    }

    console.log(`[ANNOUNCEMENTS] Deleted ${id} by ${req.userProfile?.displayName}`);
    res.json({ success: true });
  } catch (err) {
    console.error('[ANNOUNCEMENTS] Error deleting:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// Feature Requests - Admin feature/bug request system
// ============================================

// Get all feature requests (sorted by vote score)
app.get('/api/admin/feature-requests', requireAuth, requireModerator, async (req, res) => {
  try {
    const requests = await db.getAllFeatureRequests();
    res.json(requests);
  } catch (err) {
    console.error('[FEATURE_REQUESTS] Error fetching:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Create new feature request (any admin/mod)
app.post('/api/admin/feature-requests', requireAuth, requireModerator, async (req, res) => {
  try {
    const { title, description, type } = req.body;

    if (!title || !description) {
      return res.status(400).json({ error: 'Title and description are required' });
    }

    const request = await db.createFeatureRequest({
      title,
      description,
      type: type || 'feature',
      submittedBy: req.userId,
      submittedByName: req.userProfile?.displayName || 'Admin',
      submittedByGuid: req.userProfile?.guid || null
    });

    console.log(`[FEATURE_REQUESTS] Created by ${req.userProfile?.displayName}: "${title}"`);
    res.json({ success: true, request });
  } catch (err) {
    console.error('[FEATURE_REQUESTS] Error creating:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update feature request status/comment (developer only)
app.put('/api/admin/feature-requests/:id', requireAuth, requireRoot, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, developerComment } = req.body;

    const request = await db.updateFeatureRequest(id, { status, developerComment });

    if (!request) {
      return res.status(404).json({ error: 'Feature request not found' });
    }

    console.log(`[FEATURE_REQUESTS] Updated ${id} - status: ${status}`);
    res.json({ success: true, request });
  } catch (err) {
    console.error('[FEATURE_REQUESTS] Error updating:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Vote on feature request
app.post('/api/admin/feature-requests/:id/vote', requireAuth, requireModerator, async (req, res) => {
  try {
    const { id } = req.params;
    const { vote } = req.body; // 'up', 'down', or 'none' to remove vote
    const odg = req.userId;

    const request = await db.voteFeatureRequest(id, odg, vote);

    if (!request) {
      return res.status(404).json({ error: 'Feature request not found' });
    }

    res.json({ success: true, request });
  } catch (err) {
    console.error('[FEATURE_REQUESTS] Error voting:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Delete feature request (developer only)
app.delete('/api/admin/feature-requests/:id', requireAuth, requireRoot, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await db.deleteFeatureRequest(id);

    if (!deleted) {
      return res.status(404).json({ error: 'Feature request not found' });
    }

    console.log(`[FEATURE_REQUESTS] Deleted ${id} by ${req.userProfile?.displayName}`);
    res.json({ success: true });
  } catch (err) {
    console.error('[FEATURE_REQUESTS] Error deleting:', err.message);
    res.status(500).json({ error: err.message });
  }
});

function getApiSources() {
  return [
    { id: 'manager1', url: env.MXBIKES_API_URL_1, key: env.MXBIKES_API_KEY_1 },
    { id: 'manager2', url: env.MXBIKES_API_URL_2, key: env.MXBIKES_API_KEY_2 }
  ].filter(s => s.url && s.key);
}

async function fetchFromManager(source, endpoint, method = 'GET', body = null) {
  const url = `${source.url}${endpoint}`;
  const options = {
    method,
    headers: {
      'X-API-Key': source.key,
      'Content-Type': 'application/json'
    }
  };
  if (body && method !== 'GET') {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { success: true, message: text };
  }
}

async function proxyToManager(endpoint, method = 'GET', body = null) {
  const sources = getApiSources();
  const errors = [];

  for (const source of sources) {
    try {
      return await fetchFromManager(source, endpoint, method, body);
    } catch (err) {
      errors.push(`${source.id}: ${err.message}`);
    }
  }

  throw new Error(`All API sources failed: ${errors.join(', ')}`);
}

async function proxyToAllManagers(endpoint, method = 'GET', body = null) {
  const sources = getApiSources();
  const results = [];
  const errors = [];

  await Promise.all(sources.map(async (source) => {
    try {
      const result = await fetchFromManager(source, endpoint, method, body);
      results.push({ source: source.id, result });
    } catch (err) {
      errors.push({ source: source.id, error: err.message });
    }
  }));

  return { results, errors };
}

// Public endpoint to check if a player is banned (for profile display)
app.get('/api/player/:guid/ban-status', async (req, res) => {
  try {
    const { guid } = req.params;
    const upperGuid = guid.toUpperCase();
    const sources = getApiSources();
    let banInfo = null;

    let serverData = stateManager.getCachedServerData();
    if (!serverData) {
      serverData = await stateManager.fetchServersFromAPI();
    }

    // Check all managers for this player's ban
    for (const source of sources) {
      try {
        const managerServersResp = await fetchFromManager(source, '/servers');
        const managerServers = Array.isArray(managerServersResp) ? managerServersResp : [];

        for (const server of managerServers) {
          const serverId = server.id || server.Id;
          try {
            const bans = await fetchFromManager(source, `/servers/${serverId}/bans`);
            if (Array.isArray(bans)) {
              const playerBan = bans.find(ban => {
                const banGuid = (ban.playerGuid || ban.PlayerGuid || '').toUpperCase();
                return banGuid === upperGuid;
              });

              if (playerBan) {
                const isGlobal = playerBan.isGlobal ?? playerBan.IsGlobal ?? false;
                const serverName = server.name || server.Name || 'Unknown Server';

                banInfo = {
                  isBanned: true,
                  playerGuid: upperGuid,
                  playerName: playerBan.playerName || playerBan.PlayerName || 'Unknown',
                  reason: playerBan.reason || playerBan.Reason || 'No reason provided',
                  bannedAt: playerBan.bannedAt || playerBan.BannedAt,
                  expiresAt: playerBan.expiresAt || playerBan.ExpiresAt || null,
                  bannedBy: playerBan.bannedBy || playerBan.BannedBy || 'Admin',
                  durationDescription: playerBan.durationDescription || playerBan.DurationDescription || null,
                  isActive: playerBan.isActive ?? playerBan.IsActive ?? true,
                  isGlobal: isGlobal,
                  serverName: isGlobal ? null : serverName
                };
                // Found ban, no need to continue
                break;
              }
            }
          } catch (banErr) {
            // Ignore individual server errors
          }
        }
        if (banInfo) break;
      } catch (err) {
        // Ignore manager errors
      }
    }

    // Cross-reference with ban_history to get correct bannedBy and evidence
    if (banInfo && db) {
      try {
        const banHistory = await db.getBanHistory(upperGuid);
        if (banHistory && banHistory.length > 0) {
          const latestBan = banHistory.find(h => h.action === 'ban');
          if (latestBan?.performedBy &&
              latestBan.performedBy !== 'System' &&
              latestBan.performedBy !== 'WebAPI' &&
              latestBan.performedBy !== 'WEBAPI') {
            banInfo.bannedBy = latestBan.performedBy;
          }
          // Also get isGlobal from history if available
          if (latestBan?.isGlobal !== undefined) {
            banInfo.isGlobal = latestBan.isGlobal;
          }
          if (latestBan?.serverName && !banInfo.isGlobal) {
            banInfo.serverName = latestBan.serverName;
          }
          // Include evidence URL if available (from reports)
          if (latestBan?.evidenceUrl) {
            banInfo.evidenceUrl = latestBan.evidenceUrl;
          }
        }
      } catch (histErr) {
        // Ignore history lookup errors
      }
    }

    res.json(banInfo || { isBanned: false });
  } catch (err) {
    console.error('[BAN-CHECK] Error:', err.message);
    res.json({ isBanned: false });
  }
});

// ============ PLAYER WARNINGS (PUBLIC) ============

app.get('/api/player/:guid/warnings', async (req, res) => {
  try {
    const { guid } = req.params;
    const warnings = await db.getPlayerWarnings(guid.toUpperCase());
    res.json(warnings);
  } catch (err) {
    console.error('[WARNINGS] Error fetching warnings:', err.message);
    res.status(500).json({ error: 'Failed to fetch warnings' });
  }
});

// Get unacknowledged warnings for a player
app.get('/api/player/:guid/warnings/unacknowledged', async (req, res) => {
  try {
    const { guid } = req.params;
    const warnings = await db.getUnacknowledgedWarnings(guid.toUpperCase());
    res.json(warnings);
  } catch (err) {
    console.error('[WARNINGS] Error fetching unacknowledged warnings:', err.message);
    res.status(500).json({ error: 'Failed to fetch unacknowledged warnings' });
  }
});

// Acknowledge a warning - requires auth (player must be logged in)
app.post('/api/player/:guid/warnings/:warningId/acknowledge', requireAuth, async (req, res) => {
  try {
    const { guid, warningId } = req.params;
    const upperGuid = guid.toUpperCase();

    // Verify the player owns this GUID (check their linked accounts)
    const user = await db.getUser(req.user.uid);
    if (!user) {
      return res.status(403).json({ error: 'User not found' });
    }

    // Check if this GUID is linked to the user
    const linkedPlayer = user.linkedPlayers?.find(p => p.guid.toUpperCase() === upperGuid);
    if (!linkedPlayer) {
      return res.status(403).json({ error: 'This player is not linked to your account' });
    }

    // Acknowledge the warning
    const warning = await db.acknowledgeWarning(warningId, upperGuid);
    if (!warning) {
      return res.status(404).json({ error: 'Warning not found or already acknowledged' });
    }

    // Auto-unban the player from all sources
    console.log(`[WARNINGS] Player ${upperGuid} acknowledged warning ${warningId}, auto-unbanning...`);

    const sources = getApiSources();
    const unbanResults = [];

    for (const source of sources) {
      try {
        // Get servers from this manager
        const serversResp = await fetchFromManager(source, '/servers');
        const servers = Array.isArray(serversResp) ? serversResp : [];

        for (const server of servers) {
          const serverId = server.id || server.Id;
          try {
            await fetchFromManager(source, `/servers/${serverId}/unban`, 'POST', {
              playerGuid: upperGuid,
              playerName: warning.playerName || 'Unknown'
            });
            unbanResults.push({ serverId, success: true });
          } catch (unbanErr) {
            // Might not be banned on this server, that's okay
            unbanResults.push({ serverId, success: false, error: unbanErr.message });
          }
        }
      } catch (sourceErr) {
        console.error(`[WARNINGS] Error unbanning from source ${source.name}:`, sourceErr.message);
      }
    }

    // Also clear the isBanned flag in our database
    await db.updatePlayer(upperGuid, { isBanned: false, banReason: null, banExpiry: null });

    console.log(`[WARNINGS] Player ${upperGuid} acknowledged warning and was auto-unbanned`);
    res.json({ success: true, warning, unbanResults });
  } catch (err) {
    console.error('[WARNINGS] Error acknowledging warning:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============ ADMIN WARNINGS ============

app.post('/api/admin/warn', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { playerGuid, playerName, reason, reportId } = req.body;

    if (!playerGuid || !reason) {
      return res.status(400).json({ error: 'Player GUID and reason are required' });
    }

    const upperGuid = playerGuid.toUpperCase();
    const adminName = req.user.displayName || req.user.email;

    // Create the warning record
    const warning = await db.createWarning({
      playerGuid: upperGuid,
      playerName: playerName || 'Unknown',
      reason,
      warnedBy: adminName,
      reportId
    });

    // First, send the warning message to the player in-game (before banning/kicking)
    console.log(`[ADMIN] Sending warning message to ${playerName} (${upperGuid})...`);

    const sources = getApiSources();
    const messageResults = [];

    // Send warning message via Manager's /warn endpoint (sends private + global messages)
    for (const source of sources) {
      try {
        const result = await fetchFromManager(source, '/warn', 'POST', {
          playerGuid: upperGuid,
          playerName: playerName || 'Unknown',
          reason: reason
        });
        messageResults.push({ source: source.id, success: true, result });
      } catch (msgErr) {
        // Player might not be online, that's okay
        messageResults.push({ source: source.id, success: false, error: msgErr.message });
      }
    }

    // Small delay to ensure message is delivered before kick
    await new Promise(resolve => setTimeout(resolve, 200));

    // Ban the player on all servers until they acknowledge the warning
    console.log(`[ADMIN] Warning issued to ${playerName} (${upperGuid}) - banning until acknowledged...`);

    const banResults = [];
    const banReason = `Warning: ${reason} - You must acknowledge this warning on your profile at mxb-mods.com to be unbanned`;

    for (const source of sources) {
      try {
        const serversResp = await fetchFromManager(source, '/servers');
        const servers = Array.isArray(serversResp) ? serversResp : [];

        for (const server of servers) {
          const serverId = server.id || server.Id;
          try {
            await fetchFromManager(source, `/servers/${serverId}/ban`, 'POST', {
              playerGuid: upperGuid,
              playerName: playerName || 'Unknown',
              reason: banReason,
              duration: 0, // Permanent until acknowledged
              isPermanent: true,
              sendPrivateMessage: false, // Don't send ban message, we already sent warning message
              sendGlobalMessage: false   // Don't broadcast ban, warning was already broadcast
            });
            banResults.push({ serverId, success: true });
          } catch (banErr) {
            banResults.push({ serverId, success: false, error: banErr.message });
          }
        }
      } catch (sourceErr) {
        console.error(`[ADMIN] Error banning from source ${source.name}:`, sourceErr.message);
      }
    }

    // Update player record to show banned status
    await db.updatePlayer(upperGuid, {
      isBanned: true,
      banReason: banReason
    });

    // Log to ban history
    await db.addBanHistory({
      playerGuid: upperGuid,
      playerName: playerName || 'Unknown',
      action: 'ban',
      reason: banReason,
      isGlobal: true,
      isPermanent: true,
      performedBy: adminName,
      sourceManager: 'Website (Warning)'
    });

    console.log(`[ADMIN] Warning issued and player banned by ${adminName}: ${reason}`);
    res.json({ success: true, warning, messageResults, banResults });
  } catch (err) {
    console.error('[ADMIN] Warn error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/warnings/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const success = await db.deleteWarning(id);

    if (!success) {
      return res.status(404).json({ error: 'Warning not found' });
    }

    console.log(`[ADMIN] Warning ${id} deleted by ${req.user.displayName}`);
    res.json({ success: true });
  } catch (err) {
    console.error('[ADMIN] Delete warning error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get recent acknowledged warnings (for admin notifications)
app.get('/api/admin/warnings/acknowledged', requireAuth, requireModerator, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const acknowledged = await db.getRecentAcknowledgedWarnings(limit);
    res.json(acknowledged);
  } catch (err) {
    console.error('[ADMIN] Get acknowledged warnings error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get all warnings (for admin view)
app.get('/api/admin/warnings', requireAuth, requireModerator, async (req, res) => {
  try {
    const result = await db.pool.query(`
      SELECT * FROM player_warnings
      ORDER BY "createdAt" DESC
      LIMIT 100
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('[ADMIN] Get all warnings error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/bans', requireAuth, requireModerator, async (req, res) => {
  try {
    const sources = getApiSources();
    const allBansMap = new Map();
    const errors = [];

    let serverData = stateManager.getCachedServerData();
    if (!serverData) {
      serverData = await stateManager.fetchServersFromAPI();
    }
    const servers = serverData?.servers || [];

    await Promise.all(sources.map(async (source) => {
      try {
        const managerServersResp = await fetchFromManager(source, '/servers');
        const managerServers = Array.isArray(managerServersResp) ? managerServersResp : [];

        for (const server of managerServers) {
          const serverId = server.id || server.Id;
          try {
            const bans = await fetchFromManager(source, `/servers/${serverId}/bans`);
            if (Array.isArray(bans)) {
              for (const ban of bans) {
                const guid = (ban.playerGuid || ban.PlayerGuid || '').toUpperCase();
                if (!guid) continue;

                const normalizedBan = {
                  id: ban.id || ban.Id,
                  playerGuid: guid,
                  playerName: ban.playerName || ban.PlayerName || 'Unknown',
                  reason: ban.reason || ban.Reason || 'No reason provided',
                  bannedAt: ban.bannedAt || ban.BannedAt,
                  expiresAt: ban.expiresAt || ban.ExpiresAt || null,
                  bannedBy: ban.bannedBy || ban.BannedBy || 'System',
                  isGlobal: ban.isGlobal ?? ban.IsGlobal ?? true,
                  isActive: ban.isActive ?? ban.IsActive ?? true,
                  durationDescription: ban.durationDescription || ban.DurationDescription || null,
                  sourceManager: source.id,
                  serverName: server.name || server.Name || 'Unknown Server'
                };

                const existing = allBansMap.get(guid);
                if (!existing) {
                  allBansMap.set(guid, normalizedBan);
                } else {
                  const existingDate = new Date(existing.bannedAt || 0);
                  const newDate = new Date(normalizedBan.bannedAt || 0);
                  if (newDate > existingDate) {
                    normalizedBan.onBothManagers = existing.sourceManager !== source.id;
                    allBansMap.set(guid, normalizedBan);
                  } else if (existing.sourceManager !== source.id) {
                    existing.onBothManagers = true;
                  }
                }
              }
            }
          } catch (banErr) {
          }
        }
      } catch (err) {
        errors.push({ source: source.id, error: err.message });
      }
    }));

    const uniqueBans = Array.from(allBansMap.values());
    console.log(`[ADMIN] Fetched ${uniqueBans.length} unique bans from ${sources.length} managers`);

    // Cross-reference with ban_history to get correct performedBy (admin name)
    try {
      for (const ban of uniqueBans) {
        const banHistory = await db.getBanHistory(ban.playerGuid);
        if (banHistory && banHistory.length > 0) {
          // Find the most recent ban entry
          const banEntries = banHistory.filter(h => h.action === 'ban');
          if (banEntries.length > 0) {
            // First try to match by reason
            let matchingEntry = banEntries.find(h => h.reason === ban.reason);
            // If no match by reason, use the most recent ban (already sorted by createdAt DESC)
            if (!matchingEntry) {
              matchingEntry = banEntries[0];
            }

            if (matchingEntry?.performedBy &&
                matchingEntry.performedBy !== 'System' &&
                matchingEntry.performedBy !== 'WebAPI' &&
                matchingEntry.performedBy !== 'WEBAPI') {
              ban.bannedBy = matchingEntry.performedBy;
            }
          }
        }
      }
    } catch (historyErr) {
      console.log('[ADMIN] Could not enrich bans with history:', historyErr.message);
    }

    res.json({
      bans: uniqueBans,
      totalUnique: uniqueBans.length,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (err) {
    console.error('[ADMIN] Get all bans error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/servers/:serverId/bans', requireAuth, requireModerator, async (req, res) => {
  try {
    const { serverId } = req.params;
    const sources = getApiSources();

    for (const source of sources) {
      try {
        const bans = await fetchFromManager(source, `/servers/${serverId}/bans`);
        return res.json(bans);
      } catch (err) {
      }
    }

    res.json([]);
  } catch (err) {
    console.error('[ADMIN] Get bans error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/ban', requireAuth, requireAdmin, async (req, res) => {
  try {
    const banData = req.body;
    const sources = getApiSources();
    const results = [];
    const errors = [];

    // Calculate expiry timestamp
    let expiresAt = null;
    const isPermanent = banData.durationType === 'Permanent' || !banData.duration;
    if (!isPermanent && banData.duration) {
      const now = Date.now();
      const durationMs = {
        'Minutes': banData.duration * 60 * 1000,
        'Hours': banData.duration * 60 * 60 * 1000,
        'Days': banData.duration * 24 * 60 * 60 * 1000,
        'Months': banData.duration * 30 * 24 * 60 * 60 * 1000,
        'Years': banData.duration * 365 * 24 * 60 * 60 * 1000
      }[banData.durationType] || banData.duration * 60 * 60 * 1000;
      expiresAt = now + durationMs;
    }

    for (const source of sources) {
      try {
        const serversResp = await fetchFromManager(source, '/servers');
        const servers = Array.isArray(serversResp) ? serversResp : [];
        if (servers.length > 0) {
          const firstServer = servers[0];
          const serverId = firstServer.id || firstServer.Id;
          // Use full-ban endpoint if available, fallback to ban endpoint
          let result;
          let usedEndpoint = 'full-ban';
          const adminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';
          const isGlobal = banData.isGlobal !== false; // Default to true if not explicitly false
          try {
            result = await fetchFromManager(source, `/servers/${serverId}/full-ban`, 'POST', {
              ...banData,
              isGlobal,
              bannedBy: adminName
            });
            console.log(`[ADMIN] Ban succeeded via full-ban on ${source.id} by ${adminName} (global: ${isGlobal})`);
          } catch (fullBanErr) {
            console.log(`[ADMIN] full-ban failed on ${source.id}: ${fullBanErr.message}, trying ban endpoint`);
            usedEndpoint = 'ban';
            result = await fetchFromManager(source, `/servers/${serverId}/ban`, 'POST', {
              ...banData,
              isGlobal
            });
            console.log(`[ADMIN] Ban succeeded via ban on ${source.id} (global: ${isGlobal})`);
          }
          results.push({ source: source.id, result, endpoint: usedEndpoint });
        } else {
          console.log(`[ADMIN] No servers found on ${source.id}`);
        }
      } catch (err) {
        console.error(`[ADMIN] Ban failed on ${source.id}: ${err.message}`);
        errors.push({ source: source.id, error: err.message });
      }
    }

    // Store ban history
    if (results.length > 0) {
      const adminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';
      try {
        await db.addBanHistory({
          playerGuid: banData.playerGuid,
          playerName: banData.playerName,
          action: 'ban',
          reason: banData.reason,
          duration: banData.duration,
          durationType: banData.durationType,
          isGlobal: true,
          isPermanent,
          expiresAt,
          performedBy: adminName,
          sourceManager: results.map(r => r.source).join(','),
          serverName: null, // Global ban - all servers
          evidenceUrl: banData.evidenceUrl || null // Video evidence from reports
        });
      } catch (histErr) {
        console.error('[ADMIN] Failed to store ban history:', histErr.message);
      }

      // Reduce safety rating by 20% when banned
      try {
        await db.reduceSafetyRating(banData.playerGuid, 0.2);
        console.log(`[ADMIN] Safety rating reduced by 20% for ${banData.playerName}`);
      } catch (srErr) {
        console.error('[ADMIN] Failed to reduce safety rating:', srErr.message);
      }
    }

    console.log(`[ADMIN] Banned player ${banData.playerName} on ${results.length} managers, ${errors.length} errors`);

    // Return more detailed response
    const response = {
      success: results.length > 0,
      results,
      errors,
      message: results.length > 0
        ? `Banned on ${results.length} manager(s)${errors.length > 0 ? `, ${errors.length} failed` : ''}`
        : errors.length > 0
          ? `Ban failed: ${errors.map(e => e.error).join(', ')}`
          : 'No managers available'
    };

    if (results.length === 0 && errors.length > 0) {
      res.status(400).json(response);
    } else {
      res.json(response);
    }
  } catch (err) {
    console.error('[ADMIN] Global ban error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/servers/:serverId/ban', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const banData = req.body;
    const sources = getApiSources();
    const adminName = req.userProfile?.displayName || req.user?.name || req.user?.email || 'Admin';
    const isGlobal = banData.isGlobal === true; // Default to false for server-specific bans

    const results = [];
    const errors = [];
    let serverName = null;

    // Try all managers - the one that owns this server will succeed
    for (const source of sources) {
      try {
        // First check if this manager has this server
        const serversResp = await fetchFromManager(source, '/servers');
        const servers = Array.isArray(serversResp) ? serversResp : [];
        const server = servers.find(s => (s.id || s.Id) === serverId);

        if (!server) {
          console.log(`[ADMIN] Server ${serverId} not found on ${source.id}, skipping`);
          continue;
        }

        // Capture server name for ban history
        serverName = server.name || server.Name || serverName;

        // This manager has the server, do the ban
        let result;
        try {
          result = await fetchFromManager(source, `/servers/${serverId}/full-ban`, 'POST', {
            ...banData,
            isGlobal,
            bannedBy: adminName
          });
          console.log(`[ADMIN] Banned player ${banData.playerName} on server ${serverName} via full-ban on ${source.id}`);
        } catch (fullBanErr) {
          console.log(`[ADMIN] full-ban failed on ${source.id}: ${fullBanErr.message}, trying basic ban`);
          result = await fetchFromManager(source, `/servers/${serverId}/ban`, 'POST', {
            ...banData,
            isGlobal
          });
          console.log(`[ADMIN] Banned player ${banData.playerName} on server ${serverName} via basic ban on ${source.id}`);
        }
        results.push({ source: source.id, result, serverName });
      } catch (err) {
        console.error(`[ADMIN] Ban failed on ${source.id}: ${err.message}`);
        errors.push({ source: source.id, error: err.message });
      }
    }

    if (results.length === 0) {
      const errorMsg = errors.length > 0
        ? `Ban failed: ${errors.map(e => e.error).join(', ')}`
        : `Server ${serverId} not found on any manager`;
      return res.status(400).json({ success: false, error: errorMsg, errors });
    }

    // Store ban history with server name
    try {
      // Calculate expiry for history
      let expiresAt = null;
      const isPermanent = banData.durationType === 'Permanent' || !banData.duration;
      if (!isPermanent && banData.duration) {
        const now = Date.now();
        const durationMs = {
          'Minutes': banData.duration * 60 * 1000,
          'Hours': banData.duration * 60 * 60 * 1000,
          'Days': banData.duration * 24 * 60 * 60 * 1000,
          'Months': banData.duration * 30 * 24 * 60 * 60 * 1000,
          'Years': banData.duration * 365 * 24 * 60 * 60 * 1000
        }[banData.durationType] || banData.duration * 60 * 60 * 1000;
        expiresAt = now + durationMs;
      }

      await db.addBanHistory({
        playerGuid: banData.playerGuid,
        playerName: banData.playerName,
        action: 'ban',
        reason: banData.reason,
        duration: banData.duration,
        durationType: banData.durationType,
        isGlobal: false,
        isPermanent,
        expiresAt,
        performedBy: adminName,
        sourceManager: results.map(r => r.source).join(','),
        serverName: serverName, // Store which server they were banned from
        evidenceUrl: banData.evidenceUrl || null // Video evidence from reports
      });

      // Reduce safety rating by 20% when banned
      try {
        await db.reduceSafetyRating(banData.playerGuid, 0.2);
        console.log(`[ADMIN] Safety rating reduced by 20% for ${banData.playerName}`);
      } catch (srErr) {
        console.error('[ADMIN] Failed to reduce safety rating:', srErr.message);
      }
    } catch (histErr) {
      console.error('[ADMIN] Failed to store ban history:', histErr.message);
    }

    res.json({
      success: true,
      message: `Banned on ${serverName || 'server'}`,
      results,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (err) {
    console.error('[ADMIN] Ban player error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/unban', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { playerGuid, playerName } = req.body;
    const sources = getApiSources();
    const results = [];
    const errors = [];

    for (const source of sources) {
      try {
        const serversResp = await fetchFromManager(source, '/servers');
        const servers = Array.isArray(serversResp) ? serversResp : [];

        if (servers.length > 0) {
          const firstServer = servers[0];
          const serverId = firstServer.id || firstServer.Id;
          try {
            // Use full-unban endpoint if available, fallback to unban endpoint
            const result = await fetchFromManager(source, `/servers/${serverId}/full-unban`, 'POST', { playerGuid })
              .catch(() => fetchFromManager(source, `/servers/${serverId}/unban`, 'POST', { playerGuid }));
            results.push({ source: source.id, result });
          } catch (err) {
            errors.push({ source: source.id, error: err.message });
          }
        }
      } catch (err) {
        errors.push({ source: source.id, error: err.message });
      }
    }

    // Store unban history
    if (results.length > 0) {
      try {
        await db.addBanHistory({
          playerGuid,
          playerName: playerName || 'Unknown',
          action: 'unban',
          reason: null,
          isGlobal: true,
          performedBy: req.user?.email || 'Admin',
          sourceManager: results.map(r => r.source).join(',')
        });
      } catch (histErr) {
        console.error('[ADMIN] Failed to store unban history:', histErr.message);
      }
    }

    console.log(`[ADMIN] Unbanned player ${playerGuid} from ${results.length} managers`);
    res.json({
      success: results.length > 0,
      message: `Unbanned from ${results.length} manager(s)`,
      results,
      errors
    });
  } catch (err) {
    console.error('[ADMIN] Global unban error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/servers/:serverId/unban', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { playerGuid } = req.body;
    const result = await proxyToManager(`/servers/${serverId}/unban`, 'POST', { playerGuid });
    console.log(`[ADMIN] Unbanned player ${playerGuid} on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Unban player error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Ban History Endpoints
app.get('/api/admin/ban-history', requireAuth, requireAdmin, async (req, res) => {
  try {
    const history = await db.getAllBanHistory(200);
    res.json(history);
  } catch (err) {
    console.error('[ADMIN] Get ban history error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/ban-history/:playerGuid', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { playerGuid } = req.params;
    const history = await db.getBanHistory(playerGuid);
    res.json(history);
  } catch (err) {
    console.error('[ADMIN] Get player ban history error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Delete ban history entry
app.delete('/api/admin/ban-history/entry/:entryId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { entryId } = req.params;
    const success = await db.deleteBanHistoryEntry(entryId);
    if (!success) {
      return res.status(404).json({ error: 'Ban history entry not found' });
    }
    console.log(`[ADMIN] Ban history entry ${entryId} deleted`);
    res.json({ success: true });
  } catch (err) {
    console.error('[ADMIN] Delete ban history error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Ban Sync Endpoint - syncs bans between all managers
app.post('/api/admin/sync-bans', requireAuth, requireAdmin, async (req, res) => {
  try {
    const sources = getApiSources();
    if (sources.length < 2) {
      return res.json({ success: true, message: 'Only one manager configured, no sync needed', synced: 0 });
    }

    // Fetch bans from all managers
    const managerBans = {};
    for (const source of sources) {
      try {
        const serversResp = await fetchFromManager(source, '/servers');
        const servers = Array.isArray(serversResp) ? serversResp : [];
        if (servers.length > 0) {
          const serverId = servers[0].id || servers[0].Id;
          const bans = await fetchFromManager(source, `/servers/${serverId}/bans`);
          managerBans[source.id] = {
            source,
            serverId,
            bans: Array.isArray(bans) ? bans : []
          };
        }
      } catch (err) {
        console.error(`[SYNC] Failed to fetch bans from ${source.id}:`, err.message);
      }
    }

    const managerIds = Object.keys(managerBans);
    if (managerIds.length < 2) {
      return res.json({ success: false, error: 'Could not reach multiple managers' });
    }

    // Find and sync missing bans
    const syncResults = [];

    for (const sourceManagerId of managerIds) {
      const sourceBans = managerBans[sourceManagerId].bans;

      for (const targetManagerId of managerIds) {
        if (sourceManagerId === targetManagerId) continue;

        const targetBans = managerBans[targetManagerId].bans;
        const targetGuids = new Set(targetBans.map(b => b.playerGuid?.toUpperCase() || b.PlayerGuid?.toUpperCase()));

        // Find bans missing in target
        const missingBans = sourceBans.filter(ban => {
          const guid = (ban.playerGuid || ban.PlayerGuid || '').toUpperCase();
          return guid && !targetGuids.has(guid);
        });

        // Sync missing bans to target
        for (const ban of missingBans) {
          try {
            const targetSource = managerBans[targetManagerId].source;
            const targetServerId = managerBans[targetManagerId].serverId;

            await fetchFromManager(targetSource, `/servers/${targetServerId}/ban`, 'POST', {
              PlayerName: ban.playerName || ban.PlayerName,
              PlayerGuid: ban.playerGuid || ban.PlayerGuid,
              Reason: ban.reason || ban.Reason || 'Synced from another manager',
              Duration: 0,
              DurationType: 'Permanent',
              IsGlobal: true
            });

            syncResults.push({
              from: sourceManagerId,
              to: targetManagerId,
              playerGuid: ban.playerGuid || ban.PlayerGuid,
              playerName: ban.playerName || ban.PlayerName,
              success: true
            });

            console.log(`[SYNC] Synced ban for ${ban.playerName || ban.PlayerName} from ${sourceManagerId} to ${targetManagerId}`);
          } catch (err) {
            syncResults.push({
              from: sourceManagerId,
              to: targetManagerId,
              playerGuid: ban.playerGuid || ban.PlayerGuid,
              success: false,
              error: err.message
            });
          }
        }
      }
    }

    const successCount = syncResults.filter(r => r.success).length;
    console.log(`[SYNC] Ban sync completed: ${successCount} bans synced`);

    res.json({
      success: true,
      synced: successCount,
      total: syncResults.length,
      results: syncResults
    });
  } catch (err) {
    console.error('[ADMIN] Ban sync error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/servers/:serverId/kick', requireAuth, requireModerator, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { playerGuid } = req.body;
    const result = await proxyToManager(`/servers/${serverId}/kick`, 'POST', { playerGuid });
    console.log(`[ADMIN] Kicked player ${playerGuid} from server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Kick player error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/servers/:serverId/start', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/start`, 'POST');
    console.log(`[ADMIN] Started server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Start server error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/servers/:serverId/stop', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/stop`, 'POST');
    console.log(`[ADMIN] Stopped server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Stop server error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/servers/:serverId/restart', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/restart`, 'POST');
    console.log(`[ADMIN] Restarted server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Restart server error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/servers/:serverId/message', requireAuth, requireModerator, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { message, targetGuid } = req.body;
    // Pass targetGuid if provided for private messages, otherwise public message
    const payload = targetGuid ? { message, targetGuid } : { message };
    const result = await proxyToManager(`/servers/${serverId}/message`, 'POST', payload);
    console.log(`[ADMIN] Sent ${targetGuid ? 'private' : 'public'} message to server ${serverId}: ${message}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Send message error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/servers/:serverId/config', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const config = req.body;
    const result = await proxyToManager(`/servers/${serverId}/config`, 'POST', config);
    console.log(`[ADMIN] Updated config for server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Update config error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/servers/:serverId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const sourceNum = parseInt(req.query.source) || 1;
    const result = await proxyToSpecificManager(sourceNum, `/servers/${serverId}`, 'DELETE');
    console.log(`[ADMIN] Deleted server ${serverId} from manager ${sourceNum}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Delete server error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/servers', requireAuth, requireAdmin, async (req, res) => {
  try {
    const config = req.body;
    const result = await proxyToManager('/servers', 'POST', config);
    console.log(`[ADMIN] Created new server`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Create server error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Reset track deformation/dynamics
app.post('/api/admin/servers/:serverId/reset-track', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/reset-track`, 'POST');
    console.log(`[ADMIN] Reset track on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Reset track error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Start specific session (practice, pre-qualify, qualify, warmup, race1, race2)
app.post('/api/admin/servers/:serverId/start-session', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { sessionType } = req.body;
    const result = await proxyToManager(`/servers/${serverId}/start-session`, 'POST', { sessionType });
    console.log(`[ADMIN] Started session ${sessionType} on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Start session error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Black flag (disqualify) a player
app.post('/api/admin/servers/:serverId/blackflag', requireAuth, requireModerator, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { playerGuid, playerName, raceNumber } = req.body;
    const result = await proxyToManager(`/servers/${serverId}/blackflag`, 'POST', { playerGuid, playerName, raceNumber });
    console.log(`[ADMIN] Black flagged player ${playerName || raceNumber} on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Black flag error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Make player admin in-game
app.post('/api/admin/servers/:serverId/makeadmin', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { playerGuid, playerName, raceNumber } = req.body;
    const result = await proxyToManager(`/servers/${serverId}/makeadmin`, 'POST', { playerGuid, playerName, raceNumber });
    console.log(`[ADMIN] Made player ${playerName || raceNumber} admin on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Make admin error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Send raw remote admin command
app.post('/api/admin/servers/:serverId/remoteadmin/command', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { command } = req.body;
    const result = await proxyToManager(`/servers/${serverId}/remoteadmin/command`, 'POST', { command });
    console.log(`[ADMIN] Sent remote admin command to server ${serverId}: ${command}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Remote admin command error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get server admins list
app.get('/api/admin/servers/:serverId/admins', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/admins`, 'GET');
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Get server admins error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Add server admin
app.post('/api/admin/servers/:serverId/admins', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const adminData = req.body;
    const result = await proxyToManager(`/servers/${serverId}/admins`, 'POST', adminData);
    console.log(`[ADMIN] Added admin ${adminData.name} to server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Add server admin error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Remove server admin
app.delete('/api/admin/servers/:serverId/admins/:adminId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId, adminId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/admins/${adminId}`, 'DELETE');
    console.log(`[ADMIN] Removed admin ${adminId} from server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Remove server admin error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get server whitelist
app.get('/api/admin/servers/:serverId/whitelist', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/whitelist`, 'GET');
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Get whitelist error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Add player to whitelist
app.post('/api/admin/servers/:serverId/whitelist', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const entryData = req.body;
    const result = await proxyToManager(`/servers/${serverId}/whitelist`, 'POST', entryData);
    console.log(`[ADMIN] Added ${entryData.name || entryData.guid} to whitelist on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Add to whitelist error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update whitelist entry (full MXB fields support)
app.put('/api/admin/servers/:serverId/whitelist/:entryIndex', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId, entryIndex } = req.params;
    const entryData = req.body;
    const result = await proxyToManager(`/servers/${serverId}/whitelist/${entryIndex}`, 'PUT', entryData);
    console.log(`[ADMIN] Updated whitelist entry ${entryIndex} on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Update whitelist entry error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Remove player from whitelist
app.delete('/api/admin/servers/:serverId/whitelist/:entryId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId, entryId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/whitelist/${entryId}`, 'DELETE');
    console.log(`[ADMIN] Removed entry ${entryId} from whitelist on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Remove from whitelist error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update whitelist (reload from file)
app.post('/api/admin/servers/:serverId/whitelist/reload', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/whitelist/reload`, 'POST');
    console.log(`[ADMIN] Reloaded whitelist on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Reload whitelist error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// TRACK LIST & SERVER CONFIG ENDPOINTS
// ==========================================

// Helper to proxy to a specific manager by source number (1 or 2)
async function proxyToSpecificManager(sourceNum, endpoint, method = 'GET', body = null) {
  const sources = getApiSources();
  const targetId = sourceNum === 2 ? 'manager2' : 'manager1';
  const source = sources.find(s => s.id === targetId);

  if (!source) {
    throw new Error(`Manager ${sourceNum} not configured`);
  }

  return await fetchFromManager(source, endpoint, method, body);
}

// Get tracks from specific manager (for track selection in server config)
app.get('/api/admin/tracks', requireAuth, requireAdmin, async (req, res) => {
  try {
    const sourceNum = parseInt(req.query.source) || 1;
    const result = await proxyToSpecificManager(sourceNum, '/tracks', 'GET');
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Get tracks error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get full server configuration
app.get('/api/admin/servers/:serverId/config', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/config`, 'GET');
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Get server config error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update server configuration (PUT - comprehensive update)
app.put('/api/admin/servers/:serverId/config', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const config = req.body;
    const result = await proxyToManager(`/servers/${serverId}/config`, 'PUT', config);
    console.log(`[ADMIN] Updated full config for server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Update server config error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Create new server on specific manager
app.post('/api/admin/servers/create', requireAuth, requireAdmin, async (req, res) => {
  try {
    const sourceNum = parseInt(req.query.source) || 1;
    const config = req.body;
    const result = await proxyToSpecificManager(sourceNum, '/servers/create', 'POST', config);
    console.log(`[ADMIN] Created new server on manager ${sourceNum}: ${config.name || 'unnamed'}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Create server error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// ANALYTICS ENDPOINTS
// ==========================================

// In-memory analytics store (synced to Firestore periodically)
const analyticsCache = {
  pageViews: [],
  activeVisitors: new Map(), // visitorId -> { lastSeen, sessionId }
  lastFlush: Date.now()
};

const ANALYTICS_FLUSH_INTERVAL = 60000; // Flush to Firestore every 60 seconds
const ACTIVE_VISITOR_TIMEOUT = 300000; // 5 minutes

// Parse user agent for device type
function getDeviceType(userAgent) {
  if (!userAgent) return 'unknown';
  const ua = userAgent.toLowerCase();
  if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/i.test(ua)) return 'mobile';
  if (/ipad|tablet|playbook|silk/i.test(ua)) return 'tablet';
  return 'desktop';
}

// Public endpoint - Track page views (no auth required, uses sendBeacon)
app.post('/api/analytics/track', express.text({ type: '*/*' }), async (req, res) => {
  try {
    let data;
    try {
      data = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    } catch (e) {
      return res.status(400).json({ error: 'Invalid JSON' });
    }

    const { visitorId, sessionId, userId, page, type, timestamp, userAgent, screenWidth } = data;

    if (!visitorId || !sessionId) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Update active visitors
    analyticsCache.activeVisitors.set(visitorId, {
      lastSeen: Date.now(),
      sessionId,
      page
    });

    // Track page view
    if (type !== 'session_end') {
      analyticsCache.pageViews.push({
        visitorId,
        sessionId,
        userId: userId || null,
        page: page || '/',
        deviceType: getDeviceType(userAgent),
        screenWidth: screenWidth || null,
        timestamp: timestamp || new Date().toISOString()
      });
    }

    // Clean up stale active visitors
    const now = Date.now();
    for (const [id, visitor] of analyticsCache.activeVisitors) {
      if (now - visitor.lastSeen > ACTIVE_VISITOR_TIMEOUT) {
        analyticsCache.activeVisitors.delete(id);
      }
    }

    res.status(200).json({ success: true });
  } catch (err) {
    console.error('[ANALYTICS] Track error:', err.message);
    res.status(500).json({ error: 'Failed to track' });
  }
});

// Flush analytics to Firestore
async function flushAnalyticsToFirestore() {
  if (!firebaseAdmin || analyticsCache.pageViews.length === 0) return;

  try {
    const firestore = firebaseAdmin.firestore();
    const batch = firestore.batch();
    const today = new Date().toISOString().split('T')[0];

    // Get or create daily stats document
    const dailyRef = firestore.collection('analytics_daily').doc(today);
    const dailyDoc = await dailyRef.get();

    let dailyData = dailyDoc.exists ? dailyDoc.data() : {
      date: today,
      uniqueVisitors: 0,
      pageViews: 0,
      visitors: [],
      pageViewsByPage: {},
      deviceBreakdown: { desktop: 0, mobile: 0, tablet: 0 },
      hourlyActivity: Array(24).fill(0)
    };

    // Ensure hourlyActivity exists for older documents
    if (!dailyData.hourlyActivity) {
      dailyData.hourlyActivity = Array(24).fill(0);
    }

    // Process cached page views
    const newVisitors = new Set(dailyData.visitors || []);
    for (const pv of analyticsCache.pageViews) {
      dailyData.pageViews++;

      // Track unique visitors
      if (!newVisitors.has(pv.visitorId)) {
        newVisitors.add(pv.visitorId);
        dailyData.uniqueVisitors++;
      }

      // Track by page
      dailyData.pageViewsByPage[pv.page] = (dailyData.pageViewsByPage[pv.page] || 0) + 1;

      // Track by device
      if (pv.deviceType && dailyData.deviceBreakdown[pv.deviceType] !== undefined) {
        dailyData.deviceBreakdown[pv.deviceType]++;
      }

      // Track by hour (UTC)
      const hour = new Date(pv.timestamp).getUTCHours();
      dailyData.hourlyActivity[hour] = (dailyData.hourlyActivity[hour] || 0) + 1;
    }

    dailyData.visitors = Array.from(newVisitors);
    dailyData.lastUpdated = new Date().toISOString();

    batch.set(dailyRef, dailyData, { merge: true });

    // Update totals
    const totalsRef = firestore.collection('analytics_totals').doc('summary');
    batch.set(totalsRef, {
      totalPageViews: firebaseAdmin.firestore.FieldValue.increment(analyticsCache.pageViews.length),
      lastUpdated: new Date().toISOString()
    }, { merge: true });

    await batch.commit();

    console.log(`[ANALYTICS] Flushed ${analyticsCache.pageViews.length} page views to Firestore`);
    analyticsCache.pageViews = [];
    analyticsCache.lastFlush = Date.now();
  } catch (err) {
    console.error('[ANALYTICS] Flush error:', err.message);
  }
}

// Start analytics flush loop
setInterval(flushAnalyticsToFirestore, ANALYTICS_FLUSH_INTERVAL);

// Admin endpoint - Get analytics data
app.get('/api/admin/analytics', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (!firebaseAdmin) {
      return res.status(503).json({ error: 'Analytics service unavailable' });
    }

    const range = req.query.range || '7d';
    const days = range === '90d' ? 90 : range === '30d' ? 30 : 7;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    const startDateStr = startDate.toISOString().split('T')[0];

    const firestore = firebaseAdmin.firestore();

    // Get daily stats for the range
    const dailySnapshot = await firestore
      .collection('analytics_daily')
      .where('date', '>=', startDateStr)
      .orderBy('date', 'asc')
      .get();

    const dailyStats = [];
    let totalVisitors = 0;
    let totalPageViews = 0;
    const allVisitors = new Set();
    const pageViewsByPage = {};
    const deviceBreakdown = { desktop: 0, mobile: 0, tablet: 0 };
    const hourlyActivity = Array(24).fill(0);

    dailySnapshot.forEach(doc => {
      const data = doc.data();
      dailyStats.push({
        date: data.date,
        uniqueVisitors: data.uniqueVisitors || 0,
        pageViews: data.pageViews || 0
      });

      totalPageViews += data.pageViews || 0;
      (data.visitors || []).forEach(v => allVisitors.add(v));

      // Aggregate page views
      for (const [page, count] of Object.entries(data.pageViewsByPage || {})) {
        pageViewsByPage[page] = (pageViewsByPage[page] || 0) + count;
      }

      // Aggregate device breakdown
      if (data.deviceBreakdown) {
        deviceBreakdown.desktop += data.deviceBreakdown.desktop || 0;
        deviceBreakdown.mobile += data.deviceBreakdown.mobile || 0;
        deviceBreakdown.tablet += data.deviceBreakdown.tablet || 0;
      }

      // Aggregate hourly activity (real data)
      if (data.hourlyActivity && Array.isArray(data.hourlyActivity)) {
        for (let i = 0; i < 24; i++) {
          hourlyActivity[i] += data.hourlyActivity[i] || 0;
        }
      }
    });

    totalVisitors = allVisitors.size;

    // Get today's stats
    const today = new Date().toISOString().split('T')[0];
    const todayDoc = await firestore.collection('analytics_daily').doc(today).get();
    const todayData = todayDoc.exists ? todayDoc.data() : { uniqueVisitors: 0, pageViews: 0 };

    // Get all-time totals
    const totalsDoc = await firestore.collection('analytics_totals').doc('summary').get();
    const totalsData = totalsDoc.exists ? totalsDoc.data() : { totalPageViews: 0 };

    // Top pages
    const topPages = Object.entries(pageViewsByPage)
      .map(([page, views]) => ({ page, views }))
      .sort((a, b) => b.views - a.views)
      .slice(0, 10);

    res.json({
      dailyStats,
      topPages,
      deviceBreakdown,
      hourlyActivity: hourlyActivity.map((visitors, hour) => ({ hour, visitors })),
      summary: {
        totalVisitors,
        todayVisitors: todayData.uniqueVisitors || 0,
        totalPageViews: totalsData.totalPageViews || totalPageViews,
        activeNow: analyticsCache.activeVisitors.size,
        avgSessionDuration: 180, // Placeholder - would need session tracking
        bounceRate: 35, // Placeholder
        newVisitors: Math.round(totalVisitors * 0.4),
        returningVisitors: Math.round(totalVisitors * 0.6)
      }
    });
  } catch (err) {
    console.error('[ANALYTICS] Fetch error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const LEADER_HEARTBEAT_INTERVAL = 5000;
const LEADER_STALE_THRESHOLD = 15000;
const LEADER_CHECK_INTERVAL = 3000;

// ============================================================================
// MESSAGE SETTINGS & AUTOMATED MESSAGES API
// ============================================================================

// Get message templates and settings
app.get('/api/admin/settings/messages', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await proxyToManager('/settings/messages', 'GET');
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Get message settings error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update message templates and settings (sends to ALL managers)
app.put('/api/admin/settings/messages', requireAuth, requireAdmin, async (req, res) => {
  try {
    const settings = req.body;
    // Use proxyToAllManagers to update settings on ALL managers, not just the first one
    const { results, errors } = await proxyToAllManagers('/settings/messages', 'PUT', settings);
    console.log(`[ADMIN] Updated message settings on ${results.length} manager(s), ${errors.length} error(s)`);

    if (results.length === 0 && errors.length > 0) {
      throw new Error(`All managers failed: ${errors.map(e => e.error).join(', ')}`);
    }

    // Return the first successful result for compatibility
    res.json(results.length > 0 ? results[0].result : { success: true });
  } catch (err) {
    console.error('[ADMIN] Update message settings error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get automated messages for a server
app.get('/api/admin/servers/:serverId/automatedmessages', requireAuth, requireModerator, async (req, res) => {
  try {
    const { serverId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/automatedmessages`, 'GET');
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Get automated messages error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Add automated message to a server
app.post('/api/admin/servers/:serverId/automatedmessages', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const messageData = req.body;
    const result = await proxyToManager(`/servers/${serverId}/automatedmessages`, 'POST', messageData);
    console.log(`[ADMIN] Added automated message to server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Add automated message error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update automated message
app.put('/api/admin/servers/:serverId/automatedmessages/:messageId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId, messageId } = req.params;
    const messageData = req.body;
    const result = await proxyToManager(`/servers/${serverId}/automatedmessages/${messageId}`, 'PUT', messageData);
    console.log(`[ADMIN] Updated automated message ${messageId} on server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Update automated message error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Delete automated message
app.delete('/api/admin/servers/:serverId/automatedmessages/:messageId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId, messageId } = req.params;
    const result = await proxyToManager(`/servers/${serverId}/automatedmessages/${messageId}`, 'DELETE');
    console.log(`[ADMIN] Deleted automated message ${messageId} from server ${serverId}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Delete automated message error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get ALL automated messages from ALL managers and ALL servers
app.get('/api/admin/settings/automatedmessages', requireAuth, requireModerator, async (req, res) => {
  try {
    const { results, errors } = await proxyToAllManagers('/settings/automatedmessages', 'GET');

    // Merge results from all managers
    const allMessages = [];
    for (const { source, result } of results) {
      if (Array.isArray(result)) {
        for (const msg of result) {
          allMessages.push({
            ...msg,
            managerId: source
          });
        }
      }
    }

    res.json({ messages: allMessages, errors });
  } catch (err) {
    console.error('[ADMIN] Get all automated messages error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Add automated message to a specific manager's server
app.post('/api/admin/settings/automatedmessages', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { serverId, message, intervalMinutes, isEnabled, isGlobal, managerId } = req.body;

    if (!serverId || !message) {
      return res.status(400).json({ error: 'Server ID and message are required' });
    }

    // Use specific manager if provided, otherwise use default proxy
    const sources = getApiSources();
    const targetSource = managerId ? sources.find(s => s.id === managerId) : sources[0];

    if (!targetSource) {
      return res.status(400).json({ error: 'Invalid manager specified' });
    }

    const result = await fetchFromManager(targetSource, `/servers/${serverId}/automatedmessages`, 'POST', {
      message: message.slice(0, 99), // Enforce 99 char limit
      intervalMinutes: intervalMinutes || 5,
      isEnabled: isEnabled !== false,
      isGlobal: isGlobal || false
    });

    console.log(`[ADMIN] Added automated message to server ${serverId} on ${targetSource.id}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Add automated message error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Delete automated message from specific manager
app.delete('/api/admin/settings/automatedmessages/:messageId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { serverId, managerId } = req.query;

    if (!serverId) {
      return res.status(400).json({ error: 'Server ID is required' });
    }

    const sources = getApiSources();
    const targetSource = managerId ? sources.find(s => s.id === managerId) : sources[0];

    if (!targetSource) {
      return res.status(400).json({ error: 'Invalid manager specified' });
    }

    const result = await fetchFromManager(targetSource, `/servers/${serverId}/automatedmessages/${messageId}`, 'DELETE');
    console.log(`[ADMIN] Deleted automated message ${messageId} from server ${serverId} on ${targetSource.id}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Delete automated message error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Toggle automated message enabled/disabled
app.put('/api/admin/settings/automatedmessages/:messageId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { serverId, managerId, isEnabled, message, intervalMinutes, isGlobal } = req.body;

    if (!serverId) {
      return res.status(400).json({ error: 'Server ID is required' });
    }

    const sources = getApiSources();
    const targetSource = managerId ? sources.find(s => s.id === managerId) : sources[0];

    if (!targetSource) {
      return res.status(400).json({ error: 'Invalid manager specified' });
    }

    const result = await fetchFromManager(targetSource, `/servers/${serverId}/automatedmessages/${messageId}`, 'PUT', {
      message,
      intervalMinutes,
      isEnabled,
      isGlobal
    });

    console.log(`[ADMIN] Updated automated message ${messageId} on server ${serverId} on ${targetSource.id}`);
    res.json(result);
  } catch (err) {
    console.error('[ADMIN] Update automated message error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Discord Webhook for Server List - DISABLED
// To re-enable: uncomment startDiscordServerListLoop() call in the leader election section
/*
const DISCORD_SERVERLIST_WEBHOOK = 'https://discord.com/api/webhooks/1445267775609245726/AYqI__1rlHdIF1oc1fsgVqE65PwNa5kImpEHDVqZByH71zNLzp0gsb1E_jtMRd2vKu_h';
const DISCORD_UPDATE_INTERVAL = 10 * 1000;
let discordMessageId = null;
let discordLoopInterval = null;

async function updateDiscordServerList() { }
async function testDiscordWebhook() { }
*/
function startDiscordServerListLoop() {
  // DISABLED - does nothing
}

app.listen(PORT, async () => {
  console.log(`[SERVER] MXBikes Stats Server running on port ${PORT}`);
  console.log(`[SERVER] PostgreSQL connected`);

  const machineId = process.env.FLY_MACHINE_ID || 'local';
  console.log(`[SERVER] Machine ID: ${machineId}`);

  await db.initLeaderTable();

  // Start background ban sync on ALL instances (needed for API responses)
  startBannedGuidsSyncLoop();

  // Start background bulk cache pre-generation (INSTANT responses, no DB wait)
  startBulkCacheLoop();

  let isLeader = false;
  let updateLoopInterval = null;
  let cycleRunning = false;
  let cycleStartTime = 0;
  let consecutiveSkips = 0;
  const MAX_CYCLE_TIME = 20000;
  const MAX_CONSECUTIVE_SKIPS = 8;

  const startUpdateLoop = async () => {
    if (updateLoopInterval) return;

    console.log(`[SERVER] ${machineId} starting PRIMARY update loop`);

    await stateManager.recoverStateFromDatabase();

    // Run first update immediately
    console.log(`[SERVER] Running initial data fetch...`);
    try {
      await stateManager.runUpdateCycle();
      console.log(`[SERVER] Initial data fetch complete`);
    } catch (err) {
      console.error('[SERVER] Initial fetch error:', err.message);
    }

    updateLoopInterval = setInterval(async () => {
      if (cycleRunning) {
        const cycleAge = Date.now() - cycleStartTime;
        consecutiveSkips++;

        if (cycleAge > MAX_CYCLE_TIME || consecutiveSkips >= MAX_CONSECUTIVE_SKIPS) {
          console.error(`[UPDATE LOOP] FORCE RESET - cycle stuck for ${cycleAge}ms (${consecutiveSkips} skips)`);

          if (stateManager.currentAbortController) {
            console.log('[UPDATE LOOP] Aborting stuck cycle via AbortController');
            stateManager.currentAbortController.abort();
          }

          cycleRunning = false;
          consecutiveSkips = 0;
        } else {
          console.log(`[UPDATE LOOP] Skipping - previous cycle running (${Math.round(cycleAge/1000)}s, skip #${consecutiveSkips})`);
          return;
        }
      }

      try {
        const stillLeader = await db.isLeader(machineId);
        if (!stillLeader) {
          console.log(`[SERVER] ${machineId} lost leadership, stopping update loop`);
          stopUpdateLoop();
          isLeader = false;
          return;
        }
      } catch (err) {
        console.error('[UPDATE LOOP] Leader check failed:', err.message);
      }

      cycleRunning = true;
      cycleStartTime = Date.now();
      consecutiveSkips = 0;

      try {
        await stateManager.runUpdateCycle();
        // Avatar sync handled by dedicated startAvatarSyncLoop()
      } catch (err) {
        console.error('[UPDATE LOOP] Error:', err.message);
      } finally {
        cycleRunning = false;
      }
    }, 5000);
  };

  const stopUpdateLoop = () => {
    if (updateLoopInterval) {
      clearInterval(updateLoopInterval);
      updateLoopInterval = null;
      console.log(`[SERVER] ${machineId} stopped update loop`);
    }
  };

  setInterval(async () => {
    if (isLeader) {
      const success = await db.sendLeaderHeartbeat(machineId);
      if (!success) {
        console.log(`[LEADER] ${machineId} heartbeat failed, may lose leadership`);
      }
    }
  }, LEADER_HEARTBEAT_INTERVAL);

  const checkLeadership = async () => {
    let acquired = false;
    try {
      acquired = await db.tryAcquireLeadership(machineId, LEADER_STALE_THRESHOLD);
    } catch (err) {
      console.error(`[LEADER] Error trying to acquire leadership:`, err.message);
      return;
    }

    if (acquired && !isLeader) {
      isLeader = true;
      console.log(`[SERVER] ${machineId} is now the PRIMARY leader`);
      await startUpdateLoop();

      // Start fast avatar sync loop (runs until all avatars are synced)
      startAvatarSyncLoop();

      // Start Discord server list webhook loop
      startDiscordServerListLoop();
    } else if (!acquired && isLeader) {
      isLeader = false;
      console.log(`[SERVER] ${machineId} lost leadership, becoming SECONDARY`);
      stopUpdateLoop();
    } else if (!acquired && !isLeader) {
    }
  };

  await checkLeadership();

  setInterval(checkLeadership, LEADER_CHECK_INTERVAL);

  if (isLeader) {
    console.log(`[SERVER] ${machineId} started as PRIMARY leader`);
  } else {
    console.log(`[SERVER] ${machineId} started as SECONDARY (API only)`);
  }

  const gracefulShutdown = async () => {
    console.log(`[SERVER] ${machineId} shutting down...`);
    if (isLeader) {
      await db.releaseLeadership(machineId);
    }
    process.exit(0);
  };

  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);
});
