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

const ADMIN_ROLES = ['admin', 'superadmin'];
const MODERATOR_ROLES = ['moderator', 'admin', 'superadmin'];

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
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
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
  res.send('MXBikes Stats Server v3 - Fly.io Edition');
});

app.get('/api/bulk', async (req, res) => {
  try {
    const [players, sessions, servers, leaderboardMMR, leaderboardSR, records, stats] = await Promise.all([
      db.getAllPlayers(),
      db.getRecentSessions(50),
      Promise.resolve(stateManager.getCachedServerData()),
      db.getTopPlayersByMMR(100),
      db.getTopPlayersBySR(100),
      db.getAllTrackRecords(),
      db.getTotalFinalizedSessionsCount().then(count => ({ totalRaces: count }))
    ]);
    res.json({
      players,
      sessions,
      servers,
      leaderboards: { mmr: leaderboardMMR, sr: leaderboardSR },
      records,
      stats
    });
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

app.get('/api/stats', async (req, res) => {
  try {
    const totalRaces = await db.getTotalFinalizedSessionsCount();
    res.json({ totalRaces });
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
    const { playerGuid, playerName, trackName, lapTime, sessionType, raceNumber, bikeName, serverId } = req.body;

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
      bikeName: bikeName || null
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

app.post('/api/steam/avatars', async (req, res) => {
  try {
    const { guids } = req.body;

    if (!Array.isArray(guids) || guids.length === 0) {
      return res.status(400).json({ error: 'guids must be a non-empty array' });
    }

    const limitedGuids = guids.slice(0, 100);

    const steam64s = limitedGuids
      .map(guid => ({ guid: guid.toUpperCase(), steam64: guidToSteam64(guid.toUpperCase()) }))
      .filter(item => item.steam64);

    if (steam64s.length === 0) {
      return res.json({ avatars: {} });
    }

    const steamIds = steam64s.map(s => s.steam64).join(',');
    const response = await fetch(
      `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${env.STEAM_API_KEY}&steamids=${steamIds}`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch Steam profiles');
    }

    const data = await response.json();
    const players = data.response?.players || [];

    const avatars = {};
    for (const player of players) {
      const guid = steam64ToGuid(player.steamid);
      if (guid) {
        avatars[guid] = {
          avatar: player.avatar,
          avatarMedium: player.avatarmedium,
          avatarFull: player.avatarfull,
          displayName: player.personaname
        };
      }
    }

    res.json({ avatars });
  } catch (err) {
    console.error('[STEAM] Batch avatars error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const DISCORD_REPORTS_WEBHOOK = process.env.DISCORD_REPORTS_WEBHOOK;
const DISCORD_BAN_APPEALS_WEBHOOK = process.env.DISCORD_BAN_APPEALS_WEBHOOK;

app.post('/api/reports', async (req, res) => {
  try {
    const {
      reporterName,
      reporterGuid,
      offenderName,
      offenderGuid,
      serverName,
      reason,
      reasonLabel,
      description,
      videoUrl,
      discordUsername,
      timestamp
    } = req.body;

    if (!reporterName || !offenderName || !reason || !description) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (DISCORD_REPORTS_WEBHOOK) {
      const reasonColors = {
        cheating: 0xFF0000,
        intentional_crashing: 0xFF8C00,
        toxic_behavior: 0xFFD700,
        inappropriate_name: 0x9400D3,
        exploiting: 0x0000FF,
        other: 0x808080
      };

      const embed = {
        title: 'New Player Report',
        color: reasonColors[reason] || 0xFF0000,
        fields: [
          { name: 'Reporter', value: reporterName, inline: true },
          { name: 'Offender', value: offenderName, inline: true },
          { name: 'Reason', value: reasonLabel || reason, inline: true }
        ],
        timestamp: timestamp || new Date().toISOString(),
        footer: { text: 'CBR Report System' }
      };

      if (serverName) {
        embed.fields.push({ name: 'Server', value: serverName, inline: true });
      }
      if (discordUsername) {
        embed.fields.push({ name: 'Discord', value: discordUsername, inline: true });
      }

      embed.fields.push({ name: 'Description', value: description.slice(0, 1024) });

      if (videoUrl) {
        embed.fields.push({ name: 'Video Evidence', value: videoUrl });
      }
      if (offenderGuid) {
        embed.fields.push({ name: 'Offender GUID', value: `\`${offenderGuid}\`` });
      }
      if (reporterGuid) {
        embed.fields.push({ name: 'Reporter GUID', value: `\`${reporterGuid}\`` });
      }

      try {
        await fetch(DISCORD_REPORTS_WEBHOOK, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ embeds: [embed] })
        });
      } catch (webhookErr) {
        console.error('[REPORT] Discord webhook failed:', webhookErr.message);
      }
    }

    console.log(`[REPORT] ${reporterName} reported ${offenderName} for ${reasonLabel}`);
    res.json({ success: true, message: 'Report submitted successfully' });

  } catch (err) {
    console.error('[REPORT] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ban-appeals', async (req, res) => {
  try {
    const {
      playerName,
      playerGuid,
      serverName,
      banReason,
      banReasonLabel,
      banDate,
      appealReason,
      additionalInfo,
      discordUsername,
      userId,
      timestamp
    } = req.body;

    if (!playerName || !playerGuid || !banReason || !appealReason) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (DISCORD_BAN_APPEALS_WEBHOOK) {
      const embed = {
        title: 'New Ban Appeal',
        color: 0xFFA500,
        fields: [
          { name: 'Player Name', value: playerName, inline: true },
          { name: 'Player GUID', value: `\`${playerGuid}\``, inline: true },
          { name: 'Ban Reason', value: banReasonLabel || banReason, inline: true }
        ],
        timestamp: timestamp || new Date().toISOString(),
        footer: { text: 'CBR Ban Appeals' }
      };

      if (serverName) {
        embed.fields.push({ name: 'Server', value: serverName, inline: true });
      }
      if (banDate) {
        embed.fields.push({ name: 'Ban Date', value: banDate, inline: true });
      }
      if (discordUsername) {
        embed.fields.push({ name: 'Discord', value: discordUsername, inline: true });
      }

      embed.fields.push({ name: 'Appeal', value: appealReason.slice(0, 1024) });

      if (additionalInfo) {
        embed.fields.push({ name: 'Additional Info', value: additionalInfo.slice(0, 1024) });
      }

      try {
        await fetch(DISCORD_BAN_APPEALS_WEBHOOK, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ embeds: [embed] })
        });
      } catch (webhookErr) {
        console.error('[BAN-APPEAL] Discord webhook failed:', webhookErr.message);
      }
    }

    console.log(`[BAN-APPEAL] ${playerName} (${playerGuid}) appealing ban for ${banReasonLabel}`);
    res.json({ success: true, message: 'Ban appeal submitted successfully' });

  } catch (err) {
    console.error('[BAN-APPEAL] Error:', err.message);
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
                banInfo = {
                  isBanned: true,
                  playerGuid: upperGuid,
                  playerName: playerBan.playerName || playerBan.PlayerName || 'Unknown',
                  reason: playerBan.reason || playerBan.Reason || 'No reason provided',
                  bannedAt: playerBan.bannedAt || playerBan.BannedAt,
                  expiresAt: playerBan.expiresAt || playerBan.ExpiresAt || null,
                  bannedBy: playerBan.bannedBy || playerBan.BannedBy || 'Admin',
                  durationDescription: playerBan.durationDescription || playerBan.DurationDescription || null,
                  isActive: playerBan.isActive ?? playerBan.IsActive ?? true
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

    res.json(banInfo || { isBanned: false });
  } catch (err) {
    console.error('[BAN-CHECK] Error:', err.message);
    res.json({ isBanned: false });
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
          try {
            result = await fetchFromManager(source, `/servers/${serverId}/full-ban`, 'POST', {
              ...banData,
              isGlobal: true
            });
            console.log(`[ADMIN] Ban succeeded via full-ban on ${source.id}`);
          } catch (fullBanErr) {
            console.log(`[ADMIN] full-ban failed on ${source.id}: ${fullBanErr.message}, trying ban endpoint`);
            usedEndpoint = 'ban';
            result = await fetchFromManager(source, `/servers/${serverId}/ban`, 'POST', {
              ...banData,
              isGlobal: true
            });
            console.log(`[ADMIN] Ban succeeded via ban on ${source.id}`);
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
          performedBy: req.user?.email || 'Admin',
          sourceManager: results.map(r => r.source).join(',')
        });
      } catch (histErr) {
        console.error('[ADMIN] Failed to store ban history:', histErr.message);
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
    const result = await proxyToManager(`/servers/${serverId}/ban`, 'POST', banData);
    console.log(`[ADMIN] Banned player ${banData.playerName} on server ${serverId}`);
    res.json(result);
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
    const { message } = req.body;
    const result = await proxyToManager(`/servers/${serverId}/message`, 'POST', { message });
    console.log(`[ADMIN] Sent message to server ${serverId}: ${message}`);
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
    const result = await proxyToManager(`/servers/${serverId}`, 'DELETE');
    console.log(`[ADMIN] Deleted server ${serverId}`);
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

const LEADER_HEARTBEAT_INTERVAL = 5000;
const LEADER_STALE_THRESHOLD = 15000;
const LEADER_CHECK_INTERVAL = 3000;

app.listen(PORT, async () => {
  console.log(`[SERVER] MXBikes Stats Server running on port ${PORT}`);
  console.log(`[SERVER] PostgreSQL connected`);

  const machineId = process.env.FLY_MACHINE_ID || 'local';
  console.log(`[SERVER] Machine ID: ${machineId}`);

  await db.initLeaderTable();

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
