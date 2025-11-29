// MXBikes Stats Server - Fly.io Edition
// Replaces Cloudflare Workers + Durable Objects

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import admin from 'firebase-admin';
import { PostgresDatabaseManager } from './database-postgres.js';
import { StateManager } from './state-manager.js';

// Initialize Firebase Admin SDK
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

const app = express();
const PORT = process.env.PORT || 8080;

// Environment variables
const env = {
  DATABASE_URL: process.env.DATABASE_URL,
  MXBIKES_API_URL_1: process.env.MXBIKES_API_URL_1,
  MXBIKES_API_URL_2: process.env.MXBIKES_API_URL_2,
  MXBIKES_API_KEY_1: process.env.MXBIKES_API_KEY_1,
  MXBIKES_API_KEY_2: process.env.MXBIKES_API_KEY_2,
  STEAM_API_KEY: process.env.STEAM_API_KEY,
};

// ========== STEAM UTILITY FUNCTIONS ==========

// Convert MX Bikes GUID to Steam64 ID
// GUID format: FF + Steam64 in hex (e.g., FF011000010BFF56AA)
function guidToSteam64(guid) {
  if (!guid || guid.length !== 18) return null;
  try {
    const steamHex = guid.substring(2); // Remove 'FF' prefix
    return BigInt('0x' + steamHex).toString();
  } catch (e) {
    return null;
  }
}

// Convert Steam64 ID to MX Bikes GUID
function steam64ToGuid(steam64) {
  if (!steam64) return null;
  try {
    const steamHex = BigInt(steam64).toString(16).toUpperCase().padStart(16, '0');
    return 'FF' + steamHex;
  } catch (e) {
    return null;
  }
}

// Fetch Steam profile from Steam Web API
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

// Initialize database and state manager
let db;
let stateManager;

try {
  db = new PostgresDatabaseManager(env.DATABASE_URL);
  await db.initializeTables(); // Create tables if they don't exist
  stateManager = new StateManager(db, env);
  console.log('[INIT] PostgreSQL Database and StateManager initialized');
} catch (err) {
  console.error('[INIT] Failed to initialize:', err.message);
  process.exit(1);
}

// CORS config
const allowedOrigins = ['https://cbrservers.com', 'http://localhost:3000', 'http://localhost:3001', 'http://localhost:5173'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, 'https://cbrservers.com');
    }
  },
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// Root
app.get('/', (req, res) => {
  res.send('MXBikes Stats Server v3 - Fly.io Edition');
});

// ========== API ROUTES ==========

// Get all players
app.get('/api/players', async (req, res) => {
  try {
    const players = await db.getAllPlayers();
    res.json(players);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get recent sessions
app.get('/api/sessions', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const sessions = await db.getRecentSessions(limit);
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Cleanup rotation server data (temporary endpoint)
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
      // Get session IDs
      const sessions = await db.client.execute({
        sql: 'SELECT id FROM sessions WHERE serverName LIKE ?',
        args: [serverPattern]
      });

      for (const row of sessions.rows) {
        const sessionId = row.id;
        // Delete related data
        const ps = await db.client.execute({ sql: 'DELETE FROM player_sessions WHERE sessionId = ?', args: [sessionId] });
        const c = await db.client.execute({ sql: 'DELETE FROM contacts WHERE sessionId = ?', args: [sessionId] });
        const h = await db.client.execute({ sql: 'DELETE FROM holeshots WHERE sessionId = ?', args: [sessionId] });
        results.playerSessions += ps.rowsAffected || 0;
        results.contacts += c.rowsAffected || 0;
        results.holeshots += h.rowsAffected || 0;
      }

      // Delete sessions
      const s = await db.client.execute({
        sql: 'DELETE FROM sessions WHERE serverName LIKE ?',
        args: [serverPattern]
      });
      results.sessions += s.rowsAffected || 0;
    }

    // Clean track records for rotation tracks
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

// Get player sessions (race history)
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

// Get leaderboards
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

// Get track records
app.get('/api/records', async (req, res) => {
  try {
    const records = await db.getAllTrackRecords();
    res.json(records);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get global stats (total races, etc.)
app.get('/api/stats', async (req, res) => {
  try {
    const totalRaces = await db.getTotalFinalizedSessionsCount();
    res.json({ totalRaces });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get servers (cached)
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

// Link/create player profile
app.post('/api/players/link', async (req, res) => {
  try {
    const { playerGuid, displayName } = req.body;

    // Validate GUID format
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

// Player connect (from Manager)
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

// Check PB (from Manager)
app.post('/api/check-pb', async (req, res) => {
  try {
    const { playerGuid, playerName, trackName, lapTime, sessionType, raceNumber, bikeName, serverId } = req.body;

    // Resolve track name - use provided or lookup from server cache
    let resolvedTrackName = trackName;
    if (!resolvedTrackName && serverId) {
      // Try to get track name from serverTracks map (populated during update cycle)
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

// ========== STEAM API ROUTES ==========

// Get Steam profile by Steam64 ID
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

// Get Steam profile by MX Bikes GUID (auto-converts)
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

    // Include the GUID in response for convenience
    res.json({ ...profile, guid: normalizedGuid });
  } catch (err) {
    console.error('[STEAM] Error fetching profile by GUID:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Convert Steam64 to GUID (utility endpoint)
app.get('/api/steam/convert/to-guid/:steamId', (req, res) => {
  const { steamId } = req.params;
  const guid = steam64ToGuid(steamId);

  if (!guid) {
    return res.status(400).json({ error: 'Invalid Steam64 ID' });
  }

  res.json({ steamId, guid });
});

// Convert GUID to Steam64 (utility endpoint)
app.get('/api/steam/convert/to-steam/:guid', (req, res) => {
  const { guid } = req.params;
  const steam64 = guidToSteam64(guid.toUpperCase());

  if (!steam64) {
    return res.status(400).json({ error: 'Invalid GUID' });
  }

  res.json({ guid: guid.toUpperCase(), steamId: steam64 });
});

// Verify Steam OpenID callback and return user data + Firebase custom token
app.post('/api/steam/verify', async (req, res) => {
  try {
    const params = req.body;

    // Verify with Steam
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

    // Extract Steam ID from claimed_id
    const claimedId = params['openid.claimed_id'];
    const steamIdMatch = claimedId?.match(/\/id\/(\d+)$/);
    const steamId = steamIdMatch?.[1];

    if (!steamId) {
      return res.status(400).json({ error: 'Could not extract Steam ID' });
    }

    // Get Steam profile
    const profile = await fetchSteamProfile(steamId);
    if (!profile) {
      return res.status(404).json({ error: 'Steam profile not found' });
    }

    // Convert to GUID
    const guid = steam64ToGuid(steamId);

    // Check if player exists in database
    const existingPlayer = await db.getPlayer(guid);

    // Generate Firebase custom token if Firebase Admin is configured
    let firebaseToken = null;
    let existingFirebaseUser = null;

    if (firebaseAdmin) {
      try {
        // Check if a user already exists with this Steam ID linked in Firestore
        const usersSnapshot = await firebaseAdmin.firestore()
          .collection('users')
          .where('steamId', '==', steamId)
          .limit(1)
          .get();

        let firebaseUid;

        if (!usersSnapshot.empty) {
          // User exists with Steam linked - use their actual UID
          const existingDoc = usersSnapshot.docs[0];
          firebaseUid = existingDoc.id;
          existingFirebaseUser = { id: existingDoc.id, ...existingDoc.data() };
          console.log(`[STEAM] Found existing user ${firebaseUid} with Steam linked`);
        } else {
          // New Steam user - use steam_ prefix
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
        // Continue without token - frontend will handle gracefully
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

// Batch fetch Steam avatars for multiple GUIDs
app.post('/api/steam/avatars', async (req, res) => {
  try {
    const { guids } = req.body;

    if (!Array.isArray(guids) || guids.length === 0) {
      return res.status(400).json({ error: 'guids must be a non-empty array' });
    }

    // Limit to 100 at a time (Steam API limit)
    const limitedGuids = guids.slice(0, 100);

    // Convert GUIDs to Steam64 IDs
    const steam64s = limitedGuids
      .map(guid => ({ guid: guid.toUpperCase(), steam64: guidToSteam64(guid.toUpperCase()) }))
      .filter(item => item.steam64);

    if (steam64s.length === 0) {
      return res.json({ avatars: {} });
    }

    // Fetch all profiles in one API call
    const steamIds = steam64s.map(s => s.steam64).join(',');
    const response = await fetch(
      `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${env.STEAM_API_KEY}&steamids=${steamIds}`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch Steam profiles');
    }

    const data = await response.json();
    const players = data.response?.players || [];

    // Build GUID -> avatar map
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

// ========== REPORTS & BAN APPEALS ==========

const DISCORD_REPORTS_WEBHOOK = process.env.DISCORD_REPORTS_WEBHOOK;
const DISCORD_BAN_APPEALS_WEBHOOK = process.env.DISCORD_BAN_APPEALS_WEBHOOK;

// Submit a player report
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

    // Send to Discord webhook
    if (DISCORD_REPORTS_WEBHOOK) {
      const reasonColors = {
        cheating: 0xFF0000,          // Red
        intentional_crashing: 0xFF8C00, // Orange
        toxic_behavior: 0xFFD700,    // Yellow
        inappropriate_name: 0x9400D3, // Purple
        exploiting: 0x0000FF,        // Blue
        other: 0x808080              // Gray
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

      // Description as its own field at the end
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

// Submit a ban appeal
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

    // Send to Discord webhook
    if (DISCORD_BAN_APPEALS_WEBHOOK) {
      const embed = {
        title: 'New Ban Appeal',
        color: 0xFFA500, // Orange
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

      // Appeal reason as its own field
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

// ========== ADMIN PROXY ROUTES ==========
// These proxy admin actions to C# Manager APIs (avoids CORS issues)

// Get configured API sources
function getApiSources() {
  return [
    { id: 'manager1', url: env.MXBIKES_API_URL_1, key: env.MXBIKES_API_KEY_1 },
    { id: 'manager2', url: env.MXBIKES_API_URL_2, key: env.MXBIKES_API_KEY_2 }
  ].filter(s => s.url && s.key);
}

// Helper to make request to a single manager
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

// Helper to make requests to first successful manager (for server-specific actions)
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

// Helper to execute action on ALL managers (for global actions like unban)
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

// Get ALL bans from BOTH managers, combined and deduplicated
app.get('/api/admin/bans', async (req, res) => {
  try {
    const sources = getApiSources();
    const allBansMap = new Map(); // Use playerGuid as key for deduplication
    const errors = [];

    // First get all servers from cache
    let serverData = stateManager.getCachedServerData();
    if (!serverData) {
      serverData = await stateManager.fetchServersFromAPI();
    }
    const servers = serverData?.servers || [];

    // Fetch bans from each manager's servers
    await Promise.all(sources.map(async (source) => {
      // Get servers for this manager
      try {
        const managerServersResp = await fetchFromManager(source, '/servers');
        const managerServers = Array.isArray(managerServersResp) ? managerServersResp : [];

        // Fetch bans from each server on this manager
        for (const server of managerServers) {
          const serverId = server.id || server.Id;
          try {
            const bans = await fetchFromManager(source, `/servers/${serverId}/bans`);
            if (Array.isArray(bans)) {
              for (const ban of bans) {
                const guid = (ban.playerGuid || ban.PlayerGuid || '').toUpperCase();
                if (!guid) continue;

                // Normalize ban data
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

                // Keep the most recent ban for each player (by bannedAt)
                const existing = allBansMap.get(guid);
                if (!existing) {
                  allBansMap.set(guid, normalizedBan);
                } else {
                  const existingDate = new Date(existing.bannedAt || 0);
                  const newDate = new Date(normalizedBan.bannedAt || 0);
                  if (newDate > existingDate) {
                    // Mark as banned on both managers if we found them on both
                    normalizedBan.onBothManagers = existing.sourceManager !== source.id;
                    allBansMap.set(guid, normalizedBan);
                  } else if (existing.sourceManager !== source.id) {
                    existing.onBothManagers = true;
                  }
                }
              }
            }
          } catch (banErr) {
            // Server might not have bans endpoint or be offline
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

// Get bans for a specific server (tries both managers)
app.get('/api/admin/servers/:serverId/bans', async (req, res) => {
  try {
    const { serverId } = req.params;
    const sources = getApiSources();

    // Try each source until one succeeds
    for (const source of sources) {
      try {
        const bans = await fetchFromManager(source, `/servers/${serverId}/bans`);
        return res.json(bans);
      } catch (err) {
        // Try next source
      }
    }

    // If no source succeeded, return empty array
    res.json([]);
  } catch (err) {
    console.error('[ADMIN] Get bans error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Ban a player on ALL managers (global ban)
app.post('/api/admin/ban', async (req, res) => {
  try {
    const banData = req.body;
    const sources = getApiSources();
    const results = [];
    const errors = [];

    // Get servers from each manager and ban on first available server
    for (const source of sources) {
      try {
        const serversResp = await fetchFromManager(source, '/servers');
        const servers = Array.isArray(serversResp) ? serversResp : [];
        if (servers.length > 0) {
          const firstServer = servers[0];
          const serverId = firstServer.id || firstServer.Id;
          const result = await fetchFromManager(source, `/servers/${serverId}/ban`, 'POST', {
            ...banData,
            isGlobal: true // Force global ban
          });
          results.push({ source: source.id, result });
        }
      } catch (err) {
        errors.push({ source: source.id, error: err.message });
      }
    }

    console.log(`[ADMIN] Banned player ${banData.playerName} on ${results.length} managers`);
    res.json({ success: results.length > 0, results, errors });
  } catch (err) {
    console.error('[ADMIN] Global ban error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Ban a player on a specific server
app.post('/api/admin/servers/:serverId/ban', async (req, res) => {
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

// Unban a player from ALL managers (global unban)
app.post('/api/admin/unban', async (req, res) => {
  try {
    const { playerGuid } = req.body;
    const sources = getApiSources();
    const results = [];
    const errors = [];

    // Get servers from each manager and unban on all of them
    for (const source of sources) {
      try {
        const serversResp = await fetchFromManager(source, '/servers');
        const servers = Array.isArray(serversResp) ? serversResp : [];

        // Unban on first server (global unbans affect all servers on that manager)
        if (servers.length > 0) {
          const firstServer = servers[0];
          const serverId = firstServer.id || firstServer.Id;
          try {
            const result = await fetchFromManager(source, `/servers/${serverId}/unban`, 'POST', { playerGuid });
            results.push({ source: source.id, result });
          } catch (err) {
            errors.push({ source: source.id, error: err.message });
          }
        }
      } catch (err) {
        errors.push({ source: source.id, error: err.message });
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

// Unban a player from a specific server
app.post('/api/admin/servers/:serverId/unban', async (req, res) => {
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

// Kick a player
app.post('/api/admin/servers/:serverId/kick', async (req, res) => {
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

// Start server
app.post('/api/admin/servers/:serverId/start', async (req, res) => {
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

// Stop server
app.post('/api/admin/servers/:serverId/stop', async (req, res) => {
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

// Restart server
app.post('/api/admin/servers/:serverId/restart', async (req, res) => {
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

// Send public message to server
app.post('/api/admin/servers/:serverId/message', async (req, res) => {
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

// Update server config
app.post('/api/admin/servers/:serverId/config', async (req, res) => {
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

// Delete server
app.delete('/api/admin/servers/:serverId', async (req, res) => {
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

// Create new server
app.post('/api/admin/servers', async (req, res) => {
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

// ========== START SERVER ==========

const LEADER_HEARTBEAT_INTERVAL = 5000;  // Send heartbeat every 5 seconds
const LEADER_STALE_THRESHOLD = 15000;    // Consider leader stale after 15 seconds
const LEADER_CHECK_INTERVAL = 3000;      // Check for leadership every 3 seconds

app.listen(PORT, async () => {
  console.log(`[SERVER] MXBikes Stats Server running on port ${PORT}`);
  console.log(`[SERVER] PostgreSQL connected`);

  const machineId = process.env.FLY_MACHINE_ID || 'local';
  console.log(`[SERVER] Machine ID: ${machineId}`);

  // Initialize leader election table
  await db.initLeaderTable();

  let isLeader = false;
  let updateLoopInterval = null;
  let cycleRunning = false;
  let cycleStartTime = 0;
  let consecutiveSkips = 0;
  const MAX_CYCLE_TIME = 20000; // Force reset if cycle runs longer than 20s (reduced from 25s)
  const MAX_CONSECUTIVE_SKIPS = 8; // Force reset after 8 skips (~16 seconds)

  // Function to start the update loop when becoming leader
  const startUpdateLoop = async () => {
    if (updateLoopInterval) return; // Already running

    console.log(`[SERVER] ${machineId} starting PRIMARY update loop`);

    // Recover state from database before starting
    await stateManager.recoverStateFromDatabase();

    updateLoopInterval = setInterval(async () => {
      // SAFETY CHECK: Force reset if cycle has been running too long
      if (cycleRunning) {
        const cycleAge = Date.now() - cycleStartTime;
        consecutiveSkips++;

        if (cycleAge > MAX_CYCLE_TIME || consecutiveSkips >= MAX_CONSECUTIVE_SKIPS) {
          console.error(`[UPDATE LOOP] FORCE RESET - cycle stuck for ${cycleAge}ms (${consecutiveSkips} skips)`);

          // Abort the current cycle via its AbortController
          if (stateManager.currentAbortController) {
            console.log('[UPDATE LOOP] Aborting stuck cycle via AbortController');
            stateManager.currentAbortController.abort();
          }

          cycleRunning = false;
          consecutiveSkips = 0;
          // Don't return - let it start a new cycle immediately
        } else {
          console.log(`[UPDATE LOOP] Skipping - previous cycle running (${Math.round(cycleAge/1000)}s, skip #${consecutiveSkips})`);
          return;
        }
      }

      // Verify we're still the leader before running
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
        // Continue anyway - don't stop loop on transient DB errors
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
    }, 5000); // 5 second interval for responsive live timing
  };

  // Function to stop the update loop when losing leadership
  const stopUpdateLoop = () => {
    if (updateLoopInterval) {
      clearInterval(updateLoopInterval);
      updateLoopInterval = null;
      console.log(`[SERVER] ${machineId} stopped update loop`);
    }
  };

  // Leader heartbeat - keep leadership alive
  setInterval(async () => {
    if (isLeader) {
      const success = await db.sendLeaderHeartbeat(machineId);
      if (!success) {
        console.log(`[LEADER] ${machineId} heartbeat failed, may lose leadership`);
      }
    }
  }, LEADER_HEARTBEAT_INTERVAL);

  // Leadership election check - try to become leader if not already
  const checkLeadership = async () => {
    let acquired = false;
    try {
      acquired = await db.tryAcquireLeadership(machineId, LEADER_STALE_THRESHOLD);
    } catch (err) {
      console.error(`[LEADER] Error trying to acquire leadership:`, err.message);
      // Continue with acquired = false, will retry on next interval
      return;
    }

    if (acquired && !isLeader) {
      // Just became the leader
      isLeader = true;
      console.log(`[SERVER] ${machineId} is now the PRIMARY leader`);
      await startUpdateLoop();
    } else if (!acquired && isLeader) {
      // Lost leadership
      isLeader = false;
      console.log(`[SERVER] ${machineId} lost leadership, becoming SECONDARY`);
      stopUpdateLoop();
    } else if (!acquired && !isLeader) {
      // Still not the leader
      // Only log occasionally to avoid spam
    }
  };

  // Initial leadership check
  await checkLeadership();

  // Periodic leadership check (for failover)
  setInterval(checkLeadership, LEADER_CHECK_INTERVAL);

  // Log initial state
  if (isLeader) {
    console.log(`[SERVER] ${machineId} started as PRIMARY leader`);
  } else {
    console.log(`[SERVER] ${machineId} started as SECONDARY (API only)`);
  }

  // Graceful shutdown - release leadership
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
