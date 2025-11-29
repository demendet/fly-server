// State Manager - Replaces Cloudflare Durable Object
// Uses in-memory Maps/Sets with the same logic

import { setMaxListeners } from 'events';

export class StateManager {
  constructor(db, env) {
    this.db = db;
    this.env = env;

    // In-memory state (same as Durable Object)
    this.previousServerStates = new Map();
    this.serverSessions = new Map();
    this.serverSessionPhases = new Map();
    this.mmrSentSessions = new Set();
    this.serverToApiMap = new Map();

    // Write optimization caches
    this.cachedPlayerStates = new Map();
    this.insertedHoleshots = new Map();
    this.insertedContacts = new Map();
    this.cachedWarmupStates = new Map();

    // Server ID -> Track name mapping for PB lookups
    this.serverTracks = new Map();

    this.LASTSEEN_UPDATE_INTERVAL = 60000;
    this.cachedServerData = null;
    this.lastServerDataFetch = 0;
    this.alarmCounter = 0;
  }

  // Recover state from database on startup (handles Fly.io restarts)
  async recoverStateFromDatabase() {
    try {
      const activeSessions = await this.db.getActiveSessions();

      if (activeSessions.length === 0) {
        console.log('[RECOVERY] No active sessions to recover');
        return;
      }

      for (const session of activeSessions) {
        // Rebuild serverSessions map
        this.serverSessions.set(session.serverId, session.id);

        // Rebuild serverSessionPhases map
        if (session.currentSessionPhase) {
          this.serverSessionPhases.set(session.serverId, session.currentSessionPhase);
        }

        // Rebuild previousServerStates map
        if (session.sessionState) {
          this.previousServerStates.set(session.serverId, session.sessionState);
        }

        // If raceResults exist, MMR was already sent - add to mmrSentSessions
        if (session.raceResults && session.raceResults.length > 0) {
          this.mmrSentSessions.add(session.id);
        }
      }

      console.log(`[RECOVERY] Recovered ${activeSessions.length} active sessions, ${this.mmrSentSessions.size} with MMR already sent`);
    } catch (err) {
      console.error('[RECOVERY] Error recovering state:', err.message);
      // Non-fatal - continue without recovery
    }
  }

  // Get track name for a server ID (used by PB endpoint)
  getTrackForServer(serverId) {
    return this.serverTracks.get(serverId) || null;
  }

  // Main update loop (replaces Durable Object alarm)
  async runUpdateCycle() {
    this.alarmCounter++;
    const cycleId = this.alarmCounter;
    const cycleStart = Date.now();

    // Track active cycle to detect overlaps
    if (this.activeCycleId && this.activeCycleId !== cycleId) {
      console.warn(`[Update] Cycle #${cycleId} starting while #${this.activeCycleId} still active - overlap detected!`);
    }
    this.activeCycleId = cycleId;

    // Use AbortController for proper cancellation
    const abortController = new AbortController();
    this.currentAbortController = abortController; // Store for external access

    // Increase max listeners to prevent warnings with many parallel fetches
    try {
      setMaxListeners(50, abortController.signal);
    } catch (e) {
      // Ignore if setMaxListeners doesn't work (shouldn't happen in Node)
    }

    const timeoutId = setTimeout(() => {
      console.error(`[Update] TIMEOUT after 30s - aborting cycle #${cycleId}`);
      abortController.abort();
    }, 30000); // 30 second timeout (increased to allow database operations to complete)

    try {
      await this._runUpdateCycleInternal(abortController.signal, cycleId);
    } catch (error) {
      if (error.name === 'AbortError') {
        console.error(`[Update] Cycle #${cycleId} aborted after ${Date.now() - cycleStart}ms`);
      } else {
        console.error(`[Update] Error after ${Date.now() - cycleStart}ms:`, error.message);
      }
    } finally {
      clearTimeout(timeoutId);
      if (this.activeCycleId === cycleId) {
        this.activeCycleId = null;
      }
      this.currentAbortController = null;
    }
  }

  async _runUpdateCycleInternal(abortSignal, cycleId) {
    // Helper to check abort and throw if needed
    const checkAbort = () => {
      if (abortSignal?.aborted) {
        throw new DOMException('Aborted', 'AbortError');
      }
    };

    try {
      checkAbort();

      const serverData = await this.fetchServersFromAPI(abortSignal);
      if (!serverData || !serverData.servers) {
        console.log('[Update] No server data received, skipping cycle');
        return;
      }

      checkAbort();

      const { onlinePlayers } = serverData;
      const now = Date.now();

      // Update players (only when changed) - CHUNKED to allow abort between chunks
      if (onlinePlayers && onlinePlayers.length > 0) {
        const playersToUpdate = [];

        for (const player of onlinePlayers) {
          const guid = player.guid.toUpperCase();
          const cached = this.cachedPlayerStates.get(guid);

          const currentState = {
            server: player.currentServer,
            track: player.currentTrack,
            bike: player.bikeName,
            raceNum: player.raceNumber,
            name: player.displayName
          };

          const hasChanges = !cached ||
            cached.server !== currentState.server ||
            cached.track !== currentState.track ||
            cached.bike !== currentState.bike ||
            cached.raceNum !== currentState.raceNum ||
            cached.name !== currentState.name;

          const shouldUpdateLastSeen = !cached || !cached.lastSeenUpdate ||
            (now - cached.lastSeenUpdate) >= this.LASTSEEN_UPDATE_INTERVAL;

          if (hasChanges || shouldUpdateLastSeen) {
            playersToUpdate.push({
              guid,
              displayName: player.displayName,
              currentServer: player.currentServer,
              currentTrack: player.currentTrack,
              raceNumber: player.raceNumber,
              bikeName: player.bikeName,
              lastSeen: now,
              autoGenerated: true
            });

            this.cachedPlayerStates.set(guid, {
              ...currentState,
              lastSeenUpdate: shouldUpdateLastSeen ? now : cached?.lastSeenUpdate
            });
          }
        }

        // Process in chunks of 25 to allow abort checks between database calls
        const CHUNK_SIZE = 25;
        let totalUpdated = 0;
        for (let i = 0; i < playersToUpdate.length; i += CHUNK_SIZE) {
          checkAbort(); // Check abort BEFORE each chunk
          const chunk = playersToUpdate.slice(i, i + CHUNK_SIZE);
          await this.db.batchUpsertPlayers(chunk);
          totalUpdated += chunk.length;
        }
        if (totalUpdated > 0) {
          console.log(`[UPDATE] Updated ${totalUpdated}/${onlinePlayers.length} players`);
        }
      }

      checkAbort();

      // Process session updates (pass abort signal through)
      await this.processServerUpdates(serverData, abortSignal);

      console.log(`[Cycle #${cycleId}] ${serverData.servers.length} servers, ${this.serverSessions.size} sessions, ${onlinePlayers?.length || 0} online`);
    } catch (error) {
      if (error.name === 'AbortError') throw error; // Re-throw abort errors
      console.error('[Update] Internal error:', error.message);
    }
  }

  async fetchServersFromAPI(abortSignal) {
    // Helper to add timeout to any promise
    const withTimeout = (promise, timeoutMs, fallback = null) => {
      return Promise.race([
        promise,
        new Promise((resolve) =>
          setTimeout(() => resolve(fallback), timeoutMs)
        )
      ]);
    };

    // Helper to fetch with timeout (including json parsing)
    // Links to parent abortSignal so parent timeout kills child fetches
    const fetchJsonWithTimeout = async (url, options, timeoutMs = 5000) => {
      try {
        // Check parent abort signal before starting
        if (abortSignal?.aborted) return null;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        // Link to parent - if parent aborts, abort this fetch too
        // Use { once: true } to auto-cleanup listener
        let abortHandler = null;
        if (abortSignal) {
          abortHandler = () => controller.abort();
          abortSignal.addEventListener('abort', abortHandler, { once: true });
        }

        try {
          const response = await fetch(url, { ...options, signal: controller.signal });
          clearTimeout(timeoutId);

          if (!response.ok) return null;

          // Also timeout the json parsing
          const json = await withTimeout(response.json(), 3000, null);
          return json;
        } finally {
          // Clean up resources
          clearTimeout(timeoutId);
          if (abortSignal && abortHandler && !abortSignal.aborted) {
            abortSignal.removeEventListener('abort', abortHandler);
          }
        }
      } catch (err) {
        // Check if this was due to parent abort
        if (abortSignal?.aborted) {
          throw new DOMException('Aborted', 'AbortError');
        }
        return null;
      }
    };

    const [servers1, servers2] = await Promise.all([
      fetchJsonWithTimeout(`${this.env.MXBIKES_API_URL_1}/servers`, {
        headers: { 'X-API-Key': this.env.MXBIKES_API_KEY_1 },
      }, 10000), // Increased from 3s to 10s to handle network latency
      fetchJsonWithTimeout(`${this.env.MXBIKES_API_URL_2}/servers`, {
        headers: { 'X-API-Key': this.env.MXBIKES_API_KEY_2 },
      }, 10000), // Increased from 3s to 10s to handle network latency
    ]);

    // Deduplicate servers by ID (same server might appear in both APIs)
    const serverMap = new Map();
    let api1Count = 0, api2Count = 0, duplicateCount = 0;
    (servers1 || []).forEach(s => {
      serverMap.set(s.id, { server: s, source: 1 });
      api1Count++;
    });
    (servers2 || []).forEach(s => {
      if (!serverMap.has(s.id)) {
        serverMap.set(s.id, { server: s, source: 2 });
        api2Count++;
      } else {
        duplicateCount++;
      }
    });
    const allServers = Array.from(serverMap.values()).map(v => v.server);

    // Log only occasionally (every 50 cycles) to reduce spam
    if (this.alarmCounter % 50 === 1) {
      console.log(`[API-SOURCES] API1: ${api1Count}, API2: ${api2Count}, Duplicates: ${duplicateCount}, Total: ${allServers.length}`);
    }

    // Fetch detailed server info with proper timeouts
    const detailedPromises = allServers.map(server => {
      const apiSource = serverMap.get(server.id)?.source || 1;
      const apiUrl = apiSource === 1 ? this.env.MXBIKES_API_URL_1 : this.env.MXBIKES_API_URL_2;
      const apiKey = apiSource === 1 ? this.env.MXBIKES_API_KEY_1 : this.env.MXBIKES_API_KEY_2;

      this.serverToApiMap.set(server.id, apiSource);

      return fetchJsonWithTimeout(`${apiUrl}/servers/${server.id}`, {
        headers: { 'X-API-Key': apiKey },
      }, 2500);
    });

    const detailedResults = await Promise.all(detailedPromises);

    const servers = allServers.map((server, idx) => {
      const detailed = detailedResults[idx];
      if (detailed) {
        server.session = detailed.session || null;
        server.riders = detailed.riders || [];
        server.session_state = detailed.session?.session_state;
        server.session_type = detailed.session?.session_type;
      }
      return server;
    });

    // Update server ID -> track name mapping for PB lookups
    servers.forEach(server => {
      const trackName = server.session?.track_name || '';
      if (server.id && trackName) {
        this.serverTracks.set(server.id, trackName);
      }
    });

    const playersMap = new Map();
    servers.forEach(server => {
      (server.riders || []).forEach(rider => {
        if (rider?.guid && !playersMap.has(rider.guid)) {
          playersMap.set(rider.guid, {
            guid: rider.guid,
            displayName: rider.name,
            currentServer: server.name,
            currentTrack: server.session?.track_name || '',
            raceNumber: rider.race_number,
            bikeName: rider.bike,
            bestLapTime: rider.best_lap?.time || rider.best_lap_time || 0
          });
        }
      });
    });

    this.cachedServerData = {
      servers,
      totalServers: allServers.length,
      activeServers: servers.length,
      activePlayersCount: playersMap.size,
      onlinePlayers: Array.from(playersMap.values())
    };
    this.lastServerDataFetch = Date.now();

    return this.cachedServerData;
  }

  getCachedServerData() {
    if (this.cachedServerData && (Date.now() - this.lastServerDataFetch) < 5000) {
      return this.cachedServerData;
    }
    return null;
  }

  async processServerUpdates(serverData, abortSignal) {
    const { servers } = serverData;

    // Helper to check abort
    const checkAbort = () => {
      if (abortSignal?.aborted) {
        throw new DOMException('Aborted', 'AbortError');
      }
    };

    const warmupUpdates = [];
    const contactsToInsert = [];
    const holeshotsToInsert = [];

    for (const server of servers) {
      const sessionId = this.serverSessions.get(server.id);
      const currentState = server.session_state || 'UNKNOWN';
      const currentPhase = (server.session_type || '').toLowerCase();
      const isWarmup = currentPhase.includes('warmup') || currentPhase.includes('practice');

      if (sessionId && currentState === 'INPROGRESS' && isWarmup) {
        const riders = server.riders || [];
        if (riders.length > 0) {
          const warmupResults = riders
            .filter(r => r.best_lap_time > 0 || r.best_lap?.time > 0)
            .sort((a, b) => (a.best_lap?.time || a.best_lap_time || 999) - (b.best_lap?.time || b.best_lap_time || 999))
            .map((r, idx, arr) => {
              const bestTime = r.best_lap?.time || r.best_lap_time || 0;
              const leaderTime = arr[0]?.best_lap?.time || arr[0]?.best_lap_time || 0;
              const gap = idx > 0 ? bestTime - leaderTime : 0;

              return {
                playerGuid: r.guid.toUpperCase(),
                playerName: r.name,
                position: idx + 1,
                bestLapTime: bestTime,
                totalLaps: r.total_laps || 0,
                raceNumber: r.race_number,
                bikeName: r.bike_name || r.bike_short_name || '',
                gap,
                driverStatus: r.driver_status || null,
                driverStatusReason: r.driver_status_reason || null,
                holeshotTime: r.holeshot_time || null,
                penalties: r.penalties || []
              };
            });

          // Check if warmup results changed
          let hasChanges = false;
          const cachedWarmup = this.cachedWarmupStates.get(sessionId);

          if (!cachedWarmup || cachedWarmup.size !== warmupResults.length) {
            hasChanges = true;
          } else {
            for (const result of warmupResults) {
              const cached = cachedWarmup.get(result.playerGuid);
              if (!cached ||
                  cached.pos !== result.position ||
                  cached.time !== result.bestLapTime ||
                  cached.laps !== result.totalLaps) {
                hasChanges = true;
                break;
              }
            }
          }

          if (hasChanges) {
            warmupUpdates.push({
              sessionId,
              updates: { warmupResults, totalEntries: warmupResults.length },
              riderCount: warmupResults.length
            });

            const newCache = new Map();
            warmupResults.forEach(r => {
              newCache.set(r.playerGuid, { pos: r.position, time: r.bestLapTime, laps: r.totalLaps });
            });
            this.cachedWarmupStates.set(sessionId, newCache);
          }

          // Collect contacts
          for (const rider of riders) {
            if (rider.contacts && rider.contacts.length > 0) {
              if (!this.insertedContacts.has(sessionId)) {
                this.insertedContacts.set(sessionId, new Set());
              }
              const insertedContacts = this.insertedContacts.get(sessionId);

              for (const contact of rider.contacts) {
                const contactId = `${contact.time}_${contact.race_number_1}_${contact.race_number_2}`;
                if (!insertedContacts.has(contactId)) {
                  contactsToInsert.push({
                    sessionId,
                    time: contact.time,
                    playerGuid1: rider.guid?.toUpperCase(),
                    playerName1: rider.name,
                    raceNumber1: contact.race_number_1,
                    playerGuid2: null,
                    playerName2: null,
                    raceNumber2: contact.race_number_2,
                    relativeImpactVelocity: contact.relative_impact_velocity
                  });
                  insertedContacts.add(contactId);
                }
              }
            }

            // Collect holeshots
            if (rider.holeshot_time && rider.holeshot_time > 0) {
              if (!this.insertedHoleshots.has(sessionId)) {
                this.insertedHoleshots.set(sessionId, new Set());
              }
              const insertedHoleshots = this.insertedHoleshots.get(sessionId);
              const playerGuid = rider.guid?.toUpperCase();

              if (!insertedHoleshots.has(playerGuid)) {
                holeshotsToInsert.push({
                  sessionId,
                  playerGuid,
                  playerName: rider.name,
                  raceNumber: rider.race_number,
                  holeshotTime: rider.holeshot_time,
                  trackName: server.session?.track_name || ''
                });
                insertedHoleshots.add(playerGuid);
              }
            }
          }
        }
      }
    }

    // Batch updates (check abort before each) - CHUNKED for quick abort
    const BATCH_CHUNK = 10;

    // Warmup updates in chunks
    for (let i = 0; i < warmupUpdates.length; i += BATCH_CHUNK) {
      checkAbort();
      await this.db.batchUpdateSessions(warmupUpdates.slice(i, i + BATCH_CHUNK));
    }

    // Contacts in chunks
    for (let i = 0; i < contactsToInsert.length; i += BATCH_CHUNK) {
      checkAbort();
      await this.db.batchInsertContacts(contactsToInsert.slice(i, i + BATCH_CHUNK));
    }

    // Holeshots in chunks
    for (let i = 0; i < holeshotsToInsert.length; i += BATCH_CHUNK) {
      checkAbort();
      await this.db.batchInsertHoleshots(holeshotsToInsert.slice(i, i + BATCH_CHUNK));
    }

    checkAbort();

    // Handle state changes
    const processedServers = new Set();
    for (const server of servers) {
      // Check abort before each server to allow quick exit
      checkAbort();

      // Check for duplicate servers in same cycle
      if (processedServers.has(server.id)) {
        console.log(`[DUPLICATE] Server ${server.name} (${server.id}) appears multiple times in servers array!`);
        continue;
      }
      processedServers.add(server.id);

      const currentState = server.session_state || 'UNKNOWN';
      const currentPhase = (server.session_type || '').toLowerCase();
      const previousState = this.previousServerStates.get(server.id) || 'UNKNOWN';
      const previousPhase = this.serverSessionPhases.get(server.id) || '';

      if (currentState !== previousState || (currentPhase !== previousPhase && currentState === 'INPROGRESS')) {
        await this.handleSessionStateChange(server, previousState, currentState, previousPhase, currentPhase, abortSignal);
        this.previousServerStates.set(server.id, currentState);
        this.serverSessionPhases.set(server.id, currentPhase);
      }
    }
  }

  async handleSessionStateChange(server, previousState, currentState, previousPhase, currentPhase, abortSignal) {
    // Helper to check abort
    const checkAbort = () => {
      if (abortSignal?.aborted) {
        throw new DOMException('Aborted', 'AbortError');
      }
    };

    const isWarmup = currentPhase.includes('warmup') || currentPhase.includes('practice');
    const isRace = currentPhase.includes('race') || currentPhase.includes('qualify');
    const wasWarmup = previousPhase.includes('warmup') || previousPhase.includes('practice');
    const wasRace = previousPhase.includes('race') || previousPhase.includes('qualify');

    console.log(`[STATE] ${server.name}: ${previousPhase}(${previousState}) -> ${currentPhase}(${currentState})`);

    // Create new session
    if (currentState === 'INPROGRESS' && previousState !== 'INPROGRESS' && !this.serverSessions.has(server.id)) {
      checkAbort();
      const sessionId = `${server.id}_${Date.now()}`;
      const session = server.session || {};

      // Set in Map IMMEDIATELY to prevent race condition with overlapping cycles
      this.serverSessions.set(server.id, sessionId);
      this.serverSessionPhases.set(server.id, currentPhase);

      await this.db.createSession({
        id: sessionId,
        serverId: server.id,
        serverName: server.name,
        trackName: session.track_name || '',
        eventName: session.event_name || '',
        sessionType: currentPhase,
        currentSessionPhase: currentPhase,
        sessionState: currentState,
        weatherConditions: session.weather_type || '',
        airTemperature: session.air_temperature || 20,
        trackLength: session.track_length || 0
      });

      console.log(`[SESSION] Created ${sessionId} on ${server.name}`);
      return;
    }

    // Phase change: warmup -> race
    if (wasWarmup && isRace) {
      checkAbort();
      const sessionId = this.serverSessions.get(server.id);
      if (sessionId) {
        await this.db.updateSession(sessionId, { currentSessionPhase: currentPhase });
        this.serverSessionPhases.set(server.id, currentPhase);
        console.log(`[SESSION] ${sessionId} phase: warmup -> race`);
      }
      return;
    }

    // RACEOVER - Send MMR (CRITICAL - must complete even if cycle times out)
    if (currentState === 'RACEOVER' && isRace) {
      const sessionId = this.serverSessions.get(server.id);
      const apiSource = this.serverToApiMap.get(server.id) || 'unknown';
      console.log(`[RACEOVER-CHECK] Server: ${server.name} (ID: ${server.id}, API: ${apiSource}), SessionId: ${sessionId}, AlreadySent: ${this.mmrSentSessions.has(sessionId)}`);

      if (!sessionId || this.mmrSentSessions.has(sessionId)) {
        console.log(`[RACEOVER-SKIP] Skipping - no session or already sent`);
        return;
      }

      // Mark as sent IMMEDIATELY to prevent race condition with next cycle
      this.mmrSentSessions.add(sessionId);
      console.log(`[RACEOVER-PROCESS] Processing MMR for session ${sessionId}`);

      // Queue critical MMR operation to run even if main cycle times out
      this._processRaceOverAsync(server, sessionId).catch(err => {
        console.error(`[RACEOVER-ASYNC] Error processing ${sessionId}:`, err.message);
        // Remove from sent so it can retry next cycle
        this.mmrSentSessions.delete(sessionId);
      });
      return; // Don't await - let it run independently
    }

    // Finalize session
    // Handle various end-of-race scenarios:
    // - race(COMPLETE) -> anything
    // - race(anything) -> WAITING or UNKNOWN
    // - race -> warmup (new session starting)
    const isCurrentUnknown = currentState === 'UNKNOWN' || currentState === '--' || !currentState;
    const isWaiting = currentState === 'WAITING' || (isCurrentUnknown && !currentPhase);

    const shouldFinalize = (
      (previousState === 'COMPLETE' && wasRace) ||
      (wasRace && isWaiting) ||
      (wasRace && isWarmup && currentState === 'INPROGRESS')
    );

    if (shouldFinalize) {
      checkAbort();
      const sessionId = this.serverSessions.get(server.id);
      if (!sessionId) return;

      const hasRaceResults = this.mmrSentSessions.has(sessionId);
      console.log(`[FINALIZE-PRE] Session: ${sessionId}, hasRaceResults: ${hasRaceResults}, mmrSentSet: [${Array.from(this.mmrSentSessions).slice(0, 5).join(', ')}]`);

      await this.db.updateSession(sessionId, {
        hasFinished: true,
        raceFinalized: hasRaceResults,
        isActive: false,
        endTime: Date.now()
      });

      // Cleanup
      this.serverSessions.delete(server.id);
      this.serverSessionPhases.delete(server.id);
      this.mmrSentSessions.delete(sessionId);
      this.insertedHoleshots.delete(sessionId);
      this.insertedContacts.delete(sessionId);
      this.cachedWarmupStates.delete(sessionId);

      console.log(`[FINALIZE] ${sessionId} - raceFinalized: ${hasRaceResults}`);

      // Create new warmup session if transitioning
      if (wasRace && isWarmup && currentState === 'INPROGRESS') {
        checkAbort();
        const newSessionId = `${server.id}_${Date.now()}`;
        const session = server.session || {};

        // Set in Map IMMEDIATELY to prevent race condition
        this.serverSessions.set(server.id, newSessionId);
        this.serverSessionPhases.set(server.id, currentPhase);

        await this.db.createSession({
          id: newSessionId,
          serverId: server.id,
          serverName: server.name,
          trackName: session.track_name || '',
          sessionType: currentPhase,
          currentSessionPhase: currentPhase,
          sessionState: currentState
        });
      }
      return;
    }

    // Finalize warmup-only
    if (currentState === 'WAITING' && (previousState === 'COMPLETE' || previousState === 'INPROGRESS')) {
      checkAbort();
      const sessionId = this.serverSessions.get(server.id);
      if (sessionId) {
        await this.db.updateSession(sessionId, {
          hasFinished: true,
          raceFinalized: false,
          isActive: false,
          endTime: Date.now()
        });

        this.serverSessions.delete(server.id);
        this.serverSessionPhases.delete(server.id);
        this.insertedHoleshots.delete(sessionId);
        this.insertedContacts.delete(sessionId);
        this.cachedWarmupStates.delete(sessionId);
      }
    }
  }

  // Separate async function for RACEOVER processing - won't be killed by cycle timeout
  async _processRaceOverAsync(server, sessionId) {
    const riders = server.riders || [];
    if (riders.length === 0) return;

    try {
      const ridersWithLaps = riders.filter(r => r.total_laps > 0);

      if (ridersWithLaps.length > 0) {
        const raceResults = ridersWithLaps
          .sort((a, b) => (a.position || 999) - (b.position || 999))
          .map((r, idx) => ({
            playerGuid: r.guid.toUpperCase(),
            playerName: r.name,
            position: idx + 1,
            bestLapTime: r.best_lap?.time || r.best_lap_time || 0,
            totalLaps: r.total_laps || 0,
            raceNumber: r.race_number,
            bikeName: r.bike_name || r.bike_short_name || '',
            gap: r.gap || 0,
            driverStatus: r.driver_status || null,
            holeshotTime: r.holeshot_time || null
          }));

        // Calculate and apply MMR
        const mmrChanges = this.db.calculateMMRChanges(raceResults);
        console.log(`[RACEOVER-DB] Applying MMR to database for ${mmrChanges.length} players, session: ${sessionId}`);
        await this.db.batchUpdatePlayerMMR(mmrChanges);

        // Get updated player data
        const guids = raceResults.map(r => r.playerGuid);
        const updatedPlayers = await this.db.getBatchPlayers(guids);

        const raceResultsWithMMR = raceResults.map(result => {
          const mmrChange = mmrChanges.find(c => c.playerGuid === result.playerGuid);
          const playerData = updatedPlayers.find(p => p?.guid === result.playerGuid);
          return {
            ...result,
            mmrChange: mmrChange?.mmrChange || 0,
            srChange: mmrChange?.srChange || 0,
            currentMMR: playerData?.mmr || 1000
          };
        });

        // Save to player_sessions
        const playerSessions = mmrChanges.map(change => {
          const result = raceResults.find(r => r.playerGuid === change.playerGuid);
          return {
            playerGuid: change.playerGuid,
            position: result.position,
            bestLapTime: result.bestLapTime,
            totalLaps: result.totalLaps,
            didFinish: true,
            mmrChange: change.mmrChange,
            srChange: change.srChange
          };
        });

        await this.db.batchAddPlayersToSession(sessionId, playerSessions);
        await this.db.updateSession(sessionId, {
          raceResults: raceResultsWithMMR,
          totalEntries: raceResultsWithMMR.length
        });

        // Send MMR to Manager API
        await this.sendMMRToManagerAPI(server, raceResultsWithMMR);

        console.log(`[RACEOVER] ${sessionId}: Winner ${raceResults[0]?.playerName}`);
      }
    } catch (err) {
      console.error(`[RACEOVER] Error:`, err.message);
      throw err; // Re-throw so caller can handle retry
    }
  }

  async sendMMRToManagerAPI(server, raceResultsWithMMR) {
    const mmrUpdates = raceResultsWithMMR.map(result => ({
      playerGuid: result.playerGuid,
      playerName: result.playerName,
      raceNumber: result.raceNumber,
      mmrChange: result.mmrChange,
      newMMR: result.currentMMR
    }));

    const apiOrigin = this.serverToApiMap.get(server.id) || 1;
    let apiUrl = apiOrigin === 1 ? this.env.MXBIKES_API_URL_1 : this.env.MXBIKES_API_URL_2;
    let apiKey = apiOrigin === 1 ? this.env.MXBIKES_API_KEY_1 : this.env.MXBIKES_API_KEY_2;

    console.log(`[MMR] Sending ${mmrUpdates.length} updates to API ${apiOrigin} for server ${server.id}`);

    // Helper to add timeout to fetch requests
    const fetchWithTimeout = (url, options, timeoutMs = 5000) => {
      return Promise.race([
        fetch(url, options),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Request timeout')), timeoutMs)
        )
      ]);
    };

    try {
      const response = await fetchWithTimeout(`${apiUrl}/servers/${server.id}/mmr-updates`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': apiKey
        },
        body: JSON.stringify({ Players: mmrUpdates })
      });

      if (response.ok) {
        const result = await response.json();
        console.log(`[MMR] Success: ${result.messagesSent}/${result.totalPlayers} delivered`);
      } else {
        // Try alternate API
        apiUrl = apiOrigin === 1 ? this.env.MXBIKES_API_URL_2 : this.env.MXBIKES_API_URL_1;
        apiKey = apiOrigin === 1 ? this.env.MXBIKES_API_KEY_2 : this.env.MXBIKES_API_KEY_1;

        console.log(`[MMR] Retrying on alternate API`);
        const retryResponse = await fetchWithTimeout(`${apiUrl}/servers/${server.id}/mmr-updates`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
          body: JSON.stringify({ Players: mmrUpdates })
        });

        if (retryResponse.ok) {
          console.log(`[MMR] Success on retry`);
        } else {
          console.error(`[MMR] Failed on both APIs`);
        }
      }
    } catch (err) {
      console.error(`[MMR] Error:`, err.message);
    }
  }
}
