import { setMaxListeners } from 'events';

export class StateManager {
  constructor(db, env) {
    this.db = db;
    this.env = env;
    this.previousServerStates = new Map();
    this.serverSessions = new Map();
    this.serverSessionPhases = new Map();
    this.mmrSentSessions = new Set();
    this.serverToApiMap = new Map();
    this.cachedPlayerStates = new Map();
    this.insertedHoleshots = new Map();
    this.insertedContacts = new Map();
    this.cachedWarmupStates = new Map();
    this.serverTracks = new Map();
    this.LASTSEEN_UPDATE_INTERVAL = 60000;
    this.cachedServerData = null;
    this.lastServerDataFetch = 0;
    this.alarmCounter = 0;
    // Track sessions being processed to prevent race conditions
    this.processingRaceSessions = new Set();
    // Store last warmup results for sessions to ensure they're saved before transition
    this.lastWarmupResults = new Map();
    // CRITICAL: Cache race results during RACE phase so we have them even if RACEOVER is missed
    // When END message is received, riders are cleared - this cache preserves them for finalization
    this.lastRaceResults = new Map(); // sessionId -> { riders: [...], serverId, timestamp }
    // Track which servers are in active RACE phase for fast polling
    this.racePhaseServers = new Map(); // serverId -> { sessionId, apiSource }
    this.raceWatcherRunning = false;
    // Network optimization: cache detailed server data between full fetches
    this.cachedDetailedServers = new Map(); // serverId -> detailed data
    this.detailedFetchCounter = 0;
    this.DETAILED_FETCH_INTERVAL = 3; // Fetch detailed data every 3rd cycle (45s at 15s interval)
  }

  async recoverStateFromDatabase() {
    try {
      const sessions = await this.db.getActiveSessions();
      if (!sessions.length) { console.log('[RECOVERY] No active sessions'); return; }
      let racePhaseCount = 0;
      for (const s of sessions) {
        this.serverSessions.set(s.serverId, s.id);
        if (s.currentSessionPhase) this.serverSessionPhases.set(s.serverId, s.currentSessionPhase);
        if (s.sessionState) this.previousServerStates.set(s.serverId, s.sessionState);
        if (s.raceResults?.length) this.mmrSentSessions.add(s.id);
        // CRITICAL: Add race-phase sessions to race watcher so they get fast-polled for RACEOVER
        const phase = (s.currentSessionPhase || '').toLowerCase();
        if (phase.includes('race') && !phase.includes('over')) {
          this.racePhaseServers.set(s.serverId, { sessionId: s.id, apiSource: 1 });
          racePhaseCount++;
          console.log(`[RECOVERY] Added ${s.serverId} to race watcher (session ${s.id}, phase: ${s.currentSessionPhase})`);
        }
      }
      console.log(`[RECOVERY] ${sessions.length} sessions, ${this.mmrSentSessions.size} with MMR, ${racePhaseCount} in race phase`);
    } catch (err) { console.error('[RECOVERY] Error:', err.message); }
  }

  getTrackForServer(serverId) { return this.serverTracks.get(serverId) || null; }
  getCachedServerData() { return this.cachedServerData; }

  async runUpdateCycle() {
    this.alarmCounter++;
    const cycleId = this.alarmCounter;
    if (this.activeCycleId && this.activeCycleId !== cycleId) console.warn(`[Update] Cycle overlap #${cycleId}`);
    this.activeCycleId = cycleId;
    const ac = new AbortController();
    this.currentAbortController = ac;
    try { setMaxListeners(50, ac.signal); } catch {}
    // Increased from 30s to 45s to handle busy periods with many servers
    const timeout = setTimeout(() => { console.error(`[Update] TIMEOUT #${cycleId}`); ac.abort(); }, 45000);
    try { await this._runUpdateCycleInternal(ac.signal, cycleId); }
    catch (e) { if (e.name !== 'AbortError') console.error('[Update] Error:', e.message); }
    finally { clearTimeout(timeout); if (this.activeCycleId === cycleId) this.activeCycleId = null; this.currentAbortController = null; }
  }

  // Start the race watcher loop - polls race-phase servers every 3 seconds to catch RACEOVER
  startRaceWatcher() {
    if (this.raceWatcherRunning) return;
    this.raceWatcherRunning = true;
    console.log('[RACE-WATCHER] Started - polling race servers every 3s');
    this._raceWatcherLoop();
  }

  async _raceWatcherLoop() {
    while (this.raceWatcherRunning) {
      try {
        await this._pollRaceServers();
      } catch (e) {
        console.error('[RACE-WATCHER] Error:', e.message);
      }
      await new Promise(r => setTimeout(r, 3000)); // 3 second interval
    }
  }

  async _pollRaceServers() {
    if (this.racePhaseServers.size === 0) return;

    const fetchJson = async (url, opts, ms = 5000) => {
      try {
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), ms);
        try {
          const res = await fetch(url, { ...opts, signal: ctrl.signal });
          clearTimeout(tid);
          if (!res.ok) return null;
          return await res.json();
        } finally { clearTimeout(tid); }
      } catch { return null; }
    };

    // Poll each race-phase server
    const polls = Array.from(this.racePhaseServers.entries()).map(async ([serverId, info]) => {
      const url = info.apiSource === 1 ? this.env.MXBIKES_API_URL_1 : this.env.MXBIKES_API_URL_2;
      const key = info.apiSource === 1 ? this.env.MXBIKES_API_KEY_1 : this.env.MXBIKES_API_KEY_2;

      const data = await fetchJson(`${url}/servers/${serverId}`, { headers: { 'X-API-Key': key } }, 4000);
      if (!data) return;

      const state = data.session?.session_state || 'UNKNOWN';
      let riders = data.riders || [];
      const sid = info.sessionId;

      // Cache race results while we have rider data (backup for finalization)
      if (riders.length > 0) {
        this.lastRaceResults.set(sid, { riders, serverId, timestamp: Date.now() });
      }

      // FIX: Handle both RACEOVER and COMPLETE states - some servers skip RACEOVER entirely
      const isRaceEnded = (state === 'RACEOVER' || state === 'COMPLETE');
      if (isRaceEnded && !this.mmrSentSessions.has(sid)) {
        // FIX: If riders are empty at RACEOVER/COMPLETE, use cached race results
        // The game often clears rider data before we can read it
        if (riders.length === 0) {
          const cachedRace = this.lastRaceResults.get(sid);
          if (cachedRace?.riders?.length > 0) {
            console.log(`[RACE-WATCHER] ${state} detected for ${serverId} (session ${sid}) - riders empty, using cached results (${cachedRace.riders.length} riders from ${Math.round((Date.now() - cachedRace.timestamp) / 1000)}s ago)`);
            riders = cachedRace.riders;
          } else {
            console.warn(`[RACE-WATCHER] ${state} detected for ${serverId} (session ${sid}) - NO riders and NO cached results!`);
          }
        } else {
          console.log(`[RACE-WATCHER] ${state} detected for ${serverId} (session ${sid}) with ${riders.length} riders!`);
        }

        this.processingRaceSessions.add(sid);
        try {
          // Build server object for _processRaceOverAsync
          const srv = { id: serverId, name: data.server?.name || serverId, riders, session: data.session };
          const saved = await this._processRaceOverAsync(srv, sid);
          if (saved) {
            // FIX: Only set mmrSentSessions AFTER results are confirmed saved
            this.mmrSentSessions.add(sid);
            console.log(`[RACE-WATCHER] Successfully saved results for ${sid}`);
          } else {
            console.warn(`[RACE-WATCHER] No results to save for ${sid} (no riders)`);
          }
        } catch (e) {
          console.error(`[RACE-WATCHER] Failed to save results for ${sid}:`, e.message);
          // Don't set mmrSentSessions - allow retry
        } finally {
          this.processingRaceSessions.delete(sid);
        }
      }

      // If state changed to WAITING or UNKNOWN, remove from race watcher
      if (state === 'WAITING' || state === 'UNKNOWN') {
        this.racePhaseServers.delete(serverId);
      }
    });

    await Promise.all(polls);
  }

  async _runUpdateCycleInternal(signal, cycleId) {
    const check = () => { if (signal?.aborted) throw new DOMException('Aborted', 'AbortError'); };
    try {
      check();
      const data = await this.fetchServersFromAPI(signal);
      if (!data?.servers) return;
      check();
      const { onlinePlayers } = data;
      const now = Date.now();
      if (onlinePlayers?.length) {
        const toUpdate = [];
        for (const p of onlinePlayers) {
          const guid = p.guid.toUpperCase();
          const cached = this.cachedPlayerStates.get(guid);
          const state = { server: p.currentServer, track: p.currentTrack, bike: p.bikeName, raceNum: p.raceNumber, name: p.displayName };
          const changed = !cached || cached.server !== state.server || cached.track !== state.track || cached.bike !== state.bike || cached.raceNum !== state.raceNum || cached.name !== state.name;
          const updateLastSeen = !cached?.lastSeenUpdate || (now - cached.lastSeenUpdate) >= this.LASTSEEN_UPDATE_INTERVAL;
          if (changed || updateLastSeen) {
            toUpdate.push({ guid, displayName: p.displayName, currentServer: p.currentServer, currentTrack: p.currentTrack, raceNumber: p.raceNumber, bikeName: p.bikeName, lastSeen: now, autoGenerated: true });
            this.cachedPlayerStates.set(guid, { ...state, lastSeenUpdate: updateLastSeen ? now : cached?.lastSeenUpdate });
          }
        }
        for (let i = 0; i < toUpdate.length; i += 25) { check(); await this.db.batchUpsertPlayers(toUpdate.slice(i, i + 25)); }
        if (toUpdate.length) console.log(`[UPDATE] ${toUpdate.length}/${onlinePlayers.length} players`);
      }
      check();
      await this.processServerUpdates(data, signal);
      console.log(`[Cycle #${cycleId}] ${data.servers.length} servers, ${this.serverSessions.size} sessions, ${onlinePlayers?.length || 0} online`);
    } catch (e) { if (e.name === 'AbortError') throw e; console.error('[Update] Error:', e.message); }
  }

  async fetchServersFromAPI(signal) {
    const fetchJson = async (url, opts, ms = 5000) => {
      try {
        if (signal?.aborted) return null;
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), ms);
        let handler = null;
        if (signal) { handler = () => ctrl.abort(); signal.addEventListener('abort', handler, { once: true }); }
        try {
          const res = await fetch(url, { ...opts, signal: ctrl.signal });
          clearTimeout(tid);
          if (!res.ok) return null;
          return await Promise.race([res.json(), new Promise(r => setTimeout(() => r(null), 3000))]);
        } finally { clearTimeout(tid); if (signal && handler && !signal.aborted) signal.removeEventListener('abort', handler); }
      } catch { if (signal?.aborted) throw new DOMException('Aborted', 'AbortError'); return null; }
    };

    // Always fetch basic server lists (2 requests)
    const [s1, s2] = await Promise.all([
      fetchJson(`${this.env.MXBIKES_API_URL_1}/servers`, { headers: { 'X-API-Key': this.env.MXBIKES_API_KEY_1 } }, 10000),
      fetchJson(`${this.env.MXBIKES_API_URL_2}/servers`, { headers: { 'X-API-Key': this.env.MXBIKES_API_KEY_2 } }, 10000)
    ]);
    const smap = new Map();
    (s1 || []).forEach(s => smap.set(s.id, { server: s, source: 1 }));
    (s2 || []).forEach(s => { if (!smap.has(s.id)) smap.set(s.id, { server: s, source: 2 }); });
    const all = Array.from(smap.values()).map(v => v.server);

    // OPTIMIZATION: Only fetch detailed server data every Nth cycle OR for servers with active sessions
    this.detailedFetchCounter++;
    const shouldFetchAllDetailed = this.detailedFetchCounter >= this.DETAILED_FETCH_INTERVAL;
    if (shouldFetchAllDetailed) this.detailedFetchCounter = 0;

    // Determine which servers need detailed fetch
    const serversNeedingDetail = all.filter(srv => {
      // Always fetch if we should do full refresh
      if (shouldFetchAllDetailed) return true;
      // Always fetch if server has an active session
      if (this.serverSessions.has(srv.id)) return true;
      // Fetch if we don't have cached data
      if (!this.cachedDetailedServers.has(srv.id)) return true;
      // Otherwise use cache
      return false;
    });

    // Only fetch detailed data for servers that need it
    const detailedResults = new Map();
    if (serversNeedingDetail.length > 0) {
      const detailed = await Promise.all(serversNeedingDetail.map(srv => {
        const src = smap.get(srv.id)?.source || 1;
        this.serverToApiMap.set(srv.id, src);
        const url = src === 1 ? this.env.MXBIKES_API_URL_1 : this.env.MXBIKES_API_URL_2;
        const key = src === 1 ? this.env.MXBIKES_API_KEY_1 : this.env.MXBIKES_API_KEY_2;
        return fetchJson(`${url}/servers/${srv.id}`, { headers: { 'X-API-Key': key } }, 8000);
      }));
      serversNeedingDetail.forEach((srv, i) => {
        if (detailed[i]) {
          detailedResults.set(srv.id, detailed[i]);
          this.cachedDetailedServers.set(srv.id, detailed[i]); // Update cache
        }
      });
      if (!shouldFetchAllDetailed) {
        console.log(`[FETCH] Optimized: ${serversNeedingDetail.length}/${all.length} detailed fetches (${all.length - serversNeedingDetail.length} cached)`);
      }
    }

    // Build servers array using fresh + cached data
    const servers = all.map(srv => {
      const d = detailedResults.get(srv.id) || this.cachedDetailedServers.get(srv.id);
      if (d) {
        srv.session = d.session || null;
        srv.riders = d.riders || [];
        srv.session_state = d.session?.session_state;
        srv.session_type = d.session?.session_type;
        if (d.connection_status) srv.liveTimingConnected = d.connection_status.connected;
      }
      srv.apiSource = smap.get(srv.id)?.source || 1;
      srv.liveTimingConnected = srv.liveTimingConnected ?? false;
      srv.remoteAdminConnected = srv.remoteAdminConnected ?? false;
      srv.LiveTimingConnected = srv.liveTimingConnected;
      srv.RemoteAdminConnected = srv.remoteAdminConnected;
      return srv;
    });
    servers.forEach(s => { const t = s.session?.track_name; if (s.id && t) this.serverTracks.set(s.id, t); });
    const players = new Map();
    servers.forEach(s => (s.riders || []).forEach(r => { if (r?.guid && !players.has(r.guid)) players.set(r.guid, { guid: r.guid, displayName: r.name, currentServer: s.name, currentTrack: s.session?.track_name || '', raceNumber: r.race_number, bikeName: r.bike, bestLapTime: r.best_lap?.time || r.best_lap_time || 0 }); }));
    this.cachedServerData = { servers, totalServers: all.length, activeServers: servers.length, activePlayersCount: players.size, onlinePlayers: Array.from(players.values()) };
    this.lastServerDataFetch = Date.now();
    return this.cachedServerData;
  }

  async processServerUpdates(data, signal) {
    const check = () => { if (signal?.aborted) throw new DOMException('Aborted', 'AbortError'); };
    const warmups = [], contacts = [], holeshots = [];
    for (const srv of data.servers) {
      const sid = this.serverSessions.get(srv.id);
      const state = srv.session_state || 'UNKNOWN';
      // Use cached phase if API didn't return one (timeout protection)
      const cachedPhase = this.serverSessionPhases.get(srv.id) || '';
      const phase = (srv.session_type || '').toLowerCase() || cachedPhase;
      const isWarmup = phase.includes('warmup') || phase.includes('practice');
      const isRacePhase = phase.includes('race') || phase.includes('qualify');

      // FIX: Cache race-phase rider data in main cycle too (not just race watcher)
      // This provides a backup cache if the race watcher misses data due to network issues
      if (sid && isRacePhase && (state === 'INPROGRESS' || state === 'STARTSEQUENCE' || state === 'PRESTART')) {
        const riders = srv.riders || [];
        if (riders.length > 0) {
          this.lastRaceResults.set(sid, { riders, serverId: srv.id, timestamp: Date.now() });
        }
      }

      if (sid && state === 'INPROGRESS' && isWarmup) {
        const riders = srv.riders || [];
        if (riders.length) {
          const results = riders.filter(r => r.best_lap_time > 0 || r.best_lap?.time > 0)
            .sort((a, b) => (a.best_lap?.time || a.best_lap_time || 999) - (b.best_lap?.time || b.best_lap_time || 999))
            .map((r, i, arr) => {
              const best = r.best_lap?.time || r.best_lap_time || 0;
              const leader = arr[0]?.best_lap?.time || arr[0]?.best_lap_time || 0;
              return { playerGuid: r.guid.toUpperCase(), playerName: r.name, position: i + 1, bestLapTime: best, totalLaps: r.total_laps || 0, raceNumber: r.race_number, bikeName: r.bike_name || r.bike_short_name || '', gap: i > 0 ? best - leader : 0, driverStatus: r.driver_status || null, holeshotTime: r.holeshot_time || null, penalties: r.penalties || [] };
            });
          // ALWAYS store the latest warmup results so we can save them on phase transition
          if (results.length > 0) {
            this.lastWarmupResults.set(sid, results);
          }
          const cached = this.cachedWarmupStates.get(sid);
          let changed = !cached || cached.size !== results.length;
          if (!changed) for (const r of results) { const c = cached.get(r.playerGuid); if (!c || c.pos !== r.position || c.time !== r.bestLapTime || c.laps !== r.totalLaps) { changed = true; break; } }
          if (changed) {
            warmups.push({ sessionId: sid, updates: { warmupResults: results, totalEntries: results.length }, riderCount: results.length });
            const nc = new Map(); results.forEach(r => nc.set(r.playerGuid, { pos: r.position, time: r.bestLapTime, laps: r.totalLaps })); this.cachedWarmupStates.set(sid, nc);
          }
          for (const r of riders) {
            if (r.contacts?.length) {
              if (!this.insertedContacts.has(sid)) this.insertedContacts.set(sid, new Set());
              const ins = this.insertedContacts.get(sid);
              for (const c of r.contacts) {
                const cid = `${c.time}_${c.race_number_1}_${c.race_number_2}`;
                if (!ins.has(cid)) { contacts.push({ sessionId: sid, time: c.time, playerGuid1: r.guid?.toUpperCase(), playerName1: r.name, raceNumber1: c.race_number_1, playerGuid2: null, playerName2: null, raceNumber2: c.race_number_2, relativeImpactVelocity: c.relative_impact_velocity }); ins.add(cid); }
              }
            }
            if (r.holeshot_time > 0) {
              if (!this.insertedHoleshots.has(sid)) this.insertedHoleshots.set(sid, new Set());
              const ins = this.insertedHoleshots.get(sid);
              const guid = r.guid?.toUpperCase();
              if (!ins.has(guid)) { holeshots.push({ sessionId: sid, playerGuid: guid, playerName: r.name, raceNumber: r.race_number, holeshotTime: r.holeshot_time, trackName: srv.session?.track_name || '' }); ins.add(guid); }
            }
          }
        }
      }
    }
    for (let i = 0; i < warmups.length; i += 10) { check(); await this.db.batchUpdateSessions(warmups.slice(i, i + 10)); }
    for (let i = 0; i < contacts.length; i += 10) { check(); await this.db.batchInsertContacts(contacts.slice(i, i + 10)); }
    for (let i = 0; i < holeshots.length; i += 10) { check(); await this.db.batchInsertHoleshots(holeshots.slice(i, i + 10)); }
    check();
    const processed = new Set();
    for (const srv of data.servers) {
      check();
      if (processed.has(srv.id)) continue;
      processed.add(srv.id);
      const state = srv.session_state || 'UNKNOWN';
      // CRITICAL: If phase is missing but we have an active session, use the cached phase
      // This prevents losing track of sessions when API fetch times out
      const cachedPhase = this.serverSessionPhases.get(srv.id) || '';
      const phase = (srv.session_type || '').toLowerCase() || cachedPhase;
      const prevState = this.previousServerStates.get(srv.id) || 'UNKNOWN';
      const prevPhase = cachedPhase;
      if (state !== prevState || (phase !== prevPhase && state === 'INPROGRESS')) {
        await this.handleSessionStateChange(srv, prevState, state, prevPhase, phase, signal);
        this.previousServerStates.set(srv.id, state);
        if (phase) this.serverSessionPhases.set(srv.id, phase); // Only update if we have a phase
      }
    }
  }

  async handleSessionStateChange(srv, prevState, state, prevPhase, phase, signal) {
    const check = () => { if (signal?.aborted) throw new DOMException('Aborted', 'AbortError'); };
    const isWarmup = phase.includes('warmup') || phase.includes('practice');
    const isRace = phase.includes('race') || phase.includes('qualify');
    const wasWarmup = prevPhase.includes('warmup') || prevPhase.includes('practice');
    const wasRace = prevPhase.includes('race') || prevPhase.includes('qualify');
    console.log(`[STATE] ${srv.name}: ${prevPhase}(${prevState}) -> ${phase}(${state})`);
    if (state === 'INPROGRESS' && prevState !== 'INPROGRESS' && !this.serverSessions.has(srv.id)) {
      check();
      const sid = `${srv.id}_${Date.now()}`;
      const sess = srv.session || {};
      this.serverSessions.set(srv.id, sid);
      this.serverSessionPhases.set(srv.id, phase);
      await this.db.createSession({ id: sid, serverId: srv.id, serverName: srv.name, trackName: sess.track_name || '', eventName: sess.event_name || '', sessionType: phase, currentSessionPhase: phase, sessionState: state, weatherConditions: sess.weather_type || '', airTemperature: sess.air_temperature || 20, trackLength: sess.track_length || 0 });
      console.log(`[SESSION] Created ${sid}`);
      // If starting directly in race phase, add to race watcher
      if (isRace) {
        const apiSource = this.serverToApiMap.get(srv.id) || srv.apiSource || 1;
        this.racePhaseServers.set(srv.id, { sessionId: sid, apiSource });
        console.log(`[RACE-WATCHER] Added ${srv.id} to race watcher (new race session ${sid})`);
      }
      return;
    }
    if (wasWarmup && isRace) {
      check();
      const sid = this.serverSessions.get(srv.id);
      if (sid) {
        // CRITICAL: Save the final warmup results before transitioning to race phase
        // This ensures warmup results are always preserved even if we didn't catch the last INPROGRESS state
        const lastWarmup = this.lastWarmupResults.get(sid);
        if (lastWarmup && lastWarmup.length > 0) {
          await this.db.updateSession(sid, { warmupResults: lastWarmup, totalEntries: lastWarmup.length, currentSessionPhase: phase });
          console.log(`[SESSION] ${sid} warmup -> race (saved ${lastWarmup.length} warmup results)`);
        } else {
          await this.db.updateSession(sid, { currentSessionPhase: phase });
          console.log(`[SESSION] ${sid} warmup -> race (no warmup results to save)`);
        }
        this.serverSessionPhases.set(srv.id, phase);
        // Keep lastWarmupResults for reference until session finalization

        // CRITICAL: Add to race watcher for fast RACEOVER detection
        const apiSource = this.serverToApiMap.get(srv.id) || srv.apiSource || 1;
        this.racePhaseServers.set(srv.id, { sessionId: sid, apiSource });
        console.log(`[RACE-WATCHER] Added ${srv.id} to race watcher (session ${sid})`);
      }
      return;
    }
    // FIX: Handle both RACEOVER and COMPLETE in main cycle too
    if ((state === 'RACEOVER' || state === 'COMPLETE') && isRace) {
      const sid = this.serverSessions.get(srv.id);
      if (!sid || this.mmrSentSessions.has(sid)) return;
      // Mark session as being processed to prevent race conditions with finalization
      this.processingRaceSessions.add(sid);
      // Process race results - await to prevent race condition with finalization
      try {
        const saved = await this._processRaceOverAsync(srv, sid);
        if (saved) {
          // FIX: Only set mmrSentSessions AFTER successful save
          this.mmrSentSessions.add(sid);
        } else {
          console.log(`[RACEOVER] ${sid} - no results saved, will retry`);
        }
      } catch (e) {
        console.error(`[RACEOVER] Error ${sid}:`, e.message);
        // Don't set mmrSentSessions on error - allows retry on next cycle
        const session = await this.db.getSession(sid);
        if (session?.raceResults?.length > 0) {
          // Results were actually saved despite error (partial failure)
          this.mmrSentSessions.add(sid);
          console.log(`[RACEOVER] ${sid} - results already saved, marking finalized`);
        } else {
          console.log(`[RACEOVER] ${sid} - will retry on next cycle`);
        }
      } finally {
        this.processingRaceSessions.delete(sid);
      }
      return;
    }
    const isUnknown = state === 'UNKNOWN' || state === '--' || !state;
    // Treat unknown/-- state as waiting if phase is not actively racing (prevents API glitch false-finalization)
    const isWaiting = state === 'WAITING' || (isUnknown && !isRace);
    const shouldFinalize = (prevState === 'COMPLETE' && wasRace) || (prevState === 'RACEOVER' && wasRace) || (wasRace && isWaiting) || (wasRace && isWarmup && state === 'INPROGRESS');
    if (shouldFinalize) {
      check();
      const sid = this.serverSessions.get(srv.id);
      if (!sid) return;
      // CRITICAL: Wait for any in-progress race processing to complete first
      if (this.processingRaceSessions.has(sid)) {
        console.log(`[FINALIZE] ${sid} - waiting for race processing to complete...`);
        // Wait up to 10 seconds for race processing to complete
        const waitStart = Date.now();
        while (this.processingRaceSessions.has(sid) && (Date.now() - waitStart) < 10000) {
          await new Promise(r => setTimeout(r, 250));
        }
        if (this.processingRaceSessions.has(sid)) {
          console.warn(`[FINALIZE] ${sid} - race processing timed out, finalizing anyway`);
        }
      }
      // FIX: Check ONLY the database for actual results - never use mmrSentSessions as proxy
      // mmrSentSessions can be incorrectly set if _processRaceOverAsync returned without saving
      let session = await this.db.getSession(sid);
      let hasResults = session?.raceResults?.length > 0;

      // CRITICAL FIX: If this was a race session and we don't have results in DB, try to save now
      // This is the last-resort recovery for any race that was missed by race watcher AND main cycle
      if (wasRace && !hasResults) {
        console.log(`[FINALIZE] ${sid} - Race ended but no results in DB! Attempting late save...`);
        try {
          // Mark as processing to prevent double-processing
          this.processingRaceSessions.add(sid);

          // _processRaceOverAsync will automatically use cached results if live riders are empty
          const saved = await this._processRaceOverAsync(srv, sid);
          // Re-check if results were saved
          session = await this.db.getSession(sid);
          hasResults = session?.raceResults?.length > 0;
          if (saved) {
            this.mmrSentSessions.add(sid);
          }
          console.log(`[FINALIZE] ${sid} - Late result save ${hasResults ? 'SUCCEEDED' : 'FAILED'}: ${session?.raceResults?.length || 0} results`);
        } catch (e) {
          console.error(`[FINALIZE] ${sid} - Late result save error:`, e.message);
        } finally {
          this.processingRaceSessions.delete(sid);
        }
      }

      await this.db.updateSession(sid, { hasFinished: true, raceFinalized: hasResults, isActive: false, endTime: Date.now() });
      this.serverSessions.delete(srv.id);
      this.serverSessionPhases.delete(srv.id);
      this.mmrSentSessions.delete(sid);
      this.insertedHoleshots.delete(sid);
      this.insertedContacts.delete(sid);
      this.cachedWarmupStates.delete(sid);
      this.lastWarmupResults.delete(sid);
      this.lastRaceResults.delete(sid);  // Clean up race results cache
      this.racePhaseServers.delete(srv.id);  // Clean up race watcher
      console.log(`[FINALIZE] ${sid} - raceFinalized: ${hasResults}`);
      if (wasRace && isWarmup && state === 'INPROGRESS') {
        check();
        const newSid = `${srv.id}_${Date.now()}`;
        const sess = srv.session || {};
        this.serverSessions.set(srv.id, newSid);
        this.serverSessionPhases.set(srv.id, phase);
        await this.db.createSession({ id: newSid, serverId: srv.id, serverName: srv.name, trackName: sess.track_name || '', sessionType: phase, currentSessionPhase: phase, sessionState: state });
      }
      return;
    }
    if (state === 'WAITING' && (prevState === 'COMPLETE' || prevState === 'INPROGRESS')) {
      check();
      const sid = this.serverSessions.get(srv.id);
      if (sid) {
        await this.db.updateSession(sid, { hasFinished: true, raceFinalized: false, isActive: false, endTime: Date.now() });
        this.serverSessions.delete(srv.id);
        this.serverSessionPhases.delete(srv.id);
        this.insertedHoleshots.delete(sid);
        this.insertedContacts.delete(sid);
        this.cachedWarmupStates.delete(sid);
        this.lastWarmupResults.delete(sid);
        this.lastRaceResults.delete(sid);
        this.racePhaseServers.delete(srv.id);
        this.mmrSentSessions.delete(sid);
      }
    }
  }

  // Returns true if results were saved, false if no riders/results to save
  async _processRaceOverAsync(srv, sid) {
    let riders = srv.riders || [];

    // FIX: If no riders from live data, try cached race results
    if (!riders.length) {
      const cachedRace = this.lastRaceResults.get(sid);
      if (cachedRace?.riders?.length > 0) {
        console.log(`[RACEOVER] ${sid}: No live riders, using cached results (${cachedRace.riders.length} riders from ${Math.round((Date.now() - cachedRace.timestamp) / 1000)}s ago)`);
        riders = cachedRace.riders;
      } else {
        console.warn(`[RACEOVER] ${sid}: No riders present and no cached results`);
        return false;
      }
    }

    try {
      // Include ALL riders, not just those with laps - they participated in the session
      const withLaps = riders.filter(r => r.total_laps > 0);
      const withoutLaps = riders.filter(r => !r.total_laps || r.total_laps === 0);

      // Build results for riders with laps (sorted by position)
      const lapResults = withLaps.sort((a, b) => (a.position || 999) - (b.position || 999))
        .map((r, i) => ({ playerGuid: r.guid.toUpperCase(), playerName: r.name, position: i + 1, bestLapTime: r.best_lap?.time || r.best_lap_time || 0, totalLaps: r.total_laps || 0, raceNumber: r.race_number, bikeName: r.bike_name || r.bike_short_name || '', gap: r.gap || 0, driverStatus: r.driver_status || 'DNF', holeshotTime: r.holeshot_time || null, contacts: r.contacts || [], invalidLaps: r.invalid_laps || 0, penalties: r.penalties || [] }));

      // Add riders without laps as DNS/DNF at the end
      const noLapResults = withoutLaps.map((r, i) => ({
        playerGuid: r.guid.toUpperCase(), playerName: r.name, position: lapResults.length + i + 1,
        bestLapTime: 0, totalLaps: 0, raceNumber: r.race_number, bikeName: r.bike_name || r.bike_short_name || '',
        gap: 0, driverStatus: r.driver_status || 'DNS', holeshotTime: null, contacts: [], invalidLaps: 0, penalties: []
      }));

      const results = [...lapResults, ...noLapResults];

      if (results.length > 0) {
        // Only calculate MMR for riders who completed at least 1 lap
        const mmrEligible = lapResults.length >= 2 ? lapResults : [];
        const mmr = mmrEligible.length > 0 ? this.db.calculateMMRChanges(mmrEligible) : [];
        if (mmr.length > 0) {
          await this.db.batchUpdatePlayerMMR(mmr);
        }
        const players = await this.db.getBatchPlayers(results.map(r => r.playerGuid));
        const resultsWithMMR = results.map(r => {
          const m = mmr.find(c => c.playerGuid === r.playerGuid);
          const p = players.find(x => x?.guid === r.playerGuid);
          return { ...r, mmrChange: m?.mmrChange || 0, srChange: m?.srChange || 0, currentMMR: p?.mmr || 1000 };
        });
        const playerSessions = results.map(r => {
          const m = mmr.find(c => c.playerGuid === r.playerGuid);
          return { playerGuid: r.playerGuid, position: r.position, bestLapTime: r.bestLapTime, totalLaps: r.totalLaps, didFinish: r.totalLaps > 0, mmrChange: m?.mmrChange || 0, srChange: m?.srChange || 0 };
        });
        await this.db.batchAddPlayersToSession(sid, playerSessions);
        await this.db.updateSession(sid, { raceResults: resultsWithMMR, totalEntries: resultsWithMMR.length });
        // Only send MMR notifications if we actually calculated MMR
        if (mmr.length > 0) {
          await this.sendMMRToManagerAPI(srv, resultsWithMMR.filter(r => r.mmrChange !== 0));
        }
        const winner = lapResults[0];
        console.log(`[RACEOVER] ${sid}: ${lapResults.length} finishers, ${noLapResults.length} DNS/DNF${winner ? `, Winner: ${winner.playerName}` : ''}`);
        return true;
      } else {
        // No participants at all - still mark session with empty results
        await this.db.updateSession(sid, { raceResults: [], totalEntries: 0 });
        console.log(`[RACEOVER] ${sid}: No participants`);
        return false;
      }
    } catch (e) { console.error('[RACEOVER] Error:', e.message); throw e; }
  }

  async sendMMRToManagerAPI(srv, results) {
    const updates = results.map(r => ({ playerGuid: r.playerGuid, playerName: r.playerName, raceNumber: r.raceNumber, mmrChange: r.mmrChange, newMMR: r.currentMMR }));
    const src = this.serverToApiMap.get(srv.id) || 1;
    let url = src === 1 ? this.env.MXBIKES_API_URL_1 : this.env.MXBIKES_API_URL_2;
    let key = src === 1 ? this.env.MXBIKES_API_KEY_1 : this.env.MXBIKES_API_KEY_2;
    const send = (u, k) => Promise.race([fetch(`${u}/servers/${srv.id}/mmr-updates`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': k }, body: JSON.stringify({ Players: updates }) }), new Promise((_, r) => setTimeout(() => r(new Error('Timeout')), 10000))]);
    try {
      const res = await send(url, key);
      if (res.ok) { const r = await res.json(); console.log(`[MMR] ${r.messagesSent}/${r.totalPlayers} delivered`); }
      else {
        url = src === 1 ? this.env.MXBIKES_API_URL_2 : this.env.MXBIKES_API_URL_1;
        key = src === 1 ? this.env.MXBIKES_API_KEY_2 : this.env.MXBIKES_API_KEY_1;
        const retry = await send(url, key);
        if (retry.ok) console.log('[MMR] Success on retry'); else console.error('[MMR] Failed both APIs');
      }
    } catch (e) { console.error('[MMR] Error:', e.message); }
  }
}
