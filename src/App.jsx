import { useState, useEffect, useCallback, createContext, useContext } from "react";

// ============================================================
// CAPA SOLID — Super Campeones
// Cada sección implementa un principio específico.
// Este archivo se inserta reemplazando Security + Store + API
// en el archivo principal.
// ============================================================

// ─────────────────────────────────────────────────────────────
// S — SINGLE RESPONSIBILITY
// Cada clase/objeto tiene una única razón para cambiar.
// Security se divide en 4 responsabilidades independientes.
// ─────────────────────────────────────────────────────────────

/** Solo sanitiza strings de entrada del usuario (A03 OWASP) */
const Sanitizer = {
  clean: (v, maxLen = 300) => {
    if (typeof v !== "string") return "";
    return v
      .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
      .replace(/"/g,"&quot;").replace(/'/g,"&#x27;").replace(/\//g,"&#x2F;")
      .slice(0, maxLen);
  },
};

/** Solo valida formatos de datos de dominio */
const Validator = {
  score:    (s) => { const n = parseInt(s); return !isNaN(n) && n >= 0 && n <= 30; },
  username: (u) => /^[a-zA-Z0-9_]{3,20}$/.test(u),
  password: (p) => typeof p === "string" && p.length >= 4 && p.length <= 50,
  role:     (r) => ["admin","user"].includes(r),
  slot:     (s) => s === "away" ? "away" : "home",
};

/** Solo gestiona tokens JWT en memoria (A07 OWASP) */
const TokenService = {
  generate: (userId) => {
    const p = { userId, exp: Date.now() + 3600000, iat: Date.now() };
    return btoa(JSON.stringify(p)) + "." + Math.random().toString(36).slice(2);
  },
  verify: (token) => {
    try {
      const p = JSON.parse(atob(token.split(".")[0]));
      return p.exp > Date.now() ? p : null;
    } catch { return null; }
  },
};

/** Solo hashea contraseñas (A02 OWASP) */
const PasswordService = {
  hash: async (pwd) => {
    const data = new TextEncoder().encode(pwd + "sc_salt_2024");
    const buf  = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
  },
  /** Contraseña demo: acepta cualquier texto */
  isDemoHash: (hash) => hash === "demo_hash",
};

/** Solo controla la tasa de intentos (A07 OWASP) */
const RateLimiter = {
  _store: {},
  check: (key, max = 5, windowMs = 60000) => {
    const now = Date.now();
    RateLimiter._store[key] = (RateLimiter._store[key] || []).filter(t => now - t < windowMs);
    if (RateLimiter._store[key].length >= max) return false;
    RateLimiter._store[key].push(now);
    return true;
  },
};

// ─────────────────────────────────────────────────────────────
// O — OPEN/CLOSED  +  D — DEPENDENCY INVERSION
// StorageAdapter es la abstracción (interfaz).
// WindowStorageAdapter y LocalStorageAdapter son implementaciones
// intercambiables sin modificar el código que las usa.
// Agregar un nuevo backend (IndexedDB, Redis, etc.) = nueva clase,
// sin tocar nada más.
// ─────────────────────────────────────────────────────────────

/** Contrato: cualquier implementación debe cumplir get/set con T|null */
const StorageAdapterContract = {
  get: async (key) => { throw new Error("Not implemented"); },   // → T | null
  set: async (key, value) => { throw new Error("Not implemented"); }, // → boolean
};

/** Implementación para el artifact de Claude (window.storage) */
const WindowStorageAdapter = {
  isAvailable: () => {
    try { return typeof window.storage !== "undefined" && typeof window.storage.get === "function"; }
    catch { return false; }
  },
  get: async (key) => {
    try { const r = await window.storage.get(key); return r ? JSON.parse(r.value) : null; }
    catch { return null; }
  },
  set: async (key, value) => {
    try { await window.storage.set(key, JSON.stringify(value)); return true; }
    catch { return false; }
  },
};

/** Implementación para entorno web estándar (localStorage) */
const LocalStorageAdapter = {
  isAvailable: () => {
    try { return typeof localStorage !== "undefined"; }
    catch { return false; }
  },
  get: async (key) => {
    try { const raw = localStorage.getItem("sc:" + key); return raw ? JSON.parse(raw) : null; }
    catch { return null; }
  },
  set: async (key, value) => {
    try { localStorage.setItem("sc:" + key, JSON.stringify(value)); return true; }
    catch { return false; }
  },
};

/**
 * StorageAdapterFactory — O/C: para agregar un nuevo backend
 * solo se registra aquí, sin modificar ningún consumer.
 */
const StorageAdapterFactory = {
  _adapters: [WindowStorageAdapter, LocalStorageAdapter],
  resolve: () => StorageAdapterFactory._adapters.find(a => a.isAvailable()) || LocalStorageAdapter,
};

// La instancia resuelta una sola vez al arrancar
const storage = StorageAdapterFactory.resolve();

// ─────────────────────────────────────────────────────────────
// S — SINGLE RESPONSIBILITY (continuación)
// Un Repository por entidad. Cada uno sabe leer/escribir solo
// su propia colección — no sabe nada de lógica de negocio.
// ─────────────────────────────────────────────────────────────

const UserRepository = {
  getAll:     async ()     => (await storage.get("db:users"))       || [],
  save:       async (list) => storage.set("db:users", list),
  findById:   async (id)   => { const l = await UserRepository.getAll(); return l.find(u => u.id === id) || null; },
  findByName: async (name) => { const l = await UserRepository.getAll(); return l.find(u => u.username === name) || null; },
};

const TournamentRepository = {
  getAll:   async ()     => (await storage.get("db:tournaments")) || [],
  save:     async (list) => storage.set("db:tournaments", list),
  findById: async (id)   => { const l = await TournamentRepository.getAll(); return l.find(t => t.id === id) || null; },
};

const MatchRepository = {
  getAll:   async (tId)  => (await storage.get("db:matches:" + tId))     || [],
  save:     async (tId, list) => storage.set("db:matches:" + tId, list),
  findById: async (tId, id)   => { const l = await MatchRepository.getAll(tId); return l.find(m => m.id === id) || null; },
};

const PredictionRepository = {
  getAll:    async (tId)             => (await storage.get("db:predictions:" + tId)) || [],
  save:      async (tId, list)       => storage.set("db:predictions:" + tId, list),
  findByUser: async (tId, userId)    => { const l = await PredictionRepository.getAll(tId); return l.filter(p => p.userId === userId); },
  findByMatch: async (tId, matchId)  => { const l = await PredictionRepository.getAll(tId); return l.filter(p => p.matchId === matchId); },
};

const LeaderboardRepository = {
  get:    async (tId)       => (await storage.get("db:leaderboard:" + tId)) || {},
  save:   async (tId, map)  => storage.set("db:leaderboard:" + tId, map),
  addPoints: async (tId, userId, pts) => {
    const map = await LeaderboardRepository.get(tId);
    map[userId] = (map[userId] || 0) + pts;
    return LeaderboardRepository.save(tId, map);
  },
};

const InvitationRepository = {
  getAll:    async ()     => (await storage.get("db:invitations")) || [],
  save:      async (list) => storage.set("db:invitations", list),
  findByCode: async (code) => { const l = await InvitationRepository.getAll(); return l.find(i => i.code === code && i.status === "pending") || null; },
  findById:  async (id)   => { const l = await InvitationRepository.getAll(); return l.find(i => i.id === id) || null; },
};

const AuditRepository = {
  MAX_ENTRIES: 300,
  log: async (userId, action, details) => {
    const entries = (await storage.get("db:audit")) || [];
    entries.push({ ts: new Date().toISOString(), userId, action, details });
    if (entries.length > AuditRepository.MAX_ENTRIES)
      entries.splice(0, entries.length - AuditRepository.MAX_ENTRIES);
    await storage.set("db:audit", entries);
  },
};

// ─────────────────────────────────────────────────────────────
// O — OPEN/CLOSED
// PropagationStrategy: agregar nueva estrategia = nueva entrada
// en el array, sin modificar el dispatcher.
// ─────────────────────────────────────────────────────────────

/** Estrategia dinámica: el partido tiene nextMatchWinnerId explícito */
const DynamicPropagationStrategy = {
  canHandle: (match) => !!match.nextMatchWinnerId,
  propagate: async (tId, match, winner, loser) => {
    const matches = await MatchRepository.getAll(tId);
    let changed = false;
    const apply = (targetId, slot, team) => {
      const idx = matches.findIndex(m => m.id === targetId);
      if (idx < 0) return;
      matches[idx][slot === "away" ? "awayTeam" : "homeTeam"] = team;
      changed = true;
    };
    if (match.nextMatchWinnerId)
      apply(match.nextMatchWinnerId, match.nextMatchWinnerSlot || "home", winner);
    if (match.nextMatchLoserId)
      apply(match.nextMatchLoserId,  match.nextMatchLoserSlot  || "home", loser);
    if (changed) await MatchRepository.save(tId, matches);
  },
};

/** Estrategia legado: mapa estático para el Mundial 2026 */
const LegacyFifaPropagationStrategy = {
  KNOCKOUT_STAGES: ["Ronda de 32","Octavos de final","Cuartos de final","Semifinal"],
  WINNER_SLOTS: {
    "r32_1":"TBD:Gan. R32-1","r32_2":"TBD:Gan. R32-2","r32_3":"TBD:Gan. R32-3","r32_4":"TBD:Gan. R32-4",
    "r32_5":"TBD:Gan. R32-5","r32_6":"TBD:Gan. R32-6","r32_7":"TBD:Gan. R32-7","r32_8":"TBD:Gan. R32-8",
    "r32_9":"TBD:Gan. R32-9","r32_10":"TBD:Gan. R32-10","r32_11":"TBD:Gan. R32-11","r32_12":"TBD:Gan. R32-12",
    "r32_13":"TBD:Gan. R32-13","r32_14":"TBD:Gan. R32-14","r32_15":"TBD:Gan. R32-15","r32_16":"TBD:Gan. R32-16",
    "r16_1":"TBD:Gan. Oct-1","r16_2":"TBD:Gan. Oct-2","r16_3":"TBD:Gan. Oct-3","r16_4":"TBD:Gan. Oct-4",
    "r16_5":"TBD:Gan. Oct-5","r16_6":"TBD:Gan. Oct-6","r16_7":"TBD:Gan. Oct-7","r16_8":"TBD:Gan. Oct-8",
    "qf1":"TBD:Gan. CF-1","qf2":"TBD:Gan. CF-2","qf3":"TBD:Gan. CF-3","qf4":"TBD:Gan. CF-4",
    "sf1":"TBD:Gan. SF-1","sf2":"TBD:Gan. SF-2",
  },
  LOSER_SLOTS: { "sf1":"TBD:Per. SF-1","sf2":"TBD:Per. SF-2" },
  canHandle: (match) => LegacyFifaPropagationStrategy.KNOCKOUT_STAGES.includes(match.stage),
  propagate: async (tId, match, winner, loser) => {
    const matches  = await MatchRepository.getAll(tId);
    const winSlot  = LegacyFifaPropagationStrategy.WINNER_SLOTS[match.id];
    const loseSlot = LegacyFifaPropagationStrategy.LOSER_SLOTS[match.id];
    let changed = false;
    for (const m of matches) {
      if (winSlot  && m.homeTeam === winSlot)  { m.homeTeam = winner; changed = true; }
      if (winSlot  && m.awayTeam === winSlot)  { m.awayTeam = winner; changed = true; }
      if (loseSlot && m.homeTeam === loseSlot) { m.homeTeam = loser;  changed = true; }
      if (loseSlot && m.awayTeam === loseSlot) { m.awayTeam = loser;  changed = true; }
    }
    if (changed) await MatchRepository.save(tId, matches);
  },
};

/** Dispatcher: prueba estrategias en orden, usa la primera que aplique */
const PropagationDispatcher = {
  _strategies: [DynamicPropagationStrategy, LegacyFifaPropagationStrategy],
  dispatch: async (tId, match, homeScore, awayScore) => {
    const winner = homeScore > awayScore ? match.homeTeam : match.awayTeam;
    const loser  = homeScore > awayScore ? match.awayTeam : match.homeTeam;
    const strategy = PropagationDispatcher._strategies.find(s => s.canHandle(match));
    if (strategy) await strategy.propagate(tId, match, winner, loser);
  },
};

// ─────────────────────────────────────────────────────────────
// S — SINGLE RESPONSIBILITY (servicios de dominio)
// I — INTERFACE SEGREGATION
// Cada servicio expone solo los métodos relevantes a su dominio.
// Los componentes importan solo el servicio que necesitan.
// D — DEPENDENCY INVERSION
// Los servicios reciben sus dependencias (repos, validators)
// como parámetros — no las instancian ellos mismos.
// ─────────────────────────────────────────────────────────────

/** Solo autentica usuarios */
const AuthService = {
  login: async (username, password) => {
    if (!RateLimiter.check("login:" + username, 5, 60000))
      return { error: "Demasiados intentos. Esperá 60s." };
    const user = await UserRepository.findByName(Sanitizer.clean(username));
    if (!user)          return { error: "Credenciales inválidas" };
    if (!user.active)   return { error: "Tu cuenta está desactivada." };
    if (!PasswordService.isDemoHash(user.passwordHash)) {
      const hash = await PasswordService.hash(password || "");
      if (hash !== user.passwordHash) return { error: "Credenciales inválidas" };
    }
    const token = TokenService.generate(user.id);
    await AuditRepository.log(user.id, "LOGIN", { username });
    return { token, user: { id: user.id, username: user.username, role: user.role, avatar: user.avatar } };
  },
  /** Verifica que el token pertenece a un admin activo */
  requireAdmin: async (token) => {
    const payload = TokenService.verify(token);
    if (!payload) return null;
    const user = await UserRepository.findById(payload.userId);
    return user?.role === "admin" && user.active ? user : null;
  },
};

/** Solo gestiona usuarios */
const UserService = {
  getAll: async (token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    const users = await UserRepository.getAll();
    // L — Liskov: siempre retorna la misma forma, nunca undefined
    return { success: true, users: users.map(u => ({
      id: u.id, username: u.username, role: u.role,
      avatar: u.avatar, active: u.active, createdAt: u.createdAt,
      invitedByName: u.invitedByName,
    }))};
  },
  create: async (data, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    if (!Validator.username(data.username)) return { error: "Usuario inválido (3-20 chars, letras/números/_)" };
    if (!Validator.password(data.password || "")) return { error: "Contraseña mínimo 4 caracteres" };
    const users = await UserRepository.getAll();
    if (users.find(u => u.username.toLowerCase() === data.username.toLowerCase()))
      return { error: "Ese nombre de usuario ya existe" };
    const newUser = {
      id: "u_" + Date.now(),
      username: Sanitizer.clean(data.username),
      passwordHash: await PasswordService.hash(data.password),
      role: Validator.role(data.role) ? data.role : "user",
      avatar: AVATARS.includes(data.avatar) ? data.avatar : "⚽",
      active: true,
      createdAt: new Date().toISOString().split("T")[0],
    };
    await UserRepository.save([...users, newUser]);
    await AuditRepository.log("admin", "CREATE_USER", { username: newUser.username });
    return { success: true, user: { id: newUser.id, username: newUser.username, role: newUser.role, avatar: newUser.avatar, active: newUser.active, createdAt: newUser.createdAt } };
  },
  update: async (userId, fields, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    const users = await UserRepository.getAll();
    const idx = users.findIndex(u => u.id === userId);
    if (idx < 0) return { error: "Usuario no encontrado" };
    if (users[idx].id === "u1" && fields.role && fields.role !== "admin")
      return { error: "No se puede cambiar el rol del admin principal" };
    if (Validator.role(fields.role))             users[idx].role   = fields.role;
    if (fields.active !== undefined)             users[idx].active = Boolean(fields.active);
    if (AVATARS.includes(fields.avatar))         users[idx].avatar = fields.avatar;
    if (fields.password && Validator.password(fields.password))
      users[idx].passwordHash = await PasswordService.hash(fields.password);
    await UserRepository.save(users);
    await AuditRepository.log("admin", "UPDATE_USER", { userId, fields: Object.keys(fields) });
    return { success: true, user: { id: users[idx].id, username: users[idx].username, role: users[idx].role, avatar: users[idx].avatar, active: users[idx].active } };
  },
  remove: async (userId, requesterId, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    if (userId === "u1")       return { error: "No se puede eliminar el admin principal" };
    if (userId === requesterId) return { error: "No podés eliminarte a vos mismo" };
    const users = await UserRepository.getAll();
    const filtered = users.filter(u => u.id !== userId);
    if (filtered.length === users.length) return { error: "Usuario no encontrado" };
    await UserRepository.save(filtered);
    await AuditRepository.log(requesterId, "DELETE_USER", { userId });
    return { success: true };
  },
};

/** Solo gestiona torneos */
const TournamentService = {
  getAll:   async ()       => TournamentRepository.getAll(),
  findById: async (tId)    => TournamentRepository.findById(tId),
  create: async (data, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    if (!data.name || !data.startDate || !data.endDate) return { error: "Nombre y fechas requeridos" };
    const tId = "t_" + Date.now();
    const groups = (data.groups || "").split(",").map(g => g.trim().toUpperCase()).filter(Boolean);
    const tournament = {
      id: tId,
      name:      Sanitizer.clean(data.name),
      shortName: Sanitizer.clean(data.shortName || data.name.split(" ").slice(-2).join(" ")),
      region:    Sanitizer.clean(data.region || "Global"),
      status:    ["upcoming","active","finished"].includes(data.status) ? data.status : "upcoming",
      logo:      ["🌍","🌎","🌏","⚽","🏆","⭐","🥇","🎯"].includes(data.logo) ? data.logo : "🏆",
      startDate: Sanitizer.clean(data.startDate),
      endDate:   Sanitizer.clean(data.endDate),
      groups:    groups.length ? groups : ["A","B","C","D"],
      source:    data.source || "manual",
      fifaCompId:    data.fifaCompId   || null,
      fifaSeasonId:  data.fifaSeasonId || null,
    };
    const list = await TournamentRepository.getAll();
    await TournamentRepository.save([...list, tournament]);
    // Inicializar colecciones relacionadas
    await MatchRepository.save(tId, []);
    await storage.set("db:predictions:" + tId, []);
    await LeaderboardRepository.save(tId, {});
    await AuditRepository.log("admin", "CREATE_TOURNAMENT", { tId, name: tournament.name });
    return { success: true, tournament };
  },
  update: async (tId, fields, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    const list = await TournamentRepository.getAll();
    const idx  = list.findIndex(t => t.id === tId);
    if (idx < 0) return { error: "Torneo no encontrado" };
    const allowed = ["status","name","startDate","endDate","region"];
    for (const k of allowed)
      if (fields[k] !== undefined) list[idx][k] = Sanitizer.clean(String(fields[k]));
    await TournamentRepository.save(list);
    await AuditRepository.log("admin", "UPDATE_TOURNAMENT", { tId, ...fields });
    return { success: true, tournament: list[idx] };
  },
  remove: async (tId, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    if (tId === "t1") return { error: "No se puede eliminar el torneo base" };
    const list     = await TournamentRepository.getAll();
    const filtered = list.filter(t => t.id !== tId);
    if (filtered.length === list.length) return { error: "Torneo no encontrado" };
    await TournamentRepository.save(filtered);
    await AuditRepository.log("admin", "DELETE_TOURNAMENT", { tId });
    return { success: true };
  },
};

/** Solo gestiona partidos */
const MatchService = {
  getForUser: async (tId, userId) => {
    const matches = await MatchRepository.getAll(tId);
    const preds   = await PredictionRepository.getAll(tId);
    return matches.map(m => ({
      ...m,
      myPrediction: preds.find(p => p.matchId === m.id && p.userId === userId) || null,
    }));
  },
  add: async (tId, data, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    if (!data.homeTeam || !data.awayTeam) return { error: "Equipos requeridos" };
    const match = {
      id: "m_" + Date.now(), tId,
      group:    Sanitizer.clean(data.group || "A"),
      stage:    Sanitizer.clean(data.stage || "Grupo " + data.group),
      homeTeam: Sanitizer.clean(data.homeTeam),
      awayTeam: Sanitizer.clean(data.awayTeam),
      date:     Sanitizer.clean(data.date || ""),
      time:     Sanitizer.clean(data.time || "18:00"),
      homeScore: null, awayScore: null, status: "upcoming",
      ...(data.nextMatchWinnerId   && { nextMatchWinnerId:   Sanitizer.clean(data.nextMatchWinnerId) }),
      ...(data.nextMatchWinnerSlot && { nextMatchWinnerSlot: Validator.slot(data.nextMatchWinnerSlot) }),
      ...(data.nextMatchLoserId    && { nextMatchLoserId:    Sanitizer.clean(data.nextMatchLoserId) }),
      ...(data.nextMatchLoserSlot  && { nextMatchLoserSlot:  Validator.slot(data.nextMatchLoserSlot) }),
    };
    const matches = await MatchRepository.getAll(tId);
    await MatchRepository.save(tId, [...matches, match]);
    await AuditRepository.log("admin", "ADD_MATCH", { tId, matchId: match.id });
    return { success: true, match };
  },
  setResult: async (tId, matchId, homeScore, awayScore, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    if (!Validator.score(homeScore) || !Validator.score(awayScore)) return { error: "Marcador inválido" };
    const matches = await MatchRepository.getAll(tId);
    const idx     = matches.findIndex(m => m.id === matchId);
    if (idx < 0) return { error: "Partido no encontrado" };
    matches[idx] = { ...matches[idx], homeScore: parseInt(homeScore), awayScore: parseInt(awayScore), status: "finished" };
    await MatchRepository.save(tId, matches);
    await PointsCalculator.recalculate(tId, matchId, parseInt(homeScore), parseInt(awayScore));
    await PropagationDispatcher.dispatch(tId, matches[idx], parseInt(homeScore), parseInt(awayScore));
    await AuditRepository.log("admin", "SET_RESULT", { tId, matchId, homeScore, awayScore });
    return { success: true };
  },
  importFromFIFA: async (tId, idCompetition, idSeason, token, fifaClient) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    // D — Dependency Inversion: fifaClient es inyectado, no hardcodeado
    const result = await fifaClient.getMatches(idCompetition, idSeason);
    if (result.error) return { error: "FIFA API: " + result.error, corsBlocked: true };
    const matches = (result.Results || []).map(m => fifaClient.transformMatch(m, tId));
    if (!matches.length) return { error: "Sin partidos" };
    await MatchRepository.save(tId, matches);
    await AuditRepository.log("admin", "IMPORT_FIFA", { tId, count: matches.length });
    return { success: true, count: matches.length };
  },
};

/** Solo calcula puntos — responsabilidad única de scoring */
const PointsCalculator = {
  calcPts: (pred, realHome, realAway) => {
    if (pred.homeScore === realHome && pred.awayScore === realAway) return 3;
    const pW = pred.homeScore > pred.awayScore, rW = realHome > realAway;
    const pD = pred.homeScore === pred.awayScore, rD = realHome === realAway;
    const pA = pred.homeScore < pred.awayScore, rA = realHome < realAway;
    return (pW&&rW)||(pD&&rD)||(pA&&rA) ? 1 : 0;
  },
  recalculate: async (tId, matchId, realHome, realAway) => {
    const preds = await PredictionRepository.getAll(tId);
    const lb    = await LeaderboardRepository.get(tId);
    for (const p of preds) {
      if (p.matchId !== matchId) continue;
      p.points = PointsCalculator.calcPts(p, realHome, realAway);
      lb[p.userId] = (lb[p.userId] || 0) + p.points;
    }
    await PredictionRepository.save(tId, preds);
    await LeaderboardRepository.save(tId, lb);
  },
};

/** Solo gestiona predicciones de usuarios */
const PredictionService = {
  save: async (userId, tId, matchId, homeScore, awayScore) => {
    if (!Validator.score(homeScore) || !Validator.score(awayScore)) return { error: "Marcador inválido" };
    const match = await MatchRepository.findById(tId, matchId);
    if (!match || match.status === "finished") return { error: "No se puede pronosticar" };
    const preds = await PredictionRepository.getAll(tId);
    const idx   = preds.findIndex(p => p.matchId === matchId && p.userId === userId);
    const pred  = { id: "p_" + Date.now(), userId, matchId, tId,
                    homeScore: parseInt(homeScore), awayScore: parseInt(awayScore),
                    createdAt: new Date().toISOString(), points: 0 };
    if (idx >= 0) preds[idx] = pred; else preds.push(pred);
    await PredictionRepository.save(tId, preds);
    await AuditRepository.log(userId, "PREDICT", { tId, matchId, homeScore, awayScore });
    return { success: true, prediction: pred };
  },
};

/** Solo gestiona el ranking */
const LeaderboardService = {
  get: async (tId) => {
    const users = await UserRepository.getAll();
    const preds = await PredictionRepository.getAll(tId);
    const lb    = await LeaderboardRepository.get(tId);
    return users
      .filter(u => u.role === "user" && u.active)
      .map(u => ({
        ...u,
        points:      lb[u.id] || 0,
        predictions: preds.filter(p => p.userId === u.id).length,
        exact:       preds.filter(p => p.userId === u.id && p.points === 3).length,
      }))
      .sort((a, b) => b.points - a.points || b.predictions - a.predictions);
  },
  getForUser: async (userId, tId) => {
    const lb = await LeaderboardRepository.get(tId);
    return lb[userId] || 0;
  },
};

/** Solo gestiona el flujo de invitaciones */
const InvitationService = {
  create: async (userId, tId) => {
    const inviter = await UserRepository.findById(userId);
    if (!inviter?.active) return { error: "Usuario no encontrado" };
    const tournament = await TournamentRepository.findById(tId);
    if (!tournament) return { error: "Torneo no encontrado" };
    const all = await InvitationRepository.getAll();
    if (all.filter(i => i.invitedBy === userId && i.status === "pending").length >= 5)
      return { error: "Límite de 5 invitaciones activas por usuario" };
    const code = (Math.random().toString(36).slice(2,6) + Math.random().toString(36).slice(2,6)).toUpperCase();
    const inv  = { id: "inv_" + Date.now(), code, tId, tName: tournament.name,
                   invitedBy: userId, invitedByName: inviter.username,
                   status: "pending", newUsername: null, newPasswordHash: null, newAvatar: null,
                   createdAt: new Date().toISOString(), resolvedAt: null };
    await InvitationRepository.save([...all, inv]);
    await AuditRepository.log(userId, "CREATE_INVITATION", { code, tId });
    return { success: true, invitation: inv };
  },
  registerWithCode: async (code, username, password, avatar) => {
    if (!RateLimiter.check("reg:" + code, 5, 300000))
      return { error: "Demasiados intentos. Esperá 5 minutos." };
    const inv = await InvitationRepository.findByCode(code.toUpperCase().trim());
    if (!inv) return { error: "Código inválido o ya utilizado" };
    if (!Validator.username(username)) return { error: "Usuario inválido (3-20 chars)" };
    if (!Validator.password(password)) return { error: "Contraseña mínimo 4 caracteres" };
    const users = await UserRepository.getAll();
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase()))
      return { error: "Ese nombre de usuario ya existe" };
    const all = await InvitationRepository.getAll();
    const idx = all.findIndex(i => i.id === inv.id);
    all[idx] = { ...inv, status: "registered",
                 newUsername: Sanitizer.clean(username),
                 newPasswordHash: await PasswordService.hash(password),
                 newAvatar: AVATARS.includes(avatar) ? avatar : "⚽" };
    await InvitationRepository.save(all);
    await AuditRepository.log("anon", "REGISTER_WITH_CODE", { code, username });
    return { success: true, invitation: all[idx] };
  },
  getAll: async (token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    return { success: true, invitations: await InvitationRepository.getAll() };
  },
  getForUser: async (userId) => {
    const all = await InvitationRepository.getAll();
    return all.filter(i => i.invitedBy === userId);
  },
  approve: async (invId, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    const all = await InvitationRepository.getAll();
    const idx = all.findIndex(i => i.id === invId && i.status === "registered");
    if (idx < 0) return { error: "Invitación no encontrada o en estado incorrecto" };
    const inv   = all[idx];
    const users = await UserRepository.getAll();
    if (users.find(u => u.username.toLowerCase() === inv.newUsername.toLowerCase()))
      return { error: "El nombre de usuario ya fue tomado" };
    const newUser = { id: "u_" + Date.now(), username: inv.newUsername,
                      passwordHash: inv.newPasswordHash, role: "user",
                      avatar: inv.newAvatar, active: true,
                      createdAt: new Date().toISOString().split("T")[0],
                      invitedBy: inv.invitedBy, invitedByName: inv.invitedByName };
    await UserRepository.save([...users, newUser]);
    all[idx] = { ...inv, status: "approved", resolvedAt: new Date().toISOString() };
    await InvitationRepository.save(all);
    await AuditRepository.log("admin", "APPROVE_INVITATION", { invId, username: inv.newUsername });
    return { success: true, user: newUser };
  },
  reject: async (invId, token) => {
    if (!await AuthService.requireAdmin(token)) return { error: "Acceso denegado (A01)" };
    const all = await InvitationRepository.getAll();
    const idx = all.findIndex(i => i.id === invId && ["pending","registered"].includes(i.status));
    if (idx < 0) return { error: "Invitación no encontrada" };
    all[idx] = { ...all[idx], status: "rejected", resolvedAt: new Date().toISOString() };
    await InvitationRepository.save(all);
    await AuditRepository.log("admin", "REJECT_INVITATION", { invId });
    return { success: true };
  },
  cancel: async (invId, userId) => {
    const all = await InvitationRepository.getAll();
    const idx = all.findIndex(i => i.id === invId && i.invitedBy === userId && i.status === "pending");
    if (idx < 0) return { error: "Invitación no encontrada" };
    all[idx] = { ...all[idx], status: "rejected", resolvedAt: new Date().toISOString() };
    await InvitationRepository.save(all);
    await AuditRepository.log(userId, "CANCEL_INVITATION", { invId });
    return { success: true };
  },
};

// ─────────────────────────────────────────────────────────────
// D — DEPENDENCY INVERSION
// ServiceContext inyecta los servicios vía React Context.
// Los componentes consumen el contexto — no dependen de globals.
// Para tests: proveer mocks en el Provider.
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
// D — DEPENDENCY INVERSION (continuación)
// ServiceContext — los componentes reciben servicios via contexto
// en lugar de importarlos directamente (no dependen de globals).
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
// S — GRUPOS PRIVADOS
// Schema:
//   db:groups       → Group[]       { id, name, tournamentId, ownerId, ownerName, code, createdAt }
//   db:memberships  → Membership[]  { id, groupId, userId, role:"owner"|"member", joinedAt }
// El ranking de cada grupo filtra los miembros sobre las
// predicciones globales del torneo — sin duplicar datos.
// ─────────────────────────────────────────────────────────────

const GroupRepository = {
  getAll:     async ()      => (await storage.get("db:groups")) || [],
  save:       async (list)  => storage.set("db:groups", list),
  findById:   async (id)    => { const l = await GroupRepository.getAll(); return l.find(g => g.id === id) || null; },
  findByCode: async (code)  => { const l = await GroupRepository.getAll(); return l.find(g => g.code === code) || null; },
};

const MembershipRepository = {
  getAll:      async ()         => (await storage.get("db:memberships")) || [],
  save:        async (list)     => storage.set("db:memberships", list),
  findByGroup: async (groupId)  => { const l = await MembershipRepository.getAll(); return l.filter(m => m.groupId === groupId); },
  findByUser:  async (userId)   => { const l = await MembershipRepository.getAll(); return l.filter(m => m.userId === userId); },
  isMember:    async (groupId, userId) => { const l = await MembershipRepository.getAll(); return !!l.find(m => m.groupId === groupId && m.userId === userId); },
};

const GroupService = {
  getForUser: async (userId) => {
    const memberships = await MembershipRepository.findByUser(userId);
    const groups      = await GroupRepository.getAll();
    const tournaments = await TournamentRepository.getAll();
    return memberships.map(mb => {
      const g = groups.find(gr => gr.id === mb.groupId);
      if (!g) return null;
      const t = tournaments.find(t => t.id === g.tournamentId);
      return { ...g, tournamentName: t?.name||"—", tournamentLogo: t?.logo||"🏆", myRole: mb.role };
    }).filter(Boolean);
  },
  create: async (userId, data) => {
    if (!data.name?.trim()) return { error: "El nombre del grupo es requerido" };
    if (!data.tournamentId) return { error: "Seleccioná un torneo base" };
    const tournament = await TournamentRepository.findById(data.tournamentId);
    if (!tournament) return { error: "Torneo no encontrado" };
    const user = await UserRepository.findById(userId);
    if (!user) return { error: "Usuario no encontrado" };
    const myMemberships = await MembershipRepository.findByUser(userId);
    if (myMemberships.filter(m => m.role === "owner").length >= 10)
      return { error: "Límite de 10 grupos propios por usuario" };
    const code    = (Math.random().toString(36).slice(2,5)+Math.random().toString(36).slice(2,5)).toUpperCase();
    const groupId = "grp_" + Date.now();
    const group   = { id: groupId, name: Sanitizer.clean(data.name, 60),
                      tournamentId: data.tournamentId, ownerId: userId,
                      ownerName: user.username, code,
                      createdAt: new Date().toISOString().split("T")[0] };
    await GroupRepository.save([...(await GroupRepository.getAll()), group]);
    await MembershipRepository.save([...(await MembershipRepository.getAll()),
      { id: "mb_"+Date.now(), groupId, userId, role: "owner", joinedAt: new Date().toISOString() }]);
    await AuditRepository.log(userId, "CREATE_GROUP", { groupId, name: group.name });
    return { success: true, group };
  },
  joinByCode: async (userId, code) => {
    const group = await GroupRepository.findByCode(code.toUpperCase().trim());
    if (!group) return { error: "Código de grupo inválido" };
    if (await MembershipRepository.isMember(group.id, userId)) return { error: "Ya sos miembro de este grupo" };
    const members = await MembershipRepository.findByGroup(group.id);
    if (members.length >= 50) return { error: "El grupo ya alcanzó el máximo de 50 miembros" };
    await MembershipRepository.save([...(await MembershipRepository.getAll()),
      { id: "mb_"+Date.now(), groupId: group.id, userId, role: "member", joinedAt: new Date().toISOString() }]);
    await AuditRepository.log(userId, "JOIN_GROUP", { groupId: group.id });
    const tournament = await TournamentRepository.findById(group.tournamentId);
    return { success: true, group: { ...group, tournamentName: tournament?.name } };
  },
  leave: async (userId, groupId) => {
    const group = await GroupRepository.findById(groupId);
    if (!group) return { error: "Grupo no encontrado" };
    if (group.ownerId === userId) return { error: "El dueño no puede abandonar el grupo. Eliminalo." };
    const all      = await MembershipRepository.getAll();
    const filtered = all.filter(m => !(m.groupId === groupId && m.userId === userId));
    if (filtered.length === all.length) return { error: "No sos miembro de este grupo" };
    await MembershipRepository.save(filtered);
    await AuditRepository.log(userId, "LEAVE_GROUP", { groupId });
    return { success: true };
  },
  remove: async (userId, groupId) => {
    const group = await GroupRepository.findById(groupId);
    if (!group) return { error: "Grupo no encontrado" };
    if (group.ownerId !== userId) return { error: "Solo el dueño puede eliminar el grupo" };
    await GroupRepository.save((await GroupRepository.getAll()).filter(g => g.id !== groupId));
    await MembershipRepository.save((await MembershipRepository.getAll()).filter(m => m.groupId !== groupId));
    await AuditRepository.log(userId, "DELETE_GROUP", { groupId });
    return { success: true };
  },
  getMembers: async (groupId, userId) => {
    if (!await MembershipRepository.isMember(groupId, userId)) return { error: "No sos miembro de este grupo" };
    const memberships = await MembershipRepository.findByGroup(groupId);
    const users       = await UserRepository.getAll();
    return { success: true, members: memberships.map(mb => {
      const u = users.find(u => u.id === mb.userId);
      return u ? { id:u.id, username:u.username, avatar:u.avatar, role:mb.role, joinedAt:mb.joinedAt } : null;
    }).filter(Boolean)};
  },
};

const GroupLeaderboardService = {
  get: async (groupId, userId) => {
    const group = await GroupRepository.findById(groupId);
    if (!group) return { error: "Grupo no encontrado" };
    if (!await MembershipRepository.isMember(groupId, userId)) return { error: "No sos miembro" };
    const memberships = await MembershipRepository.findByGroup(groupId);
    const memberIds   = memberships.map(m => m.userId);
    const users       = await UserRepository.getAll();
    const preds       = await PredictionRepository.getAll(group.tournamentId);
    const lb          = await LeaderboardRepository.get(group.tournamentId);
    return { success: true, leaderboard: users
      .filter(u => memberIds.includes(u.id) && u.active)
      .map(u => ({ id:u.id, username:u.username, avatar:u.avatar,
        role: memberships.find(m=>m.userId===u.id)?.role||"member",
        points: lb[u.id]||0,
        predictions: preds.filter(p=>p.userId===u.id).length,
        exact: preds.filter(p=>p.userId===u.id&&p.points===3).length }))
      .sort((a,b)=>b.points-a.points||b.predictions-a.predictions) };
  },
};

// ─────────────────────────────────────────────────────────────
// D — DEPENDENCY INVERSION — ServiceContext
// ─────────────────────────────────────────────────────────────

const ServiceContext = createContext(null);

const defaultServices = {
  auth:             AuthService,
  users:            UserService,
  tournaments:      TournamentService,
  matches:          MatchService,
  predictions:      PredictionService,
  leaderboard:      LeaderboardService,
  invitations:      InvitationService,
  groups:           GroupService,
  groupLeaderboard: GroupLeaderboardService,
  fifaClient:       FIFA_API,
};

const useServices = () => useContext(ServiceContext);

const DatabaseInitializer = {
  init: async () => {
    if (!(await storage.get("db:users")))          await storage.set("db:users", SEED_USERS);
    if (!(await storage.get("db:tournaments")))     await storage.set("db:tournaments", SEED_TOURNAMENTS);
    const existingMatches = await storage.get("db:matches:t1");
    if (!existingMatches || existingMatches.length < 72)
      await storage.set("db:matches:t1", SEED_MATCHES_T1);
    const tournaments = await storage.get("db:tournaments") || [];
    const t1 = tournaments.find(t => t.id === "t1");
    if (t1 && t1.groups && t1.groups.length < 12) {
      const idx = tournaments.indexOf(t1);
      tournaments[idx] = { ...SEED_TOURNAMENTS[0] };
      await storage.set("db:tournaments", tournaments);
    }
    if (!(await storage.get("db:predictions:t1"))) await storage.set("db:predictions:t1", []);
    if (!(await storage.get("db:leaderboard:t1"))) await storage.set("db:leaderboard:t1", {});
    if (!(await storage.get("db:audit")))           await storage.set("db:audit", []);
    if (!(await storage.get("db:invitations")))     await storage.set("db:invitations", []);
    if (!(await storage.get("db:groups")))          await storage.set("db:groups", []);
    if (!(await storage.get("db:memberships")))     await storage.set("db:memberships", []);
  }
};



// ============================================================
// STYLES
// ============================================================
const S=`
@import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Barlow+Condensed:wght@400;600;700&family=Barlow:wght@300;400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080c14;--sf:#0d1520;--sf2:#111d2e;--bd:#1e3048;--gold:#c9a84c;--gold2:#e8c96a;--green:#00c878;--red:#ff4444;--blue:#4a9eff;--purple:#9b59b6;--tx:#e8edf5;--tx2:#8a9ab5;--tx3:#4a5f7a}
body{background:var(--bg);color:var(--tx);font-family:'Barlow',sans-serif}
.app{min-height:100vh;background:var(--bg);position:relative;overflow-x:hidden}
.app::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 20% 0%,rgba(201,168,76,.06) 0%,transparent 60%),radial-gradient(ellipse 60% 40% at 80% 100%,rgba(74,158,255,.05) 0%,transparent 60%);pointer-events:none;z-index:0}

.loader-wrap{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:20px}
.loader-logo{font-size:72px;animation:spin 2s linear infinite}
@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
.loader-txt{font-family:'Bebas Neue',sans-serif;font-size:18px;letter-spacing:6px;color:var(--gold)}

.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;position:relative;z-index:1}
.login-card{width:100%;max-width:420px;background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.login-hdr{background:linear-gradient(135deg,#0d1520,#1a2a40);padding:44px 40px 32px;text-align:center;border-bottom:2px solid var(--gold)}
.login-logo{font-size:60px;display:block;margin-bottom:10px;filter:drop-shadow(0 0 20px rgba(201,168,76,.4))}
.login-title{font-family:'Bebas Neue',sans-serif;font-size:34px;letter-spacing:4px;color:var(--gold);line-height:1}
.login-sub{font-family:'Barlow Condensed',sans-serif;font-size:12px;letter-spacing:3px;color:var(--tx2);text-transform:uppercase;margin-top:5px}
.login-body{padding:32px 40px 36px}
.field{margin-bottom:16px}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--tx2);margin-bottom:6px;font-family:'Barlow Condensed',sans-serif;font-weight:600}
.field input,.field select,.field textarea{width:100%;background:var(--bg);border:1px solid var(--bd);border-radius:2px;padding:10px 14px;color:var(--tx);font-family:'Barlow',sans-serif;font-size:14px;outline:none;transition:border-color .2s}
.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--gold)}
.field select option{background:var(--bg)}
.btn{padding:9px 16px;border-radius:2px;border:none;cursor:pointer;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:2px;transition:all .2s;white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.btn-gold{background:var(--gold);color:#080c14}.btn-gold:hover{background:var(--gold2)}
.btn-red{background:rgba(255,68,68,.15);border:1px solid rgba(255,68,68,.3);color:#ff8888}.btn-red:hover{background:rgba(255,68,68,.25)}
.btn-blue{background:rgba(74,158,255,.15);border:1px solid rgba(74,158,255,.3);color:var(--blue)}.btn-blue:hover{background:rgba(74,158,255,.25)}
.btn-green{background:rgba(0,200,120,.15);border:1px solid rgba(0,200,120,.3);color:var(--green)}.btn-green:hover{background:rgba(0,200,120,.25)}
.btn-ghost{background:transparent;border:1px solid var(--bd);color:var(--tx2)}.btn-ghost:hover{border-color:var(--gold);color:var(--gold)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn-full{width:100%;font-size:17px;padding:13px;justify-content:center}
.demo-box{margin-top:20px;padding:14px;background:rgba(201,168,76,.05);border:1px solid rgba(201,168,76,.15);border-radius:2px}
.demo-box p{font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--tx3);margin-bottom:8px;font-family:'Barlow Condensed',sans-serif}
.demo-btn{background:transparent;border:1px solid var(--bd);color:var(--tx2);padding:5px 11px;font-size:11px;border-radius:2px;cursor:pointer;margin:2px;font-family:'Barlow',sans-serif;transition:all .2s}
.demo-btn:hover{border-color:var(--gold);color:var(--gold)}
.msg-err{background:rgba(255,68,68,.1);border:1px solid rgba(255,68,68,.3);color:#ff8888;padding:9px 13px;border-radius:2px;font-size:12px;margin-bottom:12px}
.msg-ok{background:rgba(0,200,120,.1);border:1px solid rgba(0,200,120,.3);color:var(--green);padding:9px 13px;border-radius:2px;font-size:12px;margin-bottom:12px}
.msg-warn{background:rgba(201,168,76,.1);border:1px solid rgba(201,168,76,.3);color:var(--gold);padding:9px 13px;border-radius:2px;font-size:12px;margin-bottom:12px}

.navbar{position:sticky;top:0;z-index:100;background:rgba(8,12,20,.96);backdrop-filter:blur(14px);border-bottom:1px solid var(--bd);padding:0 22px;display:flex;align-items:center;justify-content:space-between;height:56px;gap:10px}
.nav-brand{font-family:'Bebas Neue',sans-serif;font-size:18px;letter-spacing:3px;color:var(--gold);white-space:nowrap;flex-shrink:0;display:flex;align-items:center;gap:8px}
.nav-tabs{display:flex;gap:0;flex:1;justify-content:center}
.nav-tab{background:transparent;border:none;color:var(--tx2);padding:6px 13px;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;white-space:nowrap;height:56px;display:flex;align-items:center}
.nav-tab:hover{color:var(--tx)}
.nav-tab.active{color:var(--gold);border-bottom-color:var(--gold)}
.nav-right{display:flex;align-items:center;gap:8px;flex-shrink:0}
.user-badge{display:flex;align-items:center;gap:7px;background:var(--sf2);border:1px solid var(--bd);border-radius:20px;padding:3px 10px 3px 7px;font-size:12px}
.pts-chip{background:linear-gradient(135deg,var(--gold),var(--gold2));color:#080c14;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:700;font-family:'Barlow Condensed',sans-serif;letter-spacing:1px}
.admin-chip{background:rgba(255,68,68,.15);color:#ff8888;border:1px solid rgba(255,68,68,.3);padding:2px 7px;border-radius:10px;font-size:9px;letter-spacing:2px;font-family:'Barlow Condensed',sans-serif;font-weight:700;text-transform:uppercase}

.content{position:relative;z-index:1;max-width:1120px;margin:0 auto;padding:26px 20px}
.sec-title{font-family:'Bebas Neue',sans-serif;font-size:26px;letter-spacing:4px;color:var(--tx);margin-bottom:5px}
.sec-sub{color:var(--tx3);font-size:11px;letter-spacing:1px;margin-bottom:22px;font-family:'Barlow Condensed',sans-serif;text-transform:uppercase}

/* USERS TABLE */
.users-table{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.ut-hdr{display:grid;grid-template-columns:44px 1fr 90px 90px 100px 120px;align-items:center;padding:10px 18px;background:var(--sf2);border-bottom:1px solid var(--bd);font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;font-weight:600;gap:8px}
.ut-row{display:grid;grid-template-columns:44px 1fr 90px 90px 100px 120px;align-items:center;padding:12px 18px;border-bottom:1px solid var(--bd);transition:background .15s;gap:8px}
.ut-row:last-child{border-bottom:none}
.ut-row:hover{background:var(--sf2)}
.ut-avatar{font-size:22px;width:36px;height:36px;display:flex;align-items:center;justify-content:center;background:var(--sf2);border-radius:50%;border:1px solid var(--bd)}
.ut-name{font-weight:500;font-size:14px}
.ut-date{font-size:11px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif}
.role-badge{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600;width:fit-content}
.rb-admin{background:rgba(255,68,68,.15);color:#ff8888;border:1px solid rgba(255,68,68,.28)}
.rb-user{background:rgba(74,158,255,.12);color:var(--blue);border:1px solid rgba(74,158,255,.25)}
.active-badge{font-size:9px;letter-spacing:1px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600;width:fit-content}
.ab-on{background:rgba(0,200,120,.12);color:var(--green);border:1px solid rgba(0,200,120,.25)}
.ab-off{background:rgba(100,100,100,.12);color:var(--tx3);border:1px solid rgba(100,100,100,.2)}
.ut-actions{display:flex;gap:6px;flex-wrap:wrap}
.icon-btn{background:transparent;border:1px solid var(--bd);color:var(--tx2);width:28px;height:28px;border-radius:2px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:13px;transition:all .2s;flex-shrink:0}
.icon-btn:hover{border-color:var(--gold);color:var(--gold)}
.icon-btn.danger:hover{border-color:var(--red);color:#ff8888}
.icon-btn.success:hover{border-color:var(--green);color:var(--green)}

/* MODAL */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(4px);z-index:200;display:flex;align-items:center;justify-content:center;padding:16px}
.modal{background:var(--sf);border:1px solid var(--bd);border-radius:2px;width:100%;max-width:500px;max-height:92vh;overflow-y:auto}
.modal-lg{max-width:660px}
.modal-hdr{padding:18px 22px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--sf);z-index:1}
.modal-title{font-family:'Bebas Neue',sans-serif;font-size:20px;letter-spacing:3px;color:var(--tx)}
.modal-body{padding:22px}
.modal-footer{padding:14px 22px;border-top:1px solid var(--bd);display:flex;justify-content:flex-end;gap:10px;position:sticky;bottom:0;background:var(--sf)}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-grid .field{margin-bottom:0}
.form-grid .full{grid-column:span 2}

/* AVATAR PICKER */
.avatar-picker{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.av-btn{font-size:22px;width:38px;height:38px;display:flex;align-items:center;justify-content:center;background:var(--bg);border:1px solid var(--bd);border-radius:4px;cursor:pointer;transition:all .15s}
.av-btn:hover,.av-btn.sel{border-color:var(--gold);background:rgba(201,168,76,.1)}

/* LOBBY */
.t-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:13px}
.t-card{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden;cursor:pointer;transition:transform .15s,border-color .2s,box-shadow .2s}
.t-card:hover{transform:translateY(-2px);border-color:var(--gold);box-shadow:0 6px 24px rgba(201,168,76,.1)}
.t-card-top{padding:18px;display:flex;gap:13px;align-items:center;border-bottom:1px solid var(--bd)}
.t-card-logo{font-size:36px;width:56px;height:56px;display:flex;align-items:center;justify-content:center;background:var(--sf2);border-radius:2px;flex-shrink:0}
.t-card-name{font-family:'Bebas Neue',sans-serif;font-size:17px;letter-spacing:2px;line-height:1.2}
.t-card-meta{font-size:10px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px;margin-top:3px}
.t-card-bot{padding:11px 18px;display:flex;align-items:center;justify-content:space-between}
.source-chip{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600}
.src-manual{background:rgba(74,158,255,.12);color:var(--blue);border:1px solid rgba(74,158,255,.25)}
.src-fifa{background:rgba(201,168,76,.12);color:var(--gold);border:1px solid rgba(201,168,76,.25)}
.status-badge{font-size:9px;letter-spacing:2px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 9px;border-radius:8px;font-weight:600}
.s-up{background:rgba(201,168,76,.15);color:var(--gold);border:1px solid rgba(201,168,76,.3)}
.s-act{background:rgba(0,200,120,.15);color:var(--green);border:1px solid rgba(0,200,120,.3)}
.s-fin{background:rgba(100,100,100,.12);color:var(--tx3);border:1px solid rgba(100,100,100,.25)}

/* CREATE TOURNAMENT MODAL EXTRAS */
.tab-switcher{display:flex;gap:0;margin-bottom:18px;border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.tab-sw-btn{flex:1;background:transparent;border:none;color:var(--tx2);padding:8px;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:all .2s;border-right:1px solid var(--bd)}
.tab-sw-btn:last-child{border-right:none}
.tab-sw-btn.active{background:var(--gold);color:#080c14;font-weight:700}
.fifa-sec{background:var(--sf2);border:1px solid var(--bd);border-radius:2px;padding:16px;margin-bottom:14px}
.fifa-sec-title{font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--gold);margin-bottom:10px}
.comp-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:7px;margin-bottom:12px}
.comp-btn{background:var(--bg);border:1px solid var(--bd);color:var(--tx2);padding:7px 10px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:1px;transition:all .2s;text-align:left}
.comp-btn:hover,.comp-btn.sel{border-color:var(--gold);color:var(--gold);background:rgba(201,168,76,.08)}
.search-results{max-height:180px;overflow-y:auto;border:1px solid var(--bd);border-radius:2px;margin-top:8px}
.sri{padding:9px 13px;border-bottom:1px solid var(--bd);cursor:pointer;transition:background .15s;display:flex;align-items:center;justify-content:space-between}
.sri:last-child{border-bottom:none}
.sri:hover{background:var(--sf2)}
.cors-box{background:rgba(255,68,68,.07);border:1px solid rgba(255,68,68,.2);border-radius:2px;padding:13px;margin-top:12px}
.cors-title{font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#ff8888;margin-bottom:7px}
.cors-code{font-size:10px;color:var(--tx2);line-height:1.9;font-family:monospace}
.cors-code code{background:rgba(255,255,255,.06);padding:1px 5px;border-radius:2px;color:var(--blue)}

/* TOURNAMENT HERO */
.t-hero{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden;margin-bottom:18px}
.t-hero-banner{background:linear-gradient(135deg,#0a1628,#162236,#0d1e35);padding:28px 32px;display:flex;align-items:center;gap:22px;border-bottom:2px solid var(--gold)}
.t-hero-logo{font-size:60px;filter:drop-shadow(0 0 18px rgba(201,168,76,.4))}
.t-hero-name{font-family:'Bebas Neue',sans-serif;font-size:28px;letter-spacing:4px;line-height:1}
.t-hero-region{font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:3px;color:var(--gold);text-transform:uppercase;margin-top:4px}
.t-hero-dates{font-size:11px;color:var(--tx2);margin-top:5px}
.t-hero-footer{padding:10px 32px;display:flex;align-items:center;gap:13px;flex-wrap:wrap}

/* ADMIN PANEL */
.admin-panel{background:var(--sf);border:1px solid rgba(255,68,68,.2);border-radius:2px;overflow:hidden;margin-top:18px}
.ap-hdr{background:rgba(255,68,68,.04);border-bottom:1px solid rgba(255,68,68,.15);padding:9px 16px;display:flex;align-items:center;gap:8px}
.ap-title{font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#ff8888;display:flex;align-items:center;gap:6px}
.ap-body{padding:14px 16px}
.ap-tabs{display:flex;gap:5px;margin-bottom:14px;flex-wrap:wrap}
.ap-tab{background:transparent;border:1px solid var(--bd);color:var(--tx3);padding:4px 11px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;transition:all .2s}
.ap-tab.active{border-color:#ff8888;color:#ff8888;background:rgba(255,68,68,.08)}
.ap-form{display:flex;gap:9px;flex-wrap:wrap;align-items:flex-end}
.ap-label{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;display:block;margin-bottom:4px}
.ap-input,.ap-select{background:var(--bg);border:1px solid var(--bd);border-radius:2px;color:var(--tx);padding:6px 10px;font-family:'Barlow',sans-serif;font-size:12px;outline:none;transition:border-color .2s}
.ap-input:focus,.ap-select:focus{border-color:#ff8888}
.mfg{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-bottom:10px}
.mfg .afield{grid-column:span 1}.mfg .afield.full{grid-column:span 2}
.afield{display:flex;flex-direction:column}

/* GROUPS */
.groups-nav{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:16px}
.group-btn{background:var(--sf);border:1px solid var(--bd);color:var(--tx2);padding:5px 12px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;transition:all .2s}
.group-btn:hover,.group-btn.active{background:var(--gold);color:#080c14;border-color:var(--gold);font-weight:700}

/* MATCHES */
.matches-list{display:flex;flex-direction:column;gap:8px}
.match-card{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden;transition:border-color .2s}
.match-card:hover{border-color:rgba(201,168,76,.3)}
.match-hdr{padding:6px 16px;background:var(--sf2);border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif}

/* Desktop: Local — Marcador — Visitante en una sola fila */
.match-body{padding:14px 16px;display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:12px}
.team{font-family:'Barlow Condensed',sans-serif;font-size:13px;font-weight:600;letter-spacing:1px;line-height:1.3}
.team.home{text-align:right}
.team.away{text-align:left}
.match-center{display:contents}

/* Mobile: reorganiza en dos filas
   Fila 1: [Local vs Visitante] — los nombres separados a los extremos
   Fila 2: [input] — [input] centrados                                */
@media(max-width:600px){
  .match-body{
    display:flex;
    flex-wrap:wrap;
    align-items:center;
    gap:6px 4px;
    padding:12px 14px;
  }
  /* Nombres ocupan la primera fila completa */
  .team.home{order:1;flex:1;text-align:left}
  .team.away{order:2;flex:1;text-align:right}
  /* Centro (inputs/score) ocupa la segunda fila completa */
  .match-center{display:block;order:3;width:100%;flex-basis:100%}
}

.score-fin{display:flex;align-items:center;gap:7px;font-family:'Bebas Neue',sans-serif;font-size:24px;color:var(--gold);justify-content:center;min-width:64px}
.score-sep{color:var(--tx3);font-size:17px}
.score-row{display:flex;align-items:center;gap:6px;justify-content:center}
.sinput{width:46px;height:46px;background:var(--bg);border:2px solid var(--bd);border-radius:2px;color:var(--tx);font-family:'Bebas Neue',sans-serif;font-size:20px;text-align:center;outline:none;transition:border-color .2s}
.sinput:focus{border-color:var(--gold)}
.pred-btn{background:var(--gold);color:#080c14;border:none;border-radius:2px;padding:6px 12px;font-family:'Bebas Neue',sans-serif;font-size:11px;letter-spacing:2px;cursor:pointer;transition:background .2s}
.pred-btn:hover{background:var(--gold2)}.pred-btn.saved{background:var(--green);color:#fff}
.pred-btn:disabled{opacity:.45;cursor:wait}
.save-row{display:flex;justify-content:center;padding:8px 16px 12px;border-top:1px solid rgba(255,255,255,.04)}
.pred-badge{display:inline-flex;align-items:center;gap:5px;background:rgba(0,200,120,.09);border:1px solid rgba(0,200,120,.2);border-radius:2px;padding:3px 8px;font-size:10px;color:var(--green);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px}
.pts-badge{background:rgba(201,168,76,.12);border:1px solid rgba(201,168,76,.28);border-radius:2px;padding:3px 7px;font-size:10px;color:var(--gold);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px;margin-left:4px}
.admin-footer{padding:8px 16px;background:rgba(255,68,68,.03);border-top:1px solid var(--bd);display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap}
.ainput{width:38px;height:30px;background:var(--bg);border:1px solid var(--bd);border-radius:2px;color:var(--tx);font-family:'Bebas Neue',sans-serif;font-size:15px;text-align:center;outline:none;transition:border-color .2s}
.ainput:focus{border-color:#ff8888}
.ares-btn{background:rgba(255,68,68,.12);border:1px solid rgba(255,68,68,.28);color:#ff8888;padding:5px 10px;border-radius:2px;font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:all .2s}
.ares-btn:hover{background:rgba(255,68,68,.22)}.ares-btn:disabled{opacity:.45;cursor:wait}

/* LEADERBOARD */
.lb{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.lb-row{display:grid;grid-template-columns:48px 1fr 80px 64px 64px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--bd);transition:background .15s}
.lb-row:last-child{border-bottom:none}
.lb-row:hover{background:var(--sf2)}
.lb-row.hdr{background:var(--sf2);font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;font-weight:600}
.rank{font-family:'Bebas Neue',sans-serif;font-size:18px;color:var(--tx3)}
.rank.g{color:var(--gold)}.rank.s{color:#bbb}.rank.b{color:#cd7f32}
.lb-user{display:flex;align-items:center;gap:9px}
.lb-av{width:30px;height:30px;display:flex;align-items:center;justify-content:center;font-size:16px;background:var(--sf2);border-radius:50%;border:1px solid var(--bd)}
.lb-pts{font-family:'Bebas Neue',sans-serif;font-size:20px;color:var(--gold);text-align:right}
.lb-n{color:var(--tx3);font-size:11px;text-align:center}


.toast{position:fixed;bottom:20px;right:20px;background:var(--sf);border:1px solid var(--green);color:var(--green);padding:10px 15px;border-radius:2px;font-size:12px;z-index:999;animation:sIn .3s ease;font-family:'Barlow Condensed',sans-serif;letter-spacing:1px;max-width:280px}
.toast.err{border-color:var(--red);color:#ff8888}
@keyframes sIn{from{transform:translateX(110px);opacity:0}to{transform:translateX(0);opacity:1}}
.team.tbd{color:var(--tx3);font-style:italic;font-size:11px}
.tbd-match-note{text-align:center;font-size:10px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px;padding:4px 0}
.stage-sep{background:var(--sf2);border-top:2px solid var(--gold);padding:6px 18px;font-family:'Bebas Neue',sans-serif;font-size:14px;letter-spacing:3px;color:var(--gold);margin-top:8px}
details summary::-webkit-details-marker{display:none}
details[open] summary{margin-bottom:0}
.db-dot{width:5px;height:5px;border-radius:50%;background:var(--green);display:inline-block;margin-right:5px;box-shadow:0 0 5px var(--green);vertical-align:middle}
.empty{text-align:center;padding:40px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:2px;text-transform:uppercase;font-size:11px}

/* GROUPS */
.groups-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.group-card{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden;cursor:pointer;transition:transform .15s,border-color .2s,box-shadow .2s;position:relative}
.group-card:hover{transform:translateY(-2px);border-color:var(--gold);box-shadow:0 6px 20px rgba(201,168,76,.1)}
.group-card-top{padding:16px 18px;border-bottom:1px solid var(--bd)}
.group-card-name{font-family:'Bebas Neue',sans-serif;font-size:18px;letter-spacing:2px;line-height:1.2;margin-bottom:4px}
.group-card-meta{font-size:11px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px}
.group-card-bot{padding:10px 18px;display:flex;align-items:center;justify-content:space-between}
.owner-chip{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600;background:rgba(201,168,76,.12);color:var(--gold);border:1px solid rgba(201,168,76,.25)}
.member-chip{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600;background:rgba(74,158,255,.12);color:var(--blue);border:1px solid rgba(74,158,255,.25)}
.group-code-box{background:var(--bg);border:2px dashed rgba(201,168,76,.4);border-radius:4px;padding:14px;text-align:center;margin:12px 0}
.group-code{font-family:'Bebas Neue',sans-serif;font-size:32px;letter-spacing:8px;color:var(--gold);display:block;margin-bottom:4px}
.group-code-hint{font-size:10px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px}
.back-btn{background:transparent;border:1px solid var(--bd);color:var(--tx2);padding:6px 14px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;transition:all .2s}.back-btn:hover{border-color:var(--gold);color:var(--gold)}
.group-hero{background:linear-gradient(135deg,#0a1628,#1a2a40);padding:20px 22px;border-bottom:2px solid var(--gold);display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.group-hero-info{}
.group-hero-name{font-family:'Bebas Neue',sans-serif;font-size:24px;letter-spacing:3px;color:var(--tx);line-height:1}
.group-hero-sub{font-size:11px;color:var(--gold);font-family:'Barlow Condensed',sans-serif;letter-spacing:2px;text-transform:uppercase;margin-top:4px}
.group-tabs{display:flex;gap:4px;padding:10px 16px;background:var(--sf2);border-bottom:1px solid var(--bd)}
.group-tab{background:transparent;border:none;color:var(--tx3);padding:5px 12px;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s}
.group-tab.active{color:var(--gold);border-bottom-color:var(--gold)}
.members-list{display:flex;flex-direction:column;gap:6px}
.member-row{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--sf2);border-radius:2px;border:1px solid var(--bd)}
.member-av{font-size:20px;width:32px;height:32px;display:flex;align-items:center;justify-content:center;background:var(--bg);border-radius:50%;border:1px solid var(--bd);flex-shrink:0}
.member-name{font-size:13px;font-weight:500;flex:1}
.copy-code-btn{background:rgba(201,168,76,.1);border:1px solid rgba(201,168,76,.25);color:var(--gold);padding:4px 10px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:1.5px;transition:all .2s}
.copy-code-btn:hover{background:rgba(201,168,76,.2)}
.pts-info{margin-top:11px;padding:10px 13px;background:var(--sf);border:1px solid var(--bd);border-radius:2px;font-size:11px;color:var(--tx3)}
.divider{border:none;border-top:1px solid var(--bd);margin:16px 0}
.confirm-modal{text-align:center;padding:8px 0}
.confirm-modal h3{font-family:'Bebas Neue',sans-serif;font-size:22px;letter-spacing:2px;margin-bottom:10px}
.confirm-modal p{color:var(--tx2);font-size:13px;line-height:1.6}

/* INVITATIONS */
.inv-code-box{background:var(--bg);border:2px dashed var(--gold);border-radius:4px;padding:20px;text-align:center;margin:16px 0}
.inv-code{font-family:'Bebas Neue',sans-serif;font-size:40px;letter-spacing:8px;color:var(--gold);display:block;margin-bottom:6px}
.inv-code-hint{font-size:11px;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;letter-spacing:1px}
.inv-table{background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.inv-row{display:grid;grid-template-columns:1fr 110px 120px 90px 120px;align-items:center;padding:11px 18px;border-bottom:1px solid var(--bd);gap:10px;transition:background .15s}
.inv-row:last-child{border-bottom:none}
.inv-row:hover{background:var(--sf2)}
.inv-row.hdr{background:var(--sf2);font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--tx3);font-family:'Barlow Condensed',sans-serif;font-weight:600}
.inv-badge{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Barlow Condensed',sans-serif;padding:2px 8px;border-radius:8px;font-weight:600;width:fit-content}
.ib-pending{background:rgba(201,168,76,.15);color:var(--gold);border:1px solid rgba(201,168,76,.3)}
.ib-registered{background:rgba(74,158,255,.15);color:var(--blue);border:1px solid rgba(74,158,255,.3)}
.ib-approved{background:rgba(0,200,120,.12);color:var(--green);border:1px solid rgba(0,200,120,.25)}
.ib-rejected{background:rgba(100,100,100,.12);color:var(--tx3);border:1px solid rgba(100,100,100,.2)}
.notif-dot{width:8px;height:8px;border-radius:50%;background:var(--red);display:inline-block;margin-left:4px;box-shadow:0 0 6px var(--red);vertical-align:middle;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.register-card{width:100%;max-width:460px;background:var(--sf);border:1px solid var(--bd);border-radius:2px;overflow:hidden}
.reg-steps{display:flex;gap:0;border-bottom:1px solid var(--bd)}
.reg-step{flex:1;padding:12px;text-align:center;font-family:'Barlow Condensed',sans-serif;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--tx3);border-right:1px solid var(--bd);position:relative}
.reg-step:last-child{border-right:none}
.reg-step.active{color:var(--gold)}
.reg-step.done{color:var(--green)}
.reg-step-num{display:block;font-family:'Bebas Neue',sans-serif;font-size:20px;line-height:1;margin-bottom:2px}
.copy-btn{background:rgba(201,168,76,.1);border:1px solid rgba(201,168,76,.25);color:var(--gold);padding:4px 10px;border-radius:2px;cursor:pointer;font-family:'Barlow Condensed',sans-serif;font-size:10px;letter-spacing:1.5px;transition:all .2s;margin-top:8px;display:inline-block}
.copy-btn:hover{background:rgba(201,168,76,.2)}
.pending-banner{background:rgba(74,158,255,.08);border:1px solid rgba(74,158,255,.2);border-radius:2px;padding:18px;text-align:center;margin-top:16px}
.pending-icon{font-size:36px;display:block;margin-bottom:8px}
.pending-title{font-family:'Bebas Neue',sans-serif;font-size:20px;letter-spacing:3px;color:var(--blue);margin-bottom:6px}
.pending-sub{font-size:12px;color:var(--tx2);line-height:1.6}

@media(max-width:700px){
  .navbar{padding:0 12px;flex-wrap:wrap;height:auto;min-height:52px;padding-top:8px;padding-bottom:8px}
  .nav-tabs{display:none}
  .content{padding:14px 12px}
  .match-body{grid-template-columns:1fr;gap:8px}.team.home,.team.away{text-align:center}
  .t-hero-banner{flex-direction:column;text-align:center;padding:18px;gap:12px}
  .form-grid{grid-template-columns:1fr}.form-grid .full{grid-column:span 1}
  .lb-row{grid-template-columns:36px 1fr 58px}.lb-row .lb-n{display:none}
  .inv-row{grid-template-columns:1fr 90px 80px}
  .inv-row>:nth-child(n+4){display:none}
  .ut-hdr,.ut-row{grid-template-columns:36px 1fr 80px 90px}
  .ut-hdr>:nth-child(n+5),.ut-row>:nth-child(n+5){display:none}
  .comp-grid{grid-template-columns:1fr}
  .mfg{grid-template-columns:1fr}.mfg .afield.full{grid-column:span 1}
}
`;

// ============================================================
// UTILS
// ============================================================
function Toast({message,type,onClose}){
  useEffect(()=>{const t=setTimeout(onClose,3400);return()=>clearTimeout(t);},[onClose]);
  return <div className={"toast"+(type==="err"?" err":"")}>{type==="err"?"⚠ ":"✓ "}{message}</div>;
}
function Loader({text="CARGANDO..."}){
  return <div className="loader-wrap"><div className="loader-logo">⚽</div><div className="loader-txt">{text}</div></div>;
}
function statusLabel(s){return s==="active"?"🟢 En curso":s==="upcoming"?"🟡 Próximo":"⚫ Finalizado";}
function statusClass(s){return s==="active"?"s-act":s==="upcoming"?"s-up":"s-fin";}

// ============================================================

// ============================================================
// GROUPS UI
// ============================================================

function CreateGroupModal({ user, onClose, onCreated, showToast }) {
  const { groups: groupSvc, tournaments: tournSvc } = useServices();
  const [tournaments, setTournaments] = useState([]);
  const [form, setForm] = useState({ name: "", tournamentId: "" });
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => { tournSvc.getAll().then(setTournaments); }, []);
  const handleCreate = async () => {
    setErr(""); setSaving(true);
    const r = await groupSvc.create(user.id, form);
    setSaving(false);
    if (r.error) { setErr(r.error); return; }
    showToast("¡Grupo creado! Compartí el código con tus amigos.");
    onCreated(r.group); onClose();
  };
  return(
    <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal" style={{maxWidth:440}}>
        <div className="modal-hdr">
          <div className="modal-title">NUEVO GRUPO</div>
          <button className="btn btn-ghost" style={{padding:"3px 9px",fontSize:15}} onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {err&&<div className="msg-err">{err}</div>}
          <div className="field"><label>Nombre del grupo *</label>
            <input value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} placeholder='"La Quiniela de la Oficina"' maxLength={60}/>
          </div>
          <div className="field"><label>Torneo base *</label>
            <select value={form.tournamentId} onChange={e=>setForm(f=>({...f,tournamentId:e.target.value}))}>
              <option value="">— Seleccioná un torneo —</option>
              {tournaments.map(t=><option key={t.id} value={t.id}>{t.logo} {t.name}</option>)}
            </select>
          </div>
          <p style={{fontSize:11,color:"var(--tx3)",lineHeight:1.6}}>Se genera un <strong style={{color:"var(--tx2)"}}>código único</strong> para compartir con tus amigos.</p>
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={onClose}>Cancelar</button>
          <button className="btn btn-gold" onClick={handleCreate} disabled={saving||!form.name.trim()||!form.tournamentId}>
            {saving?"CREANDO...":"CREAR GRUPO"}
          </button>
        </div>
      </div>
    </div>
  );
}

function JoinGroupModal({ user, onClose, onJoined, showToast }) {
  const { groups: groupSvc } = useServices();
  const [code, setCode] = useState("");
  const [joining, setJoining] = useState(false);
  const [err, setErr] = useState("");
  const handleJoin = async () => {
    setErr(""); setJoining(true);
    const r = await groupSvc.joinByCode(user.id, code);
    setJoining(false);
    if (r.error) { setErr(r.error); return; }
    showToast(`¡Te uniste a "${r.group.name}"!`); onJoined(r.group); onClose();
  };
  return(
    <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal" style={{maxWidth:360}}>
        <div className="modal-hdr">
          <div className="modal-title">UNIRME A UN GRUPO</div>
          <button className="btn btn-ghost" style={{padding:"3px 9px",fontSize:15}} onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {err&&<div className="msg-err">{err}</div>}
          <div className="field"><label>Código del grupo (6 caracteres)</label>
            <input value={code} onChange={e=>setCode(e.target.value.toUpperCase())} placeholder="ej: A3B7C9" maxLength={6}
              style={{textAlign:"center",letterSpacing:6,fontSize:20,fontFamily:"Bebas Neue"}}
              onKeyDown={e=>e.key==="Enter"&&handleJoin()}/>
          </div>
          <p style={{fontSize:11,color:"var(--tx3)"}}>Pedile el código al organizador de tu grupo.</p>
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={onClose}>Cancelar</button>
          <button className="btn btn-gold" onClick={handleJoin} disabled={joining||code.length<6}>
            {joining?"UNIÉNDOME...":"UNIRME"}
          </button>
        </div>
      </div>
    </div>
  );
}

function GroupDetail({ group, user, token, showToast, onBack }) {
  const { matches:matchSvc, predictions:predSvc, groupLeaderboard:lbSvc, groups:groupSvc } = useServices();
  const [innerTab, setInnerTab] = useState("matches");
  const [matches, setMatches]   = useState([]);
  const [leaders, setLeaders]   = useState([]);
  const [members, setMembers]   = useState([]);
  const [loading, setLoading]   = useState(true);
  const [copied, setCopied]     = useState(false);
  const [matchGroup, setMatchGroup] = useState("ALL");

  const GROUP_LABELS={A:"Grupo A",B:"Grupo B",C:"Grupo C",D:"Grupo D",E:"Grupo E",F:"Grupo F",G:"Grupo G",H:"Grupo H",I:"Grupo I",J:"Grupo J",K:"Grupo K",L:"Grupo L",R32:"Ronda de 32",R16:"Octavos",QF:"Cuartos",SF:"Semis","3P":"3er Puesto",FIN:"Final"};
  const STAGE_ORDER=["A","B","C","D","E","F","G","H","I","J","K","L","R32","R16","QF","SF","3P","FIN"];

  const load = useCallback(async () => {
    setLoading(true);
    const [m, lb, mem] = await Promise.all([
      matchSvc.getForUser(group.tournamentId, user.id),
      lbSvc.get(group.id, user.id),
      groupSvc.getMembers(group.id, user.id),
    ]);
    setMatches(m);
    if(lb.leaderboard) setLeaders(lb.leaderboard);
    if(mem.members)    setMembers(mem.members);
    setLoading(false);
  }, [group.id, group.tournamentId, user.id]);
  useEffect(()=>{load();},[load]);

  const copyCode = () => {
    navigator.clipboard?.writeText(`¡Sumate a mi grupo "${group.name}" en Super Campeones!\n\nCódigo: ${group.code}\n\nIngresá a la app → Mis Grupos → Unirme.`).catch(()=>{});
    setCopied(true); setTimeout(()=>setCopied(false),2000);
  };

  const isOwner = group.ownerId===user.id;
  const rc = i=>i===0?"g":i===1?"s":i===2?"b":"";
  const avGroups=["ALL",...STAGE_ORDER.filter(g=>matches.some(m=>m.group===g))];
  const filteredM=matchGroup==="ALL"?matches:matches.filter(m=>m.group===matchGroup);

  return(
    <div className="content">
      <button className="back-btn" onClick={onBack}>← Mis grupos</button>
      <div className="t-hero" style={{marginBottom:0}}>
        <div className="group-hero">
          <div className="group-hero-info">
            <div className="group-hero-name">{group.name}</div>
            <div className="group-hero-sub">{group.tournamentLogo||"🏆"} {group.tournamentName} · {members.length} miembro{members.length!==1?"s":""}</div>
          </div>
          <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:6}}>
            {isOwner?<span className="owner-chip">👑 Tuyo</span>:<span className="member-chip">👤 Miembro</span>}
            <button className="copy-code-btn" onClick={copyCode}>{copied?"✓ Copiado":`📋 Código: ${group.code}`}</button>
          </div>
        </div>
        <div className="group-tabs">
          {[{id:"matches",label:"Partidos"},{id:"ranking",label:"Ranking"},{id:"members",label:"Miembros"}].map(t=>(
            <button key={t.id} className={"group-tab"+(innerTab===t.id?" active":"")} onClick={()=>setInnerTab(t.id)}>{t.label}</button>
          ))}
          <div style={{flex:1}}/>
          {isOwner
            ?<button className="btn btn-red" style={{padding:"4px 10px",fontSize:10}} onClick={async()=>{if(!window.confirm(`¿Eliminar "${group.name}"?`))return;const r=await groupSvc.remove(user.id,group.id);if(r.success){showToast("Grupo eliminado");onBack();}else showToast(r.error,"err");}}>🗑 Eliminar</button>
            :<button className="btn btn-ghost" style={{padding:"4px 10px",fontSize:10}} onClick={async()=>{if(!window.confirm("¿Salir del grupo?"))return;const r=await groupSvc.leave(user.id,group.id);if(r.success){showToast("Saliste del grupo");onBack();}else showToast(r.error,"err");}}>Salir</button>
          }
        </div>
      </div>
      {loading?<div className="empty">Cargando...</div>:(
        <>
          {innerTab==="matches"&&(
            <div style={{marginTop:16}}>
              <div className="groups-nav">
                {avGroups.map(g=><button key={g} className={"group-btn"+(matchGroup===g?" active":"")} onClick={()=>setMatchGroup(g)}>{g==="ALL"?"Todos":(GROUP_LABELS[g]||"Grupo "+g)}</button>)}
              </div>
              <div className="matches-list">
                {filteredM.map(m=>(
                  <MatchCard key={m.id} match={m} tId={group.tournamentId} userId={user.id} token={token} isAdmin={false}
                    onSave={async(mid,h,a)=>{const r=await predSvc.save(user.id,group.tournamentId,mid,h,a);if(r.success){showToast("Pronóstico guardado");await load();}else showToast(r.error,"err");return r;}}
                    onAdminSave={()=>{}}/>
                ))}
              </div>
            </div>
          )}
          {innerTab==="ranking"&&(
            <div style={{marginTop:16}}>
              <div className="lb">
                <div className="lb-row hdr"><div>#</div><div>Jugador</div><div style={{textAlign:"right"}}>Pts</div><div style={{textAlign:"center"}}>Pred</div><div style={{textAlign:"center"}}>Exactos</div></div>
                {leaders.length===0?<div className="empty">Sin predicciones aún</div>:
                  leaders.map((u,i)=>(
                    <div key={u.id} className="lb-row" style={u.id===user.id?{background:"rgba(201,168,76,.05)",borderLeft:"2px solid var(--gold)"}:{}}>
                      <div className={"rank "+rc(i)}>{i+1}</div>
                      <div className="lb-user"><div className="lb-av">{u.avatar}</div>
                        <div><span style={{fontSize:13,fontWeight:500}}>{u.username}</span>
                          {u.id===user.id&&<span style={{fontSize:9,color:"var(--gold)",fontFamily:"Barlow Condensed",letterSpacing:1,marginLeft:6}}>TÚ</span>}
                          {u.role==="owner"&&<span style={{marginLeft:4}}>👑</span>}
                        </div>
                      </div>
                      <div className="lb-pts">{u.points}</div>
                      <div className="lb-n">{u.predictions}</div>
                      <div className="lb-n" style={{color:"var(--gold)"}}>{u.exact}</div>
                    </div>
                  ))
                }
              </div>
              <div className="pts-info" style={{marginTop:10}}>🥇 Exacto=<span style={{color:"var(--gold)"}}>3pts</span> · 🥈 Resultado=<span style={{color:"var(--gold)"}}>1pt</span> · ❌=0pts</div>
            </div>
          )}
          {innerTab==="members"&&(
            <div style={{marginTop:16}}>
              <div style={{marginBottom:12,display:"flex",alignItems:"center",justifyContent:"space-between"}}>
                <div style={{fontSize:12,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:1}}>{members.length} miembro{members.length!==1?"s":""} · Código: <strong style={{color:"var(--gold)",letterSpacing:3,fontFamily:"Bebas Neue"}}>{group.code}</strong></div>
                <button className="copy-code-btn" onClick={copyCode}>{copied?"✓":"📋 Compartir"}</button>
              </div>
              <div className="members-list">
                {members.map(m=>(
                  <div key={m.id} className="member-row">
                    <div className="member-av">{m.avatar}</div>
                    <div className="member-name">{m.username}{m.id===user.id&&<span style={{fontSize:9,color:"var(--gold)",marginLeft:6,fontFamily:"Barlow Condensed",letterSpacing:1}}>TÚ</span>}</div>
                    {m.role==="owner"?<span className="owner-chip">👑 Dueño</span>:<span className="member-chip">Miembro</span>}
                  </div>
                ))}
              </div>
              <div className="group-code-box" style={{marginTop:16}}>
                <span className="group-code">{group.code}</span>
                <span className="group-code-hint">Compartí este código para invitar amigos</span>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function MyGroupsView({ user, token, showToast }) {
  const { groups: groupSvc } = useServices();
  const [myGroups, setMyGroups]     = useState([]);
  const [loading, setLoading]       = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showJoin, setShowJoin]     = useState(false);
  const [activeGroup, setActiveGroup] = useState(null);

  const load = useCallback(async () => {
    const list = await groupSvc.getForUser(user.id);
    setMyGroups(list); setLoading(false);
  }, [user.id]);
  useEffect(()=>{load();},[load]);

  if(activeGroup) return <GroupDetail group={activeGroup} user={user} token={token} showToast={showToast} onBack={()=>{setActiveGroup(null);load();}}/>;

  return(
    <div className="content">
      <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:22,flexWrap:"wrap",gap:12}}>
        <div>
          <div className="sec-title">MIS GRUPOS</div>
          <div className="sec-sub"><span className="db-dot"></span>{myGroups.length} grupo{myGroups.length!==1?"s":""} · Quinielas privadas</div>
        </div>
        <div style={{display:"flex",gap:8}}>
          <button className="btn btn-ghost" onClick={()=>setShowJoin(true)}>🔑 Unirme</button>
          <button className="btn btn-gold" onClick={()=>setShowCreate(true)}>+ Crear grupo</button>
        </div>
      </div>
      {loading?<div className="empty">Cargando...</div>:myGroups.length===0?(
        <div style={{textAlign:"center",padding:"48px 20px"}}>
          <div style={{fontSize:48,marginBottom:12}}>🏆</div>
          <div style={{fontFamily:"Bebas Neue",fontSize:20,letterSpacing:3,color:"var(--tx2)",marginBottom:8}}>SIN GRUPOS AÚN</div>
          <p style={{fontSize:13,color:"var(--tx3)",marginBottom:20}}>Creá tu propia quiniela privada o uníte a la de un amigo.</p>
          <div style={{display:"flex",gap:10,justifyContent:"center",flexWrap:"wrap"}}>
            <button className="btn btn-gold" onClick={()=>setShowCreate(true)}>+ Crear mi grupo</button>
            <button className="btn btn-ghost" onClick={()=>setShowJoin(true)}>🔑 Tengo un código</button>
          </div>
        </div>
      ):(
        <div className="groups-grid">
          {myGroups.map(g=>(
            <div key={g.id} className="group-card" onClick={()=>setActiveGroup(g)}>
              <div className="group-card-top">
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                  <span style={{fontSize:22}}>{g.tournamentLogo}</span>
                  <div className="group-card-name">{g.name}</div>
                </div>
                <div className="group-card-meta">{g.tournamentName} · Creado {g.createdAt}</div>
              </div>
              <div className="group-card-bot">
                <span className={g.myRole==="owner"?"owner-chip":"member-chip"}>{g.myRole==="owner"?"👑 Tuyo":"👤 Miembro"}</span>
                <span style={{fontFamily:"Bebas Neue",fontSize:14,letterSpacing:3,color:"rgba(201,168,76,.5)"}}>{g.code}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {showCreate&&<CreateGroupModal user={user} onClose={()=>setShowCreate(false)} onCreated={load} showToast={showToast}/>}
      {showJoin&&<JoinGroupModal user={user} onClose={()=>setShowJoin(false)} onJoined={load} showToast={showToast}/>}
    </div>
  );
}

// REGISTER WITH INVITATION CODE
// ============================================================
function RegisterWithCodeScreen({ onBack }) {
  const [step, setStep] = useState(1);
  const [code, setCode]       = useState("");
  const [invitation, setInv]  = useState(null);
  const [username, setUsr]    = useState("");
  const [password, setPwd]    = useState("");
  const [pwd2, setPwd2]       = useState("");
  const [avatar, setAvatar]   = useState("⚽");
  const [err, setErr]         = useState("");
  const [loading, setLoading] = useState(false);

  const handleCheckCode = async () => {
    setErr(""); setLoading(true);
    const {invitations}=useServices();
    const r2=await invitations.findByCode(code.toUpperCase().trim());
    const inv=await (async()=>{const invs=await InvitationRepository.getAll();return invs.find(i=>i.code===code.toUpperCase().trim()&&i.status==="pending")||null;})();
    setLoading(false);
    if (!inv) { setErr("Código inválido o ya utilizado."); return; }
    setInv(inv); setStep(2);
  };

  const handleRegister = async () => {
    setErr("");
    if (password !== pwd2) { setErr("Las contraseñas no coinciden"); return; }
    setLoading(true);
    const {invitations:invSvc}=useServices();
    const r = await invSvc.registerWithCode(code, username, password, avatar);
    setLoading(false);
    if (r.error) { setErr(r.error); return; }
    setStep(3);
  };

  return (
    <div className="login-wrap">
      <div className="register-card">
        <div className="login-hdr" style={{padding:"28px 32px 22px"}}>
          <span className="login-logo" style={{fontSize:44}}>📨</span>
          <div className="login-title" style={{fontSize:26}}>UNIRSE CON CÓDIGO</div>
          <div className="login-sub">Ingresá el código que te enviaron</div>
        </div>
        <div className="reg-steps">
          {[{n:1,label:"Código"},{n:2,label:"Datos"},{n:3,label:"Listo"}].map(s=>(
            <div key={s.n} className={"reg-step"+(step===s.n?" active":step>s.n?" done":"")}>
              <span className="reg-step-num">{step>s.n?"✓":s.n}</span>{s.label}
            </div>
          ))}
        </div>
        <div style={{padding:"22px 26px 26px"}}>
          {step===1&&(
            <>
              {err&&<div className="msg-err">{err}</div>}
              <div className="field">
                <label>Código de invitación</label>
                <input value={code} onChange={e=>setCode(e.target.value.toUpperCase())}
                  placeholder="ej: A3B7C9D2" maxLength={8}
                  style={{textAlign:"center",letterSpacing:4,fontSize:18,fontFamily:"Bebas Neue"}}
                  onKeyDown={e=>e.key==="Enter"&&handleCheckCode()}/>
              </div>
              <button className="btn btn-gold btn-full" onClick={handleCheckCode} disabled={loading||!code.trim()}>
                {loading?"VERIFICANDO...":"VERIFICAR CÓDIGO"}
              </button>
              <button className="btn btn-ghost btn-full" style={{marginTop:8}} onClick={onBack}>← Volver al login</button>
            </>
          )}
          {step===2&&invitation&&(
            <>
              <div className="msg-ok" style={{marginBottom:14}}>
                ✓ Invitado por <strong>{invitation.invitedByName}</strong> — <strong>{invitation.tName}</strong>
              </div>
              {err&&<div className="msg-err">{err}</div>}
              <div className="field">
                <label>Nombre de usuario</label>
                <input value={username} onChange={e=>setUsr(e.target.value)} placeholder="ej: jugador99"/>
                <div style={{fontSize:10,color:"var(--tx3)",marginTop:3}}>Solo letras, números y _ (3-20 chars)</div>
              </div>
              <div className="field">
                <label>Contraseña</label>
                <input type="password" value={password} onChange={e=>setPwd(e.target.value)} placeholder="Mínimo 4 caracteres"/>
              </div>
              <div className="field">
                <label>Repetir contraseña</label>
                <input type="password" value={pwd2} onChange={e=>setPwd2(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleRegister()}/>
              </div>
              <div className="field">
                <label>Avatar</label>
                <div className="avatar-picker">
                  {AVATARS.map(a=>(
                    <button key={a} className={"av-btn"+(avatar===a?" sel":"")} onClick={()=>setAvatar(a)}>{a}</button>
                  ))}
                </div>
              </div>
              <button className="btn btn-gold btn-full" onClick={handleRegister} disabled={loading}>
                {loading?"REGISTRANDO...":"COMPLETAR REGISTRO"}
              </button>
            </>
          )}
          {step===3&&(
            <div className="pending-banner">
              <span className="pending-icon">⏳</span>
              <div className="pending-title">¡REGISTRO ENVIADO!</div>
              <p className="pending-sub">
                Tu solicitud fue enviada al administrador.<br/>
                Una vez aprobada, podrás ingresar con tu usuario y contraseña.<br/><br/>
                <strong style={{color:"var(--gold)"}}>Avisale al admin para que la apruebe.</strong>
              </p>
              <button className="btn btn-ghost" style={{marginTop:14}} onClick={onBack}>← Volver al login</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// INVITATIONS VIEW
// ============================================================
function InvitationsView({ user, token, showToast, tournaments: tournamentsProp }) {
  const {invitations:invSvc, tournaments:tournSvc} = useServices();
  const isAdmin = user.role === "admin";
  const [invitations, setInvitations] = useState([]);
  const [tournaments, setTournaments] = useState(tournamentsProp || []);
  const [loading, setLoading]         = useState(true);
  const [selTId, setSelTId]           = useState("");
  const [creating, setCreating]       = useState(false);
  const [copiedId, setCopiedId]       = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    const [tList, invData] = await Promise.all([
      TournamentService.getAll(),
      isAdmin ? InvitationService.getAll(token) : Promise.resolve(await InvitationService.getForUser(user.id)),
    ]);
    setTournaments(tList);
    if (!selTId && tList.length) setSelTId(tList[0].id);
    const invs = isAdmin ? (invData.invitations || []) : (invData || []);
    setInvitations(invs);
    setLoading(false);
  }, [user.id, token, isAdmin, selTId]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!selTId) { showToast("Seleccioná un torneo", "err"); return; }
    setCreating(true);
    const r = await invSvc.create(user.id, selTId);
    setCreating(false);
    if (r.error) { showToast(r.error, "err"); return; }
    showToast("¡Código generado! Compartilo con tu amigo.");
    load();
  };

  const handleCopy = (inv) => {
    const text = `¡Te invito a jugar Super Campeones!\n\nTorneo: ${inv.tName}\nCódigo: ${inv.code}\n\nIngresá a la app y usá "Tengo un código de invitación".`;
    navigator.clipboard?.writeText(text).catch(()=>{});
    setCopiedId(inv.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleApprove = async (invId) => {
    const r = await invSvc.approve(invId, token);
    if (r.success) { showToast(`✅ Usuario "${r.user.username}" creado y aprobado`); load(); }
    else showToast(r.error, "err");
  };

  const handleReject = async (invId) => {
    const r = await invSvc.reject(invId, token);
    if (r.success) { showToast("Invitación rechazada"); load(); }
    else showToast(r.error, "err");
  };

  const handleCancel = async (invId) => {
    const r = await invSvc.cancel(invId, user.id);
    if (r.success) { showToast("Invitación cancelada"); load(); }
    else showToast(r.error, "err");
  };

  const invBadge = (s) => {
    const map = { pending:"ib-pending", registered:"ib-registered", approved:"ib-approved", rejected:"ib-rejected" };
    const lbl = { pending:"⏳ Pendiente", registered:"📋 Con datos", approved:"✅ Aprobada", rejected:"❌ Rechazada" };
    return <span className={"inv-badge "+(map[s]||"")}>{lbl[s]||s}</span>;
  };

  const pending = invitations.filter(i => i.status === "registered");

  return (
    <div>
      {isAdmin && pending.length > 0 && (
        <div className="msg-warn" style={{marginBottom:16,display:"flex",alignItems:"center",gap:10}}>
          <span style={{fontSize:18}}>🔔</span>
          <strong>{pending.length}</strong>&nbsp;solicitud{pending.length>1?"es":""} esperando aprobación
        </div>
      )}

      {/* Create invitation */}
      <div style={{background:"var(--sf2)",border:"1px solid var(--bd)",borderRadius:2,padding:16,marginBottom:20}}>
        <div style={{fontFamily:"Barlow Condensed",fontSize:11,letterSpacing:2,textTransform:"uppercase",color:"var(--tx3)",marginBottom:12}}>
          📨 Invitar a un amigo
        </div>
        <div style={{display:"flex",gap:10,alignItems:"flex-end",flexWrap:"wrap"}}>
          <div style={{flex:1,minWidth:180}}>
            <label style={{display:"block",fontSize:9,letterSpacing:2,textTransform:"uppercase",color:"var(--tx3)",fontFamily:"Barlow Condensed",marginBottom:5}}>Torneo</label>
            <select className="ap-select" style={{width:"100%"}} value={selTId} onChange={e=>setSelTId(e.target.value)}>
              <option value="">— Seleccioná un torneo —</option>
              {(tournaments||[]).map(t=><option key={t.id} value={t.id}>{t.logo} {t.name}</option>)}
            </select>
          </div>
          <button className="btn btn-gold" onClick={handleCreate} disabled={creating||!selTId}>
            {creating?"GENERANDO...":"+ GENERAR CÓDIGO"}
          </button>
        </div>
        <div style={{fontSize:10,color:"var(--tx3)",marginTop:8,fontFamily:"Barlow Condensed",letterSpacing:1}}>
          Se genera un código único que tu amigo usará para registrarse. Un admin deberá aprobarlo.
        </div>
      </div>

      {/* List */}
      {loading ? <div className="empty">Cargando...</div> : invitations.length === 0 ? (
        <div className="empty">Sin invitaciones todavía</div>
      ) : (
        <div className="inv-table">
          <div className="inv-row hdr">
            <div>Torneo · Creada por</div>
            <div>Código</div>
            <div>Estado</div>
            <div>Usuario solicitado</div>
            <div>Acciones</div>
          </div>
          {invitations.slice().reverse().map(inv=>(
            <div key={inv.id} className="inv-row" style={inv.status==="registered"&&isAdmin?{background:"rgba(74,158,255,.04)",borderLeft:"2px solid var(--blue)"}:{}}>
              <div>
                <div style={{fontSize:12,fontWeight:500}}>{inv.tName}</div>
                <div style={{fontSize:10,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:1}}>
                  {inv.invitedByName} · {inv.createdAt?.split("T")[0]}
                </div>
              </div>
              <div>
                <span style={{fontFamily:"Bebas Neue",fontSize:inv.status==="pending"?16:13,letterSpacing:3,color:inv.status==="pending"?"var(--gold)":"var(--tx3)"}}>
                  {inv.code}
                </span>
              </div>
              <div>{invBadge(inv.status)}</div>
              <div style={{fontSize:11,color:inv.newUsername?"var(--tx2)":"var(--tx3)"}}>
                {inv.newUsername
                  ? <span style={{display:"flex",alignItems:"center",gap:5}}><span style={{fontSize:15}}>{inv.newAvatar}</span>{inv.newUsername}</span>
                  : "—"}
              </div>
              <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>
                {inv.status==="pending"&&(
                  <>
                    <button className="copy-btn" onClick={()=>handleCopy(inv)}>{copiedId===inv.id?"✓ OK":"📋 Copiar"}</button>
                    {(inv.invitedBy===user.id||isAdmin)&&(
                      <button className="icon-btn danger" title="Cancelar" onClick={()=>handleCancel(inv.id)}>✕</button>
                    )}
                  </>
                )}
                {isAdmin&&inv.status==="registered"&&(
                  <>
                    <button className="icon-btn success" title="Aprobar" onClick={()=>handleApprove(inv.id)}>✅</button>
                    <button className="icon-btn danger"  title="Rechazar" onClick={()=>handleReject(inv.id)}>❌</button>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ============================================================
// LOGIN
// ============================================================
function LoginScreen({onLogin, onRegister}){
  const {auth}=useServices();
  const [u,setU]=useState(""); const [pwd,setPwd]=useState(""); const [err,setErr]=useState(""); const [loading,setL]=useState(false);
  const go=async(name,pass)=>{
    setErr(""); setL(true);
    const r=await auth.login(name||u.trim(), pass||pwd);
    setL(false);
    if(r.error) setErr(r.error); else onLogin(r.token,r.user);
  };
  return(
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-hdr">
          <span className="login-logo">🏆</span>
          <div className="login-title">SUPER CAMPEONES</div>
          <div className="login-sub">Pronosticá · Competí · Ganá</div>
        </div>
        <div className="login-body">
          {err&&<div className="msg-err">⚠ {err}</div>}
          <div className="field"><label>Usuario</label>
            <input value={u} onChange={e=>setU(e.target.value)} placeholder="Tu nombre de usuario"
              onKeyDown={e=>e.key==="Enter"&&go()} autoComplete="username"/>
          </div>
          <div className="field"><label>Contraseña</label>
            <input type="password" value={pwd} onChange={e=>setPwd(e.target.value)} placeholder="••••••••"
              onKeyDown={e=>e.key==="Enter"&&go()} autoComplete="current-password"/>
          </div>
          <button className="btn btn-gold btn-full" onClick={()=>go()} disabled={loading}>
            {loading?"VERIFICANDO...":"INGRESAR"}
          </button>
          {/* Invitation code entry */}
          <button className="btn btn-ghost btn-full" style={{marginTop:10}} onClick={onRegister}>
            📨 Tengo un código de invitación
          </button>
          <div className="demo-box">
            <p><span className="db-dot"></span>Cuentas demo (cualquier contraseña)</p>
            {["admin","diego10","leo30","cr7fan"].map(n=>(
              <button key={n} className="demo-btn" onClick={()=>{setU(n);setPwd("demo");go(n,"demo");}}>{n}</button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// USER MANAGEMENT VIEW
// ============================================================
function ConfirmModal({title,message,onConfirm,onCancel,danger=true}){
  return(
    <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)onCancel();}}>
      <div className="modal" style={{maxWidth:380}}>
        <div className="modal-body">
          <div className="confirm-modal">
            <h3 style={{color:danger?"#ff8888":"var(--gold)"}}>{title}</h3>
            <p>{message}</p>
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={onCancel}>Cancelar</button>
          <button className={`btn ${danger?"btn-red":"btn-gold"}`} onClick={onConfirm}>Confirmar</button>
        </div>
      </div>
    </div>
  );
}

function UserFormModal({editUser, token, currentUserId, onClose, onSaved, showToast}){
  const {users:userSvc}=useServices();
  const isEdit = !!editUser;
  const [form,setForm]=useState({
    username: editUser?.username||"",
    password: "",
    role: editUser?.role||"user",
    avatar: editUser?.avatar||"⚽",
    active: editUser?.active!==undefined ? editUser.active : true,
  });
  const [err,setErr]=useState("");
  const [saving,setSaving]=useState(false);
  const upd=k=>e=>setForm(f=>({...f,[k]:e.target.type==="checkbox"?e.target.checked:e.target.value}));

  const handleSave=async()=>{
    setErr(""); setSaving(true);
    let r;
    if(isEdit){
      const fields={role:form.role,avatar:form.avatar,active:form.active};
      if(form.password) fields.password=form.password;
      r=await userSvc.update(editUser.id, fields, token);
    } else {
      r=await userSvc.create(form, token);
    }
    setSaving(false);
    if(r.error){setErr(r.error);return;}
    showToast(isEdit?"Usuario actualizado":"Usuario creado");
    onSaved(r.user);
    onClose();
  };

  return(
    <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal">
        <div className="modal-hdr">
          <div className="modal-title">{isEdit?"EDITAR USUARIO":"NUEVO USUARIO"}</div>
          <button className="btn btn-ghost" style={{padding:"3px 9px",fontSize:15}} onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {err&&<div className="msg-err">{err}</div>}
          <div className="form-grid">
            <div className="field full">
              <label>Nombre de usuario {isEdit&&<span style={{color:"var(--tx3)"}}>(no editable)</span>}</label>
              <input value={form.username} onChange={upd("username")} placeholder="ej: jugador99"
                disabled={isEdit} style={isEdit?{opacity:.5}:{}}/>
              {!isEdit&&<div style={{fontSize:10,color:"var(--tx3)",marginTop:4}}>Solo letras, números y _ (3-20 caracteres)</div>}
            </div>
            <div className="field full">
              <label>{isEdit?"Nueva contraseña (dejar vacío para no cambiar)":"Contraseña *"}</label>
              <input type="password" value={form.password} onChange={upd("password")}
                placeholder={isEdit?"••••••••  (sin cambios)":"Mínimo 4 caracteres"}/>
            </div>
            <div className="field">
              <label>Rol</label>
              <select value={form.role} onChange={upd("role")}
                disabled={isEdit&&editUser.id==="u1"} style={isEdit&&editUser.id==="u1"?{opacity:.5}:{}}>
                <option value="user">👤 Jugador</option>
                <option value="admin">🔑 Administrador</option>
              </select>
            </div>
            <div className="field">
              <label>Estado</label>
              <select value={form.active?"active":"inactive"} onChange={e=>setForm(f=>({...f,active:e.target.value==="active"}))}>
                <option value="active">🟢 Activo</option>
                <option value="inactive">🔴 Desactivado</option>
              </select>
            </div>
          </div>
          <div className="field" style={{marginTop:8}}>
            <label>Avatar</label>
            <div className="avatar-picker">
              {AVATARS.map(a=>(
                <button key={a} className={"av-btn"+(form.avatar===a?" sel":"")} onClick={()=>setForm(f=>({...f,avatar:a}))}>{a}</button>
              ))}
            </div>
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={onClose}>Cancelar</button>
          <button className="btn btn-gold" onClick={handleSave} disabled={saving}>
            {saving?"GUARDANDO...":(isEdit?"GUARDAR CAMBIOS":"CREAR USUARIO")}
          </button>
        </div>
      </div>
    </div>
  );
}

function UsersView({user, token, showToast}){
  const [innerTab, setInnerTab] = useState("users"); // "users" | "invitations"
  const [users,setUsers]=useState([]);
  const [tournaments,setTournaments]=useState([]);
  const [loading,setLoading]=useState(true);
  const [showForm,setShowForm]=useState(false);
  const [editUser,setEditUser]=useState(null);
  const [confirmDel,setConfirmDel]=useState(null);
  const [confirmToggle,setConfirmToggle]=useState(null);
  const [pendingCount,setPendingCount]=useState(0);

  const load=useCallback(async()=>{
    const {users:userSvc,tournaments:tournSvc2,invitations:invSvc2}=useServices();
    const [r, t, invs] = await Promise.all([
      userSvc.getAll(token),
      tournSvc2.getAll(),
      invSvc2.getAll(token),
    ]);
    if(r.users) setUsers(r.users);
    setTournaments(t);
    if(invs.invitations) setPendingCount(invs.invitations.filter(i=>i.status==="registered").length);
    setLoading(false);
  },[user.id,token]);

  useEffect(()=>{load();},[load]);

  const handleDelete=async()=>{
    const {users:userSvc3}=useServices();
    const r=await userSvc3.remove(confirmDel.id,user.id,token);
    setConfirmDel(null);
    if(r.success){showToast("Usuario eliminado");load();}
    else showToast(r.error,"err");
  };

  const handleToggle=async()=>{
    const {users:userSvc4}=useServices();
    const r=await userSvc4.update(confirmToggle.id,{active:!confirmToggle.active},token);
    setConfirmToggle(null);
    if(r.success){showToast(r.user.active?"Usuario activado":"Usuario desactivado");load();}
    else showToast(r.error,"err");
  };

  const totalActive=users.filter(u=>u.active&&u.role==="user").length;
  const totalAdmins=users.filter(u=>u.role==="admin").length;

  if(loading) return <div className="content"><div className="empty">Cargando...</div></div>;

  return(
    <div className="content">
      <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:20,flexWrap:"wrap",gap:12}}>
        <div>
          <div className="sec-title">GESTIÓN DE USUARIOS</div>
          <div className="sec-sub"><span className="db-dot"></span>{users.length} usuarios · {totalActive} jugadores activos</div>
        </div>
        {innerTab==="users"&&(
          <button className="btn btn-gold" onClick={()=>{setEditUser(null);setShowForm(true);}}>+ NUEVO USUARIO</button>
        )}
      </div>

      {/* Inner tabs */}
      <div className="ap-tabs" style={{marginBottom:20}}>
        <button className={"ap-tab"+(innerTab==="users"?" active":"")} onClick={()=>setInnerTab("users")}>
          👤 Usuarios
        </button>
        <button className={"ap-tab"+(innerTab==="invitations"?" active":"")} onClick={()=>{setInnerTab("invitations");load();}}>
          📨 Invitaciones
          {pendingCount>0&&<span className="notif-dot"/>}
        </button>
      </div>

      {/* USERS TAB */}
      {innerTab==="users"&&(
        <>
          {/* Stats */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(130px,1fr))",gap:10,marginBottom:20}}>
            {[
              {label:"Total",     value:users.length,                            color:"var(--tx)"},
              {label:"Jugadores", value:users.filter(u=>u.role==="user").length, color:"var(--blue)"},
              {label:"Admins",    value:totalAdmins,                             color:"#ff8888"},
              {label:"Activos",   value:users.filter(u=>u.active).length,        color:"var(--green)"},
              {label:"Inactivos", value:users.filter(u=>!u.active).length,       color:"var(--tx3)"},
            ].map(s=>(
              <div key={s.label} style={{background:"var(--sf)",border:"1px solid var(--bd)",borderRadius:2,padding:"11px 14px"}}>
                <div style={{fontFamily:"Bebas Neue",fontSize:26,color:s.color,lineHeight:1}}>{s.value}</div>
                <div style={{fontSize:9,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:2,textTransform:"uppercase",marginTop:3}}>{s.label}</div>
              </div>
            ))}
          </div>

          <div className="users-table">
            <div className="ut-hdr">
              <div></div><div>Usuario</div><div>Rol</div><div>Estado</div><div>Alta</div><div>Acciones</div>
            </div>
            {users.length===0?(
              <div className="empty">No hay usuarios</div>
            ):users.map(u=>(
              <div key={u.id} className="ut-row">
                <div className="ut-avatar">{u.avatar}</div>
                <div>
                  <div className="ut-name">{u.username}</div>
                  {u.id===user.id&&<div style={{fontSize:9,color:"var(--gold)",fontFamily:"Barlow Condensed",letterSpacing:1}}>TÚ</div>}
                  {u.invitedByName&&<div style={{fontSize:9,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:1}}>Invitado por {u.invitedByName}</div>}
                </div>
                <div><span className={"role-badge "+(u.role==="admin"?"rb-admin":"rb-user")}>{u.role==="admin"?"Admin":"Jugador"}</span></div>
                <div><span className={"active-badge "+(u.active?"ab-on":"ab-off")}>{u.active?"Activo":"Inactivo"}</span></div>
                <div className="ut-date">{u.createdAt||"-"}</div>
                <div className="ut-actions">
                  <button className="icon-btn" title="Editar" onClick={()=>{setEditUser(u);setShowForm(true);}}>✏️</button>
                  {u.id!=="u1"&&(
                    <button className={"icon-btn "+(u.active?"danger":"success")} title={u.active?"Desactivar":"Activar"} onClick={()=>setConfirmToggle(u)}>
                      {u.active?"🔒":"🔓"}
                    </button>
                  )}
                  {u.id!=="u1"&&u.id!==user.id&&(
                    <button className="icon-btn danger" title="Eliminar" onClick={()=>setConfirmDel(u)}>🗑️</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* INVITATIONS TAB */}
      {innerTab==="invitations"&&(
        <InvitationsView user={user} token={token} showToast={showToast} tournaments={tournaments}/>
      )}

      {/* Modals */}
      {showForm&&(
        <UserFormModal editUser={editUser} token={token} currentUserId={user.id}
          onClose={()=>{setShowForm(false);setEditUser(null);}}
          onSaved={()=>load()} showToast={showToast}/>
      )}
      {confirmDel&&(
        <ConfirmModal title="¿ELIMINAR USUARIO?"
          message={`¿Estás seguro que querés eliminar a "${confirmDel.username}"? Esta acción no se puede deshacer.`}
          onConfirm={handleDelete} onCancel={()=>setConfirmDel(null)}/>
      )}
      {confirmToggle&&(
        <ConfirmModal title={confirmToggle.active?"¿DESACTIVAR USUARIO?":"¿ACTIVAR USUARIO?"}
          message={confirmToggle.active
            ? `"${confirmToggle.username}" no podrá ingresar hasta que lo reactives.`
            : `"${confirmToggle.username}" podrá volver a ingresar al sistema.`}
          danger={confirmToggle.active}
          onConfirm={handleToggle} onCancel={()=>setConfirmToggle(null)}/>
      )}
    </div>
  );
}

// ============================================================
// CREATE TOURNAMENT MODAL
// ============================================================
const LOGOS=["🌍","🌎","🌏","⚽","🏆","⭐","🥇","🎯"];
const FIFA_COMPS=Object.entries(FIFA_API.COMPETITIONS);

function CreateTournamentModal({token,user,onClose,onCreated,showToast}){
  const [mode,setMode]=useState("manual");
  const [form,setForm]=useState({name:"",shortName:"",region:"Global",status:"upcoming",logo:"🏆",startDate:"",endDate:"",groups:"A,B,C,D,E,F,G,H"});
  const [saving,setSaving]=useState(false);
  const [formErr,setFormErr]=useState("");
  const [selComp,setSelComp]=useState(null);
  const [selCompId,setSelCompId]=useState(null);
  const [query,setQuery]=useState("");
  const [results,setResults]=useState([]);
  const [searching,setSearching]=useState(false);
  const [searchErr,setSearchErr]=useState("");
  const [selSeason,setSelSeason]=useState(null);
  const [corsBlocked,setCorsBlocked]=useState(false);
  const upd=k=>e=>setForm(f=>({...f,[k]:e.target.value}));

  const handleCreate=async()=>{
    setFormErr(""); setSaving(true);
    const {tournaments:tournSvc}=useServices();
    const r=await tournSvc.create({...form,source:"manual"},token);
    setSaving(false);
    if(r.error){setFormErr(r.error);return;}
    showToast("Torneo creado"); onCreated(); onClose();
  };

  const handleSearch=async()=>{
    if(!selComp||!query.trim()) return;
    setSearching(true); setSearchErr(""); setResults([]); setCorsBlocked(false);
    const r=await FIFA_API.searchSeasons(query);
    setSearching(false);
    if(r.error){setCorsBlocked(true);setSearchErr(r.error);return;}
    const list=(r.Results||r||[]);
    setResults(list);
    if(!list.length) setSearchErr("Sin resultados.");
  };

  const handleImport=async()=>{
    if(!selSeason) return;
    setSaving(true);
    const d={name:selSeason.Name?.[0]?.Description||query,shortName:selSeason.Name?.[0]?.Description||query,region:"Global",status:"upcoming",logo:"🌍",startDate:selSeason.StartDate?.split("T")[0]||"",endDate:selSeason.EndDate?.split("T")[0]||"",groups:"A,B,C,D,E,F,G,H",source:"fifa_api",fifaCompId:selCompId,fifaSeasonId:selSeason.IdSeason};
    const {tournaments:tournSvcF,matches:matchSvcF}=useServices();
    const cr=await tournSvcF.create(d,token);
    if(cr.error){setSaving(false);setFormErr(cr.error);return;}
    const ir=await matchSvcF.importFromFIFA(cr.tournament.id,selCompId,selSeason.IdSeason,token,FIFA_API);
    setSaving(false);
    if(ir.error){setCorsBlocked(ir.corsBlocked);setFormErr("Torneo creado sin partidos: "+ir.error);showToast("Torneo creado (sin partidos)","warn");onCreated();onClose();return;}
    showToast(`Importado: ${ir.count} partidos`); onCreated(); onClose();
  };

  return(
    <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal modal-lg">
        <div className="modal-hdr">
          <div className="modal-title">NUEVO TORNEO</div>
          <button className="btn btn-ghost" style={{padding:"3px 9px",fontSize:15}} onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <div className="tab-switcher">
            <button className={"tab-sw-btn"+(mode==="manual"?" active":"")} onClick={()=>setMode("manual")}>✏️ Carga Manual</button>
            <button className={"tab-sw-btn"+(mode==="fifa"?" active":"")} onClick={()=>setMode("fifa")}>🌐 FIFA API</button>
          </div>
          {mode==="manual"&&(
            <>
              {formErr&&<div className="msg-err">{formErr}</div>}
              <div className="form-grid">
                <div className="field full"><label>Nombre del torneo *</label><input value={form.name} onChange={upd("name")} placeholder="ej: Copa América 2027"/></div>
                <div className="field"><label>Nombre corto</label><input value={form.shortName} onChange={upd("shortName")} placeholder="ej: Copa América"/></div>
                <div className="field"><label>Región</label>
                  <select value={form.region} onChange={upd("region")}>
                    {["Global","CONMEBOL","UEFA","CONCACAF","CAF","AFC","OFC"].map(r=><option key={r}>{r}</option>)}
                  </select>
                </div>
                <div className="field"><label>Fecha inicio *</label><input type="date" value={form.startDate} onChange={upd("startDate")}/></div>
                <div className="field"><label>Fecha fin *</label><input type="date" value={form.endDate} onChange={upd("endDate")}/></div>
                <div className="field"><label>Estado</label>
                  <select value={form.status} onChange={upd("status")}>
                    <option value="upcoming">🟡 Próximo</option><option value="active">🟢 En curso</option><option value="finished">⚫ Finalizado</option>
                  </select>
                </div>
                <div className="field"><label>Grupos (separados por coma)</label><input value={form.groups} onChange={upd("groups")} placeholder="A,B,C,D"/></div>
              </div>
              <div className="field" style={{marginTop:10}}><label>Ícono</label>
                <div style={{display:"flex",gap:6,flexWrap:"wrap",marginTop:4}}>
                  {LOGOS.map(l=>(
                    <button key={l} onClick={()=>setForm(f=>({...f,logo:l}))}
                      style={{fontSize:24,background:form.logo===l?"rgba(201,168,76,.2)":"var(--bg)",border:form.logo===l?"1px solid var(--gold)":"1px solid var(--bd)",borderRadius:4,padding:"4px 8px",cursor:"pointer"}}>
                      {l}
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}
          {mode==="fifa"&&(
            <>
              <div className="fifa-sec">
                <div className="fifa-sec-title">🌐 API Oficial FIFA — givevoicetofootball.fifa.com</div>
                <p style={{fontSize:11,color:"var(--tx2)",marginBottom:12,lineHeight:1.6}}>Seleccioná una competencia y buscá la edición para importar torneos y partidos oficiales.</p>
                <label className="ap-label" style={{marginBottom:8}}>Competencia</label>
                <div className="comp-grid">
                  {FIFA_COMPS.map(([name,id])=>(
                    <button key={id} className={"comp-btn"+(selCompId===id?" sel":"")} onClick={()=>{setSelComp(name);setSelCompId(id);setQuery(name);}}>
                      <div style={{fontWeight:600,fontSize:11}}>{name}</div>
                      <div style={{fontSize:9,color:"var(--tx3)"}}>ID: {id}</div>
                    </button>
                  ))}
                </div>
                {selComp&&(
                  <div style={{display:"flex",gap:8,alignItems:"flex-end"}}>
                    <div style={{flex:1}}>
                      <label className="ap-label">Buscar edición</label>
                      <input className="ap-input" style={{width:"100%"}} value={query} onChange={e=>setQuery(e.target.value)}
                        placeholder={`ej: ${selComp} 2022`} onKeyDown={e=>e.key==="Enter"&&handleSearch()}/>
                    </div>
                    <button className="btn btn-blue" onClick={handleSearch} disabled={searching}>{searching?"BUSCANDO...":"BUSCAR"}</button>
                  </div>
                )}
              </div>
              {searchErr&&!corsBlocked&&<div className="msg-err">{searchErr}</div>}
              {corsBlocked&&(
                <div className="cors-box">
                  <div className="cors-title">⚠ CORS — requiere backend proxy</div>
                  <p style={{fontSize:11,color:"var(--tx2)",marginBottom:10,lineHeight:1.6}}>La API de FIFA bloquea llamadas directas desde el navegador. Funciona desde un servidor backend (Node.js, etc.).</p>
                  <div className="cors-code">
                    <div>🔍 <code>GET /api/v1/seasons/search?name=FIFA+World+Cup</code></div>
                    <div>📅 <code>GET /api/v1/calendar/matches?idSeason=X&idCompetition=Y</code></div>
                    <div>📖 <code>givevoicetofootball.fifa.com/ApiFdcpSwagger</code></div>
                  </div>
                  <button className="btn btn-gold" style={{marginTop:10,fontSize:11,padding:"6px 13px"}} onClick={()=>{setMode("manual");setCorsBlocked(false);}}>Cargar manualmente →</button>
                </div>
              )}
              {results.length>0&&(
                <>
                  <label className="ap-label" style={{marginBottom:6}}>Seleccioná la edición</label>
                  <div className="search-results">
                    {results.map(s=>(
                      <div key={s.IdSeason} className="sri"
                        style={{background:selSeason?.IdSeason===s.IdSeason?"rgba(201,168,76,.08)":"",borderLeft:selSeason?.IdSeason===s.IdSeason?"2px solid var(--gold)":"2px solid transparent"}}
                        onClick={()=>setSelSeason(s)}>
                        <div><div style={{fontSize:13,fontWeight:500}}>{s.Name?.[0]?.Description||s.IdSeason}</div><div style={{fontSize:11,color:"var(--tx3)",fontFamily:"Barlow Condensed"}}>{s.StartDate?.split("T")[0]} — {s.EndDate?.split("T")[0]}</div></div>
                        <div style={{fontSize:10,color:"var(--tx3)"}}>ID: {s.IdSeason}</div>
                      </div>
                    ))}
                  </div>
                  {selSeason&&<button className="btn btn-gold" style={{marginTop:12,width:"100%",justifyContent:"center"}} onClick={handleImport} disabled={saving}>{saving?"IMPORTANDO...":"IMPORTAR TORNEO + PARTIDOS"}</button>}
                </>
              )}
              {formErr&&<div className="msg-err" style={{marginTop:10}}>{formErr}</div>}
            </>
          )}
        </div>
        {mode==="manual"&&(
          <div className="modal-footer">
            <button className="btn btn-ghost" onClick={onClose}>Cancelar</button>
            <button className="btn btn-gold" onClick={handleCreate} disabled={saving}>{saving?"CREANDO...":"CREAR TORNEO"}</button>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================
// TOURNAMENT LOBBY
// ============================================================
function TournamentLobby({user,token,onSelect,showToast}){
  const {tournaments:tournSvc}=useServices();
  const [tournaments,setTournaments]=useState([]);
  const [loading,setLoading]=useState(true);
  const [showCreate,setShowCreate]=useState(false);
  const [confirmDel,setConfirmDel]=useState(null);
  const isAdmin=user.role==="admin";

  const load=useCallback(async()=>{
    const t=await tournSvc.getAll();setTournaments(t);setLoading(false);
  },[]);
  useEffect(()=>{load();},[load]);

  const handleDelete=async()=>{
    const r=await tournSvc.remove(confirmDel.id,token);
    setConfirmDel(null);
    if(r.success){showToast("Torneo eliminado");load();}else showToast(r.error,"err");
  };

  if(loading) return <div className="content"><div className="empty">Cargando...</div></div>;

  return(
    <div className="content">
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:22,flexWrap:"wrap",gap:12}}>
        <div>
          <div className="sec-title">TORNEOS</div>
          <div className="sec-sub"><span className="db-dot"></span>{tournaments.length} torneo{tournaments.length!==1?"s":""} disponibles</div>
        </div>
        {isAdmin&&<button className="btn btn-gold" onClick={()=>setShowCreate(true)}>+ NUEVO TORNEO</button>}
      </div>
      {tournaments.length===0?(
        <div className="empty">{isAdmin?"Sin torneos. Creá uno.":"Sin torneos disponibles."}</div>
      ):(
        <div className="t-grid">
          {tournaments.map(t=>(
            <div key={t.id} className="t-card" onClick={()=>onSelect(t)}>
              <div className="t-card-top">
                <div className="t-card-logo">{t.logo}</div>
                <div>
                  <div className="t-card-name">{t.name}</div>
                  <div className="t-card-meta">{t.region} · {t.startDate} → {t.endDate}</div>
                </div>
              </div>
              <div className="t-card-bot">
                <div style={{display:"flex",gap:6,alignItems:"center"}}>
                  <span className={"status-badge "+statusClass(t.status)}>{statusLabel(t.status)}</span>
                  <span className={"source-chip "+(t.source==="fifa_api"?"src-fifa":"src-manual")}>{t.source==="fifa_api"?"🌐 FIFA":"✏ Manual"}</span>
                </div>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <span style={{fontSize:10,color:"var(--tx3)",fontFamily:"Barlow Condensed"}}>{(t.groups||[]).length} grupos</span>
                  {isAdmin&&t.id!=="t1"&&(
                    <button onClick={e=>{e.stopPropagation();setConfirmDel(t);}}
                      style={{background:"rgba(255,68,68,.12)",border:"1px solid rgba(255,68,68,.25)",color:"#ff8888",padding:"2px 7px",borderRadius:2,cursor:"pointer",fontSize:10,fontFamily:"Barlow Condensed"}}>✕</button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      {showCreate&&<CreateTournamentModal token={token} user={user} showToast={showToast} onClose={()=>setShowCreate(false)} onCreated={load}/>}
      {confirmDel&&<ConfirmModal title="¿ELIMINAR TORNEO?" message={`¿Eliminar "${confirmDel.name}"? Se perderán todos los pronósticos asociados.`} onConfirm={handleDelete} onCancel={()=>setConfirmDel(null)}/>}
    </div>
  );
}

// ============================================================
// MATCH CARD
// ============================================================
function MatchCard({match,tId,userId,token,isAdmin,onSave,onAdminSave}){
  const [h,setH]=useState(match.myPrediction?.homeScore?.toString()??"");
  const [a,setA]=useState(match.myPrediction?.awayScore?.toString()??"");
  const [saved,setSaved]=useState(!!match.myPrediction);
  const [saving,setSaving]=useState(false);
  const [ah,setAH]=useState(match.homeScore?.toString()??"");
  const [aa,setAA]=useState(match.awayScore?.toString()??"");
  const [as2,setAS]=useState(false);
  const pts=match.myPrediction?.points;
  return(
    <div className="match-card">
      <div className="match-hdr">
        <span>{match.stage} — {match.date} {match.time}</span>
        <span className={"status-badge "+statusClass(match.status)}>{match.status==="finished"?"Finalizado":match.status==="active"?"En curso":"Pendiente"}</span>
      </div>

      {/* ── DESKTOP: Local | Centro | Visitante en una fila ───── */}
      <div className="match-body match-body-desktop">
        <div className={"team home"+(match.homeTeam?.startsWith("TBD:")?" tbd":"")}>
          {match.homeTeam?.startsWith("TBD:") ? "❓ "+match.homeTeam.slice(4) : match.homeTeam}
        </div>
        <div className="match-center">
          {match.status==="finished"?(
            <div className="score-fin"><span>{match.homeScore}</span><span className="score-sep">–</span><span>{match.awayScore}</span></div>
          ):match.homeTeam?.startsWith("TBD:")||match.awayTeam?.startsWith("TBD:")?(
            <div className="tbd-match-note">Equipos por definirse</div>
          ):(
            <div className="score-row">
              <input className="sinput" type="number" min="0" max="30" value={h} onChange={e=>{setH(e.target.value);setSaved(false)}}/>
              <span style={{color:"var(--tx3)",fontFamily:"Bebas Neue",fontSize:17}}>–</span>
              <input className="sinput" type="number" min="0" max="30" value={a} onChange={e=>{setA(e.target.value);setSaved(false)}}/>
            </div>
          )}
          {match.myPrediction&&(
            <div style={{textAlign:"center",marginTop:5,display:"flex",justifyContent:"center",flexWrap:"wrap",gap:4}}>
              <span className="pred-badge">Pronóstico: {match.myPrediction.homeScore}–{match.myPrediction.awayScore}</span>
              {match.status==="finished"&&pts!==undefined&&<span className="pts-badge">+{pts}pts</span>}
            </div>
          )}
        </div>
        <div className={"team away"+(match.awayTeam?.startsWith("TBD:")?" tbd":"")}>
          {match.awayTeam?.startsWith("TBD:") ? "❓ "+match.awayTeam.slice(4) : match.awayTeam}
        </div>
      </div>

      {/* Botón GUARDAR — fila propia debajo del marcador */}
      {match.status!=="finished"&&!match.homeTeam?.startsWith("TBD:")&&!match.awayTeam?.startsWith("TBD:")&&(
        <div className="save-row">
          <button className={"pred-btn"+(saved?" saved":"")} disabled={saving}
            onClick={async()=>{if(h===""||a==="")return;setSaving(true);const r=await onSave(match.id,h,a);setSaving(false);if(r?.success)setSaved(true);}}>
            {saving?"...":saved?"✓ GUARDADO":"GUARDAR PRONÓSTICO"}
          </button>
        </div>
      )}

      {isAdmin&&match.status!=="finished"&&(
        <div className="admin-footer">
          <span style={{fontSize:9,letterSpacing:2,color:"#ff8888",fontFamily:"Barlow Condensed",textTransform:"uppercase"}}>Admin resultado:</span>
          <input className="ainput" type="number" min="0" max="30" value={ah} onChange={e=>setAH(e.target.value)}/>
          <span style={{color:"var(--tx3)"}}>–</span>
          <input className="ainput" type="number" min="0" max="30" value={aa} onChange={e=>setAA(e.target.value)}/>
          <button className="ares-btn" disabled={as2} onClick={async()=>{setAS(true);await onAdminSave(match.id,ah,aa);setAS(false);}}>
            {as2?"...":"GUARDAR"}
          </button>
        </div>
      )}
    </div>
  );
}

// ============================================================
// MATCHES VIEW
// ============================================================
function MatchesView({tournament,user,token,showToast,onPointsUpdate}){
  const {matches:matchSvc,tournaments:tournSvc,predictions:predSvc}=useServices();
  const [matches,setMatches]=useState([]);
  const [group,setGroup]=useState("ALL");
  const [loading,setLoading]=useState(true);
  const [apTab,setApTab]=useState("status");
  const [editStatus,setEditStatus]=useState(tournament.status);
  const [savingStatus,setSavingStatus]=useState(false);
  const [mForm,setMForm]=useState({
    homeTeam:"",awayTeam:"",group:tournament.groups?.[0]||"A",date:"",time:"18:00",stage:"",
    nextMatchWinnerId:"",nextMatchWinnerSlot:"home",
    nextMatchLoserId:"", nextMatchLoserSlot:"home",
  });
  const [addingMatch,setAddingMatch]=useState(false);
  const [matchErr,setMatchErr]=useState("");
  const isAdmin=user.role==="admin";

  const load=useCallback(async()=>{
    const m=await matchSvc.getForUser(tournament.id,user.id);setMatches(m);setLoading(false);
  },[tournament.id,user.id]);
  useEffect(()=>{setLoading(true);load();},[load]);

  const mUpd=k=>e=>setMForm(f=>({...f,[k]:e.target.value}));

  const handleAddMatch=async()=>{
    setMatchErr("");setAddingMatch(true);
    const r=await matchSvc.add(tournament.id,{...mForm,stage:mForm.stage||`Grupo ${mForm.group}`},token);
    setAddingMatch(false);
    if(r.error){setMatchErr(r.error);return;}
    showToast("Partido agregado");
    setMForm(f=>({...f,homeTeam:"",awayTeam:"",date:"",time:"18:00",stage:"",nextMatchWinnerId:"",nextMatchWinnerSlot:"home",nextMatchLoserId:"",nextMatchLoserSlot:"home"}));
    await load();
  };

  if(loading) return <div className="content"><div className="empty">Cargando...</div></div>;

  // Build stage nav from actual match data
  const GROUP_LABELS = {
    A:"Grupo A",B:"Grupo B",C:"Grupo C",D:"Grupo D",E:"Grupo E",F:"Grupo F",
    G:"Grupo G",H:"Grupo H",I:"Grupo I",J:"Grupo J",K:"Grupo K",L:"Grupo L",
    R32:"Ronda de 32",R16:"Octavos",QF:"Cuartos",SF:"Semis",
    "3P":"3er Puesto",FIN:"Final"
  };
  const STAGE_ORDER = ["A","B","C","D","E","F","G","H","I","J","K","L","R32","R16","QF","SF","3P","FIN"];
  const availableGroups = ["ALL", ...STAGE_ORDER.filter(g => matches.some(m=>m.group===g))];

  const groups = availableGroups;
  const filtered=group==="ALL"?matches:matches.filter(m=>m.group===group);
  const predCount=matches.filter(m=>m.myPrediction).length;

  return(
    <div className="content">
      <div className="t-hero">
        <div className="t-hero-banner">
          <div className="t-hero-logo">{tournament.logo}</div>
          <div>
            <div className="t-hero-name">{tournament.name}</div>
            <div className="t-hero-region">{tournament.region}</div>
            <div className="t-hero-dates">📅 {tournament.startDate} → {tournament.endDate}</div>
          </div>
        </div>
        <div className="t-hero-footer">
          <span className={"status-badge "+statusClass(tournament.status)}>{statusLabel(tournament.status)}</span>
          <span style={{fontSize:11,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:1}}>{predCount}/{matches.length} pronósticos</span>
          <span className={"source-chip "+(tournament.source==="fifa_api"?"src-fifa":"src-manual")} style={{marginLeft:"auto"}}>{tournament.source==="fifa_api"?"🌐 FIFA API":"✏ Manual"}</span>
        </div>
      </div>
      {isAdmin&&(
        <div className="admin-panel">
          <div className="ap-hdr">
            <div className="ap-title"><span style={{background:"rgba(255,68,68,.2)",padding:"1px 7px",borderRadius:8,fontSize:9,letterSpacing:2}}>ADMIN</span> Gestión del torneo</div>
          </div>
          <div className="ap-body">
            <div className="ap-tabs">
              <button className={"ap-tab"+(apTab==="status"?" active":"")} onClick={()=>setApTab("status")}>Estado</button>
              <button className={"ap-tab"+(apTab==="addMatch"?" active":"")} onClick={()=>setApTab("addMatch")}>+ Partido</button>
            </div>
            {apTab==="status"&&(
              <div className="ap-form">
                <div style={{display:"flex",flexDirection:"column"}}>
                  <label className="ap-label">Estado</label>
                  <select className="ap-select" value={editStatus} onChange={e=>setEditStatus(e.target.value)}>
                    <option value="upcoming">🟡 Próximo</option><option value="active">🟢 En curso</option><option value="finished">⚫ Finalizado</option>
                  </select>
                </div>
                <button className="btn btn-red" style={{alignSelf:"flex-end"}} onClick={async()=>{setSavingStatus(true);const {tournaments:tournSvcU}=useServices();
          const r=await tournSvcU.update(tournament.id,{status:editStatus},token);setSavingStatus(false);if(r.success)showToast("Estado actualizado");else showToast(r.error,"err");}} disabled={savingStatus}>
                  {savingStatus?"...":"ACTUALIZAR"}
                </button>
              </div>
            )}
            {apTab==="addMatch"&&(
              <>
                {matchErr&&<div className="msg-err" style={{marginBottom:10}}>{matchErr}</div>}
                <div className="mfg">
                  <div className="afield"><label className="ap-label">Local *</label><input className="ap-input" style={{width:"100%"}} value={mForm.homeTeam} onChange={mUpd("homeTeam")} placeholder="ej: Brasil 🇧🇷 o TBD:Ganador SF-1"/></div>
                  <div className="afield"><label className="ap-label">Visitante *</label><input className="ap-input" style={{width:"100%"}} value={mForm.awayTeam} onChange={mUpd("awayTeam")} placeholder="ej: Argentina 🇦🇷 o TBD:Ganador SF-2"/></div>
                  <div className="afield"><label className="ap-label">Grupo / Fase</label>
                    <select className="ap-select" style={{width:"100%"}} value={mForm.group} onChange={mUpd("group")}>
                      {(tournament.groups||["A","B","C","D"]).map(g=><option key={g} value={g}>{GROUP_LABELS?.[g]||"Grupo "+g}</option>)}
                    </select>
                  </div>
                  <div className="afield"><label className="ap-label">Nombre de etapa</label><input className="ap-input" style={{width:"100%"}} value={mForm.stage} onChange={mUpd("stage")} placeholder="ej: Semifinal"/></div>
                  <div className="afield"><label className="ap-label">Fecha</label><input className="ap-input" type="date" style={{width:"100%"}} value={mForm.date} onChange={mUpd("date")}/></div>
                  <div className="afield"><label className="ap-label">Hora</label><input className="ap-input" type="time" style={{width:"100%"}} value={mForm.time} onChange={mUpd("time")}/></div>
                </div>

                {/* Propagation fields — shown when any team has TBD or manually expanded */}
                <details style={{marginTop:8,marginBottom:10}}>
                  <summary style={{fontSize:10,letterSpacing:2,textTransform:"uppercase",color:"var(--gold)",fontFamily:"Barlow Condensed",cursor:"pointer",userSelect:"none"}}>
                    ⚙ Propagación de resultados (fase eliminatoria)
                  </summary>
                  <div style={{marginTop:10,padding:12,background:"rgba(201,168,76,.05)",border:"1px solid rgba(201,168,76,.15)",borderRadius:2}}>
                    <div style={{fontSize:10,color:"var(--tx3)",fontFamily:"Barlow Condensed",letterSpacing:1,marginBottom:10,lineHeight:1.6}}>
                      Configurá a qué partido siguiente avanza el ganador (y el perdedor, si aplica). Usá los IDs de los partidos ya creados.
                    </div>
                    <div className="mfg" style={{marginBottom:0}}>
                      <div className="afield">
                        <label className="ap-label">ID partido siguiente (ganador)</label>
                        <input className="ap-input" style={{width:"100%"}} value={mForm.nextMatchWinnerId} onChange={mUpd("nextMatchWinnerId")} placeholder="ej: m_1234567890"/>
                      </div>
                      <div className="afield">
                        <label className="ap-label">Posición del ganador</label>
                        <select className="ap-select" style={{width:"100%"}} value={mForm.nextMatchWinnerSlot} onChange={mUpd("nextMatchWinnerSlot")}>
                          <option value="home">🏠 Local</option>
                          <option value="away">✈ Visitante</option>
                        </select>
                      </div>
                      <div className="afield">
                        <label className="ap-label">ID partido siguiente (perdedor)</label>
                        <input className="ap-input" style={{width:"100%"}} value={mForm.nextMatchLoserId} onChange={mUpd("nextMatchLoserId")} placeholder="ej: m_1234567891 (tercer puesto)"/>
                      </div>
                      <div className="afield">
                        <label className="ap-label">Posición del perdedor</label>
                        <select className="ap-select" style={{width:"100%"}} value={mForm.nextMatchLoserSlot} onChange={mUpd("nextMatchLoserSlot")}>
                          <option value="home">🏠 Local</option>
                          <option value="away">✈ Visitante</option>
                        </select>
                      </div>
                    </div>
                  </div>
                </details>

                <button className="btn btn-red" onClick={handleAddMatch} disabled={addingMatch}>{addingMatch?"AGREGANDO...":"+ AGREGAR PARTIDO"}</button>
              </>
            )}
          </div>
        </div>
      )}
      <div style={{marginTop:20}}>
        <div className="groups-nav">
          {groups.map(g=>(
            <button key={g} className={"group-btn"+(group===g?" active":"")} onClick={()=>setGroup(g)}>
              {g==="ALL"?"Todos":(GROUP_LABELS[g]||"Grupo "+g)}
            </button>
          ))}
        </div>
        <div className="matches-list">
          {filtered.length===0?(
            <div className="empty">{isAdmin?"Sin partidos. Agregá uno.":"Sin partidos disponibles."}</div>
          ):filtered.map(m=>(
            <MatchCard key={m.id} match={m} tId={tournament.id} userId={user.id} token={token} isAdmin={isAdmin}
              onSave={async(mid,h,a)=>{const r=await predSvc.save(user.id,tournament.id,mid,h,a);if(r.success){showToast("Pronóstico guardado");await load();}else showToast(r.error,"err");return r;}}
              onAdminSave={async(mid,h,a)=>{const r=await matchSvc.setResult(tournament.id,mid,h,a,token);if(r.success){showToast("Resultado guardado");await load();onPointsUpdate&&onPointsUpdate();}else showToast(r.error,"err");}}/>
          ))}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// LEADERBOARD
// ============================================================
function LeaderboardView({activeTournament}){
  const {leaderboard:lbSvc,tournaments:tournSvc}=useServices();
  const [tournaments,setTournaments]=useState([]);
  const [selId,setSelId]=useState(activeTournament?.id||null);
  const [leaders,setLeaders]=useState([]);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{tournSvc.getAll().then(l=>{setTournaments(l);if(!selId&&l.length)setSelId(l[0].id);});},[]);
  useEffect(()=>{if(!selId)return;setLoading(true);lbSvc.get(selId).then(l=>{setLeaders(l);setLoading(false);});},[selId]);
  const rc=i=>i===0?"g":i===1?"s":i===2?"b":"";
  const selT=tournaments.find(t=>t.id===selId);
  return(
    <div className="content">
      <div className="sec-title">CLASIFICACIÓN</div>
      <div className="sec-sub"><span className="db-dot"></span>Puntos por torneo</div>
      {tournaments.length>1&&(
        <div className="groups-nav" style={{marginBottom:18}}>
          {tournaments.map(t=><button key={t.id} className={"group-btn"+(selId===t.id?" active":"")} onClick={()=>setSelId(t.id)}>{t.logo} {t.shortName||t.name}</button>)}
        </div>
      )}
      {selT&&<div style={{marginBottom:14,display:"flex",alignItems:"center",gap:10}}>
        <span style={{fontSize:24}}>{selT.logo}</span>
        <div><div style={{fontFamily:"Bebas Neue",fontSize:17,letterSpacing:3}}>{selT.name}</div>
          <span className={"status-badge "+statusClass(selT.status)} style={{marginTop:3,display:"inline-block"}}>{statusLabel(selT.status)}</span>
        </div>
      </div>}
      {loading?<div className="empty">Cargando...</div>:(
        <>
          <div className="lb">
            <div className="lb-row hdr"><div>#</div><div>Jugador</div><div style={{textAlign:"right"}}>Pts</div><div style={{textAlign:"center"}}>Pred</div><div style={{textAlign:"center"}}>Exactos</div></div>
            {leaders.length===0?<div className="empty">Sin predicciones aún</div>:
              leaders.map((u,i)=>(
                <div key={u.id} className="lb-row">
                  <div className={"rank "+rc(i)}>{i+1}</div>
                  <div className="lb-user"><div className="lb-av">{u.avatar}</div><span style={{fontSize:13,fontWeight:500}}>{u.username}</span></div>
                  <div className="lb-pts">{u.points}</div>
                  <div className="lb-n">{u.predictions}</div>
                  <div className="lb-n" style={{color:"var(--gold)"}}>{u.exact}</div>
                </div>
              ))
            }
          </div>
          <div className="pts-info">
            <strong style={{color:"var(--tx2)"}}>Puntos:</strong>&nbsp;🥇 Exacto=<span style={{color:"var(--gold)"}}>3pts</span>&nbsp;|&nbsp;🥈 Resultado=<span style={{color:"var(--gold)"}}>1pt</span>&nbsp;|&nbsp;❌=<span style={{color:"var(--red)"}}>0pts</span>
          </div>
        </>
      )}
    </div>
  );
}


// ============================================================
// MAIN APP
// ============================================================
export default function App(){
  const [ready,setReady]       = useState(false);
  const [token,setToken]       = useState(null);
  const [user,setUser]         = useState(null);
  const [tab,setTab]           = useState("lobby");
  const [registering,setReg]   = useState(false); // show RegisterWithCodeScreen
  const [activeTournament,setActiveTournament] = useState(null);
  const [toast,setToast]       = useState(null);
  const [tk,setTk]             = useState(0);
  const [pendingInvCount,setPendingInvCount] = useState(0);

  useEffect(()=>{ DatabaseInitializer.init().then(()=>setReady(true)); },[]);

  const showToast=useCallback((msg,type="ok")=>{ setToast({msg,type}); setTk(k=>k+1); },[]);
  const handleLogin=(t,u)=>{ setToken(t); setUser(u); setReg(false); };
  const handleLogout=()=>{ setToken(null); setUser(null); setTab("lobby"); setActiveTournament(null); setPendingInvCount(0); };

  const refreshPts=useCallback(async()=>{
    if(!user||!activeTournament) return;
    const pts=await LeaderboardService.getForUser(user.id,activeTournament.id);
    setUser(p=>({...p,tournamentPoints:pts}));
  },[user,activeTournament]);

  // Poll pending invitations count for admin badge
  useEffect(()=>{
    if(!user||user.role!=="admin") return;
    const check=async()=>{
      const r=await InvitationService.getAll(token);
      if(r.invitations) setPendingInvCount(r.invitations.filter(i=>i.status==="registered").length);
    };
    check();
    const interval=setInterval(check,30000);
    return ()=>clearInterval(interval);
  },[user,token]);

  const isAdmin=user?.role==="admin";

  const tabs=[
    {id:"lobby",        label:"Torneos"},
    {id:"mygroups",     label:"Mis Grupos"},
    {id:"matches",      label:"Partidos",      dis:!activeTournament},
    {id:"leaderboard",  label:"Clasificación"},
    {id:"invitations",  label:"Invitaciones"},
    ...(isAdmin?[{id:"users",label:"Usuarios"}]:[]),
  ];

  if(!ready) return (<><style>{S}</style><div className="app"><Loader text="INICIANDO SUPER CAMPEONES..."/></div></>);

  return(
    <>
      <style>{S}</style>
      <ServiceContext.Provider value={defaultServices}>
      <div className="app">
        {!user ? (
          registering
            ? <RegisterWithCodeScreen onBack={()=>setReg(false)}/>
            : <LoginScreen onLogin={handleLogin} onRegister={()=>setReg(true)}/>
        ):(
          <>
            <nav className="navbar">
              <div className="nav-brand">🏆 SUPER CAMPEONES</div>
              <div className="nav-tabs">
                {tabs.map(t=>(
                  <button key={t.id} className={"nav-tab"+(tab===t.id?" active":"")}
                    style={t.dis?{opacity:.35,cursor:"not-allowed"}:{}}
                    onClick={()=>!t.dis&&setTab(t.id)}>
                    {t.label}
                    {t.id==="matches"&&activeTournament&&(
                      <span style={{marginLeft:5,fontSize:9,color:"var(--gold)",fontFamily:"Barlow Condensed"}}>{activeTournament.logo}</span>
                    )}
                    {t.id==="users"&&isAdmin&&pendingInvCount>0&&<span className="notif-dot"/>}
                  </button>
                ))}
              </div>
              <div className="nav-right">
                <div className="user-badge">
                  <span>{user.avatar}</span>
                  <span style={{fontSize:12}}>{user.username}</span>
                  {isAdmin&&<span className="admin-chip">admin</span>}
                  {activeTournament&&user.tournamentPoints!==undefined&&<span className="pts-chip">{user.tournamentPoints}pts</span>}
                </div>
                <button className="btn btn-ghost" style={{padding:"4px 10px",fontSize:11}} onClick={handleLogout}>Salir</button>
              </div>
            </nav>

            {tab==="mygroups"&&<MyGroupsView user={user} token={token} showToast={showToast}/>}
            {tab==="lobby"&&(
              <TournamentLobby user={user} token={token} showToast={showToast}
                onSelect={t=>{setActiveTournament(t);setTab("matches");}}/>
            )}
            {tab==="matches"&&activeTournament&&(
              <MatchesView tournament={activeTournament} user={user} token={token}
                showToast={showToast} onPointsUpdate={refreshPts}/>
            )}
            {tab==="leaderboard"&&<LeaderboardView activeTournament={activeTournament}/>}
            {tab==="invitations"&&(
              <div className="content">
                <div className="sec-title">INVITACIONES</div>
                <div className="sec-sub">
                  <span className="db-dot"></span>
                  {isAdmin?"Gestioná y aprobá invitaciones de todos los usuarios":"Invitá amigos para participar en torneos"}
                </div>
                <InvitationsView user={user} token={token} showToast={showToast}
                  tournaments={[]} /* loaded inside */
                  key="inv-main"/>
              </div>
            )}
            {tab==="users"&&isAdmin&&(
              <UsersView user={user} token={token} showToast={showToast}/>
            )}
          </>
        )}
        {toast&&<Toast key={tk} message={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      </div>
      </ServiceContext.Provider>
    </>
  );
}