// server.js - Production-ready baseline (Express + JWT + rate limit + CORS + helmet)
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const pino = require("pino");
const pinoHttp = require("pino-http");
const { RateLimiterMemory } = require("rate-limiter-flexible");

const app = express();
const logger = pino({ level: process.env.LOG_LEVEL || "info" });

/* ---------- config ---------- */
const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const ACCESS_TTL_MIN = Number(process.env.ACCESS_TTL_MIN || 20);
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS || 30);
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*"; // set to your app domain in prod

/* ---------- middleware ---------- */
app.use(pinoHttp({ logger }));
app.use(helmet());
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: "256kb" }));

// basic abuse protection: 100 req / 15 min by IP
const rateLimiter = new RateLimiterMemory({ points: 100, duration: 900 });
app.use(async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch {
    res.status(429).json({ error: "Too many requests" });
  }
});

/* ---------- in-memory dev stores (replace with Postgres/Redis in Phase 2) ---------- */
const refreshStore = new Map(); // key: refreshToken -> { sub, exp, deviceId }

/* ---------- helpers ---------- */
const nowSec = () => Math.floor(Date.now() / 1000);
function makeAccess(sub) {
  return jwt.sign({ sub, typ: "access" }, JWT_SECRET, { expiresIn: `${ACCESS_TTL_MIN}m` });
}
function makeRefresh(sub, deviceId = "dev") {
  const exp = nowSec() + REFRESH_TTL_DAYS * 24 * 60 * 60;
  const token = jwt.sign({ sub, typ: "refresh", deviceId }, JWT_SECRET, { expiresIn: `${REFRESH_TTL_DAYS}d` });
  refreshStore.set(token, { sub, exp, deviceId });
  return { token, exp };
}
function verifyAccess(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.sendStatus(401);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.typ !== "access") throw new Error("wrong token type");
    req.user = payload.sub;
    next();
  } catch {
    return res.sendStatus(401);
  }
}

/* ---------- routes ---------- */

// Health
app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

// DEV login: accepts any non-empty creds (we’ll swap to real TA in Phase 3)
app.post("/auth/login", (req, res) => {
  const { username, password, deviceId = "dev" } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  // TODO (Phase 3): exchange {username,password} for a TA session (don’t store raw password)
  // For now: simulate success
  const access = makeAccess(username);
  const { token: refresh, exp } = makeRefresh(username, deviceId);
  res.json({ access_token: access, refresh_token: refresh, exp });
});

app.post("/auth/refresh", (req, res) => {
  const { refresh_token } = req.body || {};
  if (!refresh_token) return res.status(400).json({ error: "Missing refresh_token" });

  try {
    const payload = jwt.verify(refresh_token, JWT_SECRET);
    if (payload.typ !== "refresh") return res.sendStatus(401);
    const stored = refreshStore.get(refresh_token);
    if (!stored) return res.sendStatus(401);
    if (stored.exp < nowSec()) {
      refreshStore.delete(refresh_token);
      return res.sendStatus(401);
    }
    const access = makeAccess(stored.sub);
    const exp = nowSec() + ACCESS_TTL_MIN * 60;
    res.json({ access_token: access, exp });
  } catch {
    return res.sendStatus(401);
  }
});

app.post("/auth/logout", (req, res) => {
  const { refresh_token } = req.body || {};
  if (refresh_token) refreshStore.delete(refresh_token);
  res.json({ ok: true });
});

// Example grades endpoints (protected) — replace with real TA connector in Phase 3
const demoCourses = [
  { id: "MHF4U", name: "Advanced Functions", teacher: "Ms. Kim", overall: 87 },
  { id: "ENG4U", name: "English",            teacher: "Mr. Ross", overall: 92 }
];
const demoDetails = {
  MHF4U: { course: demoCourses[0], assignments: [
    { id:"a1", name:"Quiz 1",  category:"Knowledge",   weight:10, earned:18, outOf:20, percent:90 },
    { id:"a2", name:"Test 1",  category:"Application", weight:15, earned:43, outOf:50, percent:86 },
  ]},
  ENG4U: { course: demoCourses[1], assignments: [
    { id:"b1", name:"Essay Draft", category:"Thinking", weight:10, earned:48, outOf:50, percent:96 },
  ]}
};

app.get("/grades/ping", verifyAccess, (_req, res) => res.json({ ok: true }));
app.get("/grades/courses", verifyAccess, (_req, res) => res.json({ courses: demoCourses }));
app.get("/grades/course/:id", verifyAccess, (req, res) => {
  const data = demoDetails[req.params.id];
  if (!data) return res.sendStatus(404);
  res.json(data);
});

app.use((_req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, "0.0.0.0", () => {
  logger.info(`API listening on http://0.0.0.0:${PORT}`);
});
