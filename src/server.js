const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const { chromium } = require("playwright");
const WebSocket = require("ws");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const PROFILE_ROOT = path.join(__dirname, "..", ".twdrops-profile");
const PROFILES_META_PATH = path.join(PROFILE_ROOT, "profiles.json");
const DEFAULT_PROFILE_ID = "default";
const AUTH_PATH = path.join(PROFILE_ROOT, "auth.json");
const AUTH_COOKIE = "twdrops_token";
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const PUBLIC_DIR = path.join(__dirname, "..", "public");

// Optional: inject these from your own browser if you have them
const ENV_CLIENT_INTEGRITY = process.env.TW_CLIENT_INTEGRITY || null;
const ENV_DEVICE_ID = process.env.TW_DEVICE_ID || null;
const ENV_CLIENT_ID = process.env.TW_CLIENT_ID || "kimne78kx3ncx6brgo4mv6wki5h1ko";

app.use(cors());
app.use(express.json());
app.set("trust proxy", 1);

function isSecure(req) {
  return Boolean(
    req.secure ||
      (req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https"
  );
}

function setAuthCookie(req, res, username, secret) {
  const token = signToken(username, secret);
  res.cookie(AUTH_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: isSecure(req),
    maxAge: TOKEN_TTL_MS,
  });
}

app.get("/auth/register", (req, res) => {
  const data = loadAuthData();
  if (data?.user) {
    return res.redirect("/auth/login");
  }
  res.sendFile(path.join(PUBLIC_DIR, "auth", "register.html"));
});

app.get("/auth/login", (req, res) => {
  const data = loadAuthData();
  if (!data?.user) {
    return res.redirect("/auth/register");
  }
  res.sendFile(path.join(PUBLIC_DIR, "auth", "login.html"));
});

app.post("/auth/register", (req, res) => {
  const data = loadAuthData();
  if (data?.user) {
    return res.status(400).json({ ok: false, error: "Registration already completed. Please log in." });
  }
  const { username, password } = req.body || {};
  if (typeof username !== "string" || username.trim().length < 3) {
    return res.status(400).json({ ok: false, error: "Username must be at least 3 characters." });
  }
  if (typeof password !== "string" || password.length < 6) {
    return res.status(400).json({ ok: false, error: "Password must be at least 6 characters." });
  }
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = hashPassword(password, salt);
  const secret = crypto.randomBytes(32).toString("hex");
  saveAuthData({ user: { username: username.trim(), salt, hash }, secret });
  setAuthCookie(req, res, username.trim(), secret);
  res.json({ ok: true });
});

app.post("/auth/login", (req, res) => {
  const data = loadAuthData();
  if (!data || !data.user) {
    return res.status(400).json({ ok: false, error: "No user registered. Please sign up first." });
  }
  const { username, password } = req.body || {};
  if (username !== data.user.username) {
    return res.status(401).json({ ok: false, error: "Invalid credentials." });
  }
  const hash = hashPassword(password || "", data.user.salt);
  if (hash !== data.user.hash) {
    return res.status(401).json({ ok: false, error: "Invalid credentials." });
  }
  setAuthCookie(req, res, username, ensureAuthSecret(data).secret);
  res.json({ ok: true });
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie(AUTH_COOKIE, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
  res.json({ ok: true });
});

app.use((req, res, next) => {
  if (req.path.startsWith("/auth")) return next();
  const data = ensureAuthSecret();
  if (!data.user) {
    if (req.method === "GET") return res.redirect("/auth/register");
    return res.status(401).json({ ok: false, error: "Registration required." });
  }
  const cookies = parseCookies(req);
  const verified = verifyToken(cookies[AUTH_COOKIE], data.secret);
  if (verified) {
    req.user = verified.username;
    return next();
  }
  if (req.method === "GET") return res.redirect("/auth/login");
  return res.status(401).json({ ok: false, error: "Unauthorized" });
});

app.use(express.static(PUBLIC_DIR, { index: false }));

let browserContext = null;
let browserProfileId = null;
let page = null;
let cachedCookies = [];
let profiles = [];
let activeProfileId = DEFAULT_PROFILE_ID;
let integrityToken = ENV_CLIENT_INTEGRITY || null;
let integrityExpires = 0;
let mainLoginPage = null;
let currentZoom = 1;

const farmSessions = new Map(); // profileId -> { context, page, channel, queue, inProgress }

const EMBED_VIEWPORT = { width: 1024, height: 576 };
const FRAME_INTERVAL_MS = 40;
let frameLoop = null;
let lastFrame = null;
let lastViewport = EMBED_VIEWPORT;
const wsClients = new Set();
let capturing = false;

async function switchToAvailablePage(reason = "") {
  if (!browserContext) return;
  try {
    const candidate = browserContext
      .pages()
      .find((pg) => !pg.isClosed() && pg.url() !== "about:blank");
    if (candidate) {
      await setActivePage(candidate);
      console.log("[login] switched to remaining page", reason || "");
      return;
    }
    if (mainLoginPage && !mainLoginPage.isClosed()) {
      await setActivePage(mainLoginPage);
      console.log("[login] reused main login page", reason || "");
      return;
    }
    const fresh = await browserContext.newPage();
    mainLoginPage = fresh;
    await setActivePage(fresh);
    await fresh.goto("https://www.twitch.tv/login?no-mobile-redirect=true", {
      waitUntil: "domcontentloaded",
    });
    console.log("[login] opened new login page", reason || "");
  } catch (e) {
    console.log("[login] failed switching page after", reason || "close", e.message);
  }
}

async function setActivePage(p) {
  try {
    await p.setViewportSize(EMBED_VIEWPORT);
  } catch (_) {}
  page = p;
  await applyZoom();
  lastFrame = null;
  lastViewport = EMBED_VIEWPORT;
  stopFrameCapture();
  startFrameCapture();
  console.log("[login] active page updated");
}

function summarizeCookies(cookies) {
  const twitchCookies = cookies.filter((c) => c.domain.includes("twitch.tv"));
  const lookup = twitchCookies.reduce((acc, c) => {
    acc[c.name] = c.value;
    return acc;
  }, {});

  return {
    count: twitchCookies.length,
    authToken: lookup["auth-token"] || null,
    deviceId: lookup["device_id"] || lookup["unique_id"] || null,
    language: lookup["language"] || null,
    hasSession: Boolean(lookup["session-token"] || lookup["auth-token"]),
  };
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  return header.split(";").reduce((acc, part) => {
    const [k, v] = part.split("=").map((s) => (s || "").trim());
    if (k && v) acc[k] = decodeURIComponent(v);
    return acc;
  }, {});
}

function loadAuthData() {
  if (!fs.existsSync(AUTH_PATH)) return null;
  try {
    return JSON.parse(fs.readFileSync(AUTH_PATH, "utf8"));
  } catch (e) {
    console.log("[auth] error reading auth file", e.message);
    return null;
  }
}

function saveAuthData(data) {
  try {
    ensureDir(PROFILE_ROOT);
    fs.writeFileSync(AUTH_PATH, JSON.stringify(data, null, 2), "utf8");
  } catch (e) {
    console.log("[auth] error saving auth file", e.message);
  }
}

function hashPassword(password, salt) {
  const derived = crypto.scryptSync(password, salt, 64);
  return derived.toString("hex");
}

function ensureAuthSecret(data = loadAuthData()) {
  if (data && data.secret) return data;
  const updated = data || {};
  updated.secret = crypto.randomBytes(32).toString("hex");
  saveAuthData(updated);
  return updated;
}

function signToken(username, secret) {
  const ts = Date.now();
  const payload = `${username}.${ts}`;
  const hmac = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return `${payload}.${hmac}`;
}

function verifyToken(token, secret) {
  if (!token || !secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [username, tsStr, sig] = parts;
  const ts = Number(tsStr);
  if (!username || !Number.isFinite(ts)) return null;
  if (Date.now() - ts > TOKEN_TTL_MS) return null;
  const expected = crypto.createHmac("sha256", secret).update(`${username}.${ts}`).digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  return { username };
}

function authStatus(req) {
  const data = loadAuthData();
  if (!data || !data.user || !data.secret) return { registered: false, user: null };
  const cookies = parseCookies(req);
  const token = cookies[AUTH_COOKIE];
  const verified = verifyToken(token, data.secret);
  return { registered: true, user: verified ? data.user.username : null };
}

function getProfileDir(profileId = activeProfileId) {
  return profileId === DEFAULT_PROFILE_ID ? PROFILE_ROOT : path.join(PROFILE_ROOT, profileId);
}

function getCookiesCachePath(profileId = activeProfileId) {
  return path.join(getProfileDir(profileId), "cookies.json");
}

function removeProfileDir(profileId) {
  const dir = getProfileDir(profileId);
  if (fs.existsSync(dir)) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      console.log("[profiles] error removing profile folder", profileId, e.message);
    }
  }
}

function loadCachedCookiesFromDisk(profileId = activeProfileId) {
  const cachePath = getCookiesCachePath(profileId);
  if (!fs.existsSync(cachePath)) return [];
  try {
    const raw = fs.readFileSync(cachePath, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    console.log("[cookies] error reading cache", e.message);
    return [];
  }
}

function saveProfilesMeta() {
  try {
    fs.writeFileSync(
      PROFILES_META_PATH,
      JSON.stringify({ active: activeProfileId, profiles }, null, 2),
      "utf8"
    );
  } catch (e) {
    console.log("[profiles] error guardando metadatos", e.message);
  }
}

function listProfilesWithSummary() {
  return profiles.map((p) => ({
    ...p,
    cookies: summarizeCookies(loadCachedCookiesFromDisk(p.id)),
  }));
}

function bootstrapProfiles() {
  ensureDir(PROFILE_ROOT);
  let stored = null;
  if (fs.existsSync(PROFILES_META_PATH)) {
    try {
      stored = JSON.parse(fs.readFileSync(PROFILES_META_PATH, "utf8"));
    } catch (e) {
      console.log("[profiles] error leyendo metadatos, se regeneran", e.message);
    }
  }

  if (!stored || !Array.isArray(stored.profiles) || !stored.profiles.length) {
    profiles = [
      {
        id: DEFAULT_PROFILE_ID,
        name: "Profile 1",
        createdAt: Date.now(),
        lastUsed: Date.now(),
      },
    ];
    activeProfileId = DEFAULT_PROFILE_ID;
    saveProfilesMeta();
  } else {
    profiles = stored.profiles.map((p, idx) => ({
      id: p.id || `profile-${idx + 1}`,
      name: p.name || `Profile ${idx + 1}`,
      createdAt: p.createdAt || Date.now(),
      lastUsed: p.lastUsed || Date.now(),
    }));
    activeProfileId =
      stored.active && profiles.some((p) => p.id === stored.active)
        ? stored.active
        : profiles[0].id;
  }

  profiles.forEach((p) => ensureDir(getProfileDir(p.id)));
  cachedCookies = loadCachedCookiesFromDisk(activeProfileId);
  if (cachedCookies.length) {
    console.log("[cookies] cookie cache loaded for profile", activeProfileId, cachedCookies.length);
  }
}

async function setActiveProfile(id) {
  const profile = profiles.find((p) => p.id === id);
  if (!profile) {
    throw new Error("Profile not found.");
  }
  if (id === activeProfileId) {
    return summarizeCookies(cachedCookies);
  }
  await stopEmbeddedSession();
  browserProfileId = null;
  integrityToken = ENV_CLIENT_INTEGRITY || null;
  integrityExpires = 0;
  activeProfileId = id;
  profile.lastUsed = Date.now();
  cachedCookies = loadCachedCookiesFromDisk(activeProfileId);
  saveProfilesMeta();
  return summarizeCookies(cachedCookies);
}

bootstrapProfiles();

function findCompatibleBrowser() {
  const candidates = [
    "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",
    "C:\\\\Program Files (x86)\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",
    "C:\\\\Program Files\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe",
    "C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe",
  ];
  for (const exe of candidates) {
    if (fs.existsSync(exe)) return exe;
  }
  return chromium.executablePath();
}

async function startEmbeddedLogin() {
  const profileDir = getProfileDir();
  ensureDir(profileDir);

  if (browserContext) {
    await browserContext.close();
    browserContext = null;
    browserProfileId = null;
    page = null;
  }
  stopFrameCapture();
  lastFrame = null;
  lastViewport = EMBED_VIEWPORT;

  const executablePath = findCompatibleBrowser();
  const spoofedUA =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";

  browserContext = await chromium.launchPersistentContext(profileDir, {
    headless: true,
    userAgent: spoofedUA,
    locale: "es-ES",
    timezoneId: "Europe/Madrid",
    permissions: ["geolocation"],
    ignoreDefaultArgs: ["--enable-automation"],
    args: ["--disable-blink-features=AutomationControlled"],
    viewport: EMBED_VIEWPORT,
    executablePath,
  });
  browserProfileId = activeProfileId;

  browserContext.on("page", async (p) => {
    console.log("[login] new page detected (popup/external login)");
    try {
      await setActivePage(p);
      p.once("close", async () => {
        // When the popup closes, fall back to any remaining page
        await switchToAvailablePage("popup close");
      });
    } catch (e) {
      console.log("[login] error activating new page", e.message);
    }
  });

  mainLoginPage = await browserContext.newPage();
  mainLoginPage.once("close", () => switchToAvailablePage("main page close"));
  await setActivePage(mainLoginPage);
  await mainLoginPage.goto("https://www.twitch.tv/login?no-mobile-redirect=true", {
    waitUntil: "domcontentloaded",
  });
  console.log("[login] embedded context created with", executablePath, "profile", activeProfileId);
}

function getFarmState(profileId = activeProfileId) {
  if (!farmSessions.has(profileId)) {
    farmSessions.set(profileId, { context: null, page: null, channel: null, queue: [], inProgress: false });
  }
  return farmSessions.get(profileId);
}

async function ensureContextForFarm(profileId = activeProfileId) {
  const state = getFarmState(profileId);
  if (state.context) return state.context;
  const profileDir = getProfileDir(profileId);
  ensureDir(profileDir);
  const executablePath = findCompatibleBrowser();
  const spoofedUA =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";

  state.context = await chromium.launchPersistentContext(profileDir, {
    headless: true,
    userAgent: spoofedUA,
    locale: "es-ES",
    timezoneId: "Europe/Madrid",
    permissions: ["geolocation"],
    ignoreDefaultArgs: ["--enable-automation"],
    args: ["--disable-blink-features=AutomationControlled"],
    viewport: EMBED_VIEWPORT,
    executablePath,
  });
  farmSessions.set(profileId, state);
  console.log("[farm] background context created", executablePath, "profile", profileId);
  return state.context;
}

async function stopEmbeddedSession() {
  stopFrameCapture();
  lastFrame = null;
  lastViewport = EMBED_VIEWPORT;
  if (page && !page.isClosed()) {
    try {
      await page.close();
    } catch (e) {
      console.log("[stop] error closing page", e.message);
    }
  }
  page = null;
  if (browserContext) {
    try {
      await browserContext.close();
    } catch (e) {
      console.log("[stop] error closing context", e.message);
    }
  }
  browserContext = null;
  browserProfileId = null;
  console.log("[stop] embedded session stopped");
}

async function captureCookies() {
  if (!browserContext) {
    throw new Error("No browser session is open.");
  }
  cachedCookies = await browserContext.cookies();
  try {
    ensureDir(getProfileDir());
    fs.writeFileSync(getCookiesCachePath(), JSON.stringify(cachedCookies, null, 2), "utf8");
    const profile = profiles.find((p) => p.id === activeProfileId);
    if (profile) {
      profile.lastUsed = Date.now();
      saveProfilesMeta();
    }
    console.log("[cookies] cache saved", cachedCookies.length, "profile", activeProfileId);
  } catch (e) {
    console.log("[cookies] error saving cache", e.message);
  }
  return summarizeCookies(cachedCookies);
}

function startFrameCapture() {
  stopFrameCapture();
  frameLoop = setTimeout(frameTick, FRAME_INTERVAL_MS);
  console.log("[frame] capture started");
}

async function frameTick() {
  if (!page || page.isClosed()) {
    frameLoop = null;
    return;
  }
  if (!capturing) {
    capturing = true;
    try {
      const vp = page.viewportSize() || EMBED_VIEWPORT;
      const buffer = await page.screenshot({
        type: "jpeg",
        quality: 45,
        fullPage: false,
        clip: { x: 0, y: 0, width: vp.width, height: vp.height },
      });
      lastFrame = buffer.toString("base64");
      lastViewport = vp;
      broadcastFrame(lastFrame, lastViewport);
    } catch (e) {
      console.log("[frame] error capturing frame", e.message);
    } finally {
      capturing = false;
    }
  }
  frameLoop = setTimeout(frameTick, FRAME_INTERVAL_MS);
}

function stopFrameCapture() {
  if (frameLoop) {
    clearTimeout(frameLoop);
    frameLoop = null;
    console.log("[frame] capture stopped");
  }
  capturing = false;
}

function broadcastFrame(image, viewport) {
  for (const ws of wsClients) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "frame", image, viewport }));
    } else {
      wsClients.delete(ws);
    }
  }
}

async function applyZoom() {
  if (page && !page.isClosed()) {
    try {
      await page.evaluate(
        (z) => {
          document.documentElement.style.zoom = z;
        },
        currentZoom
      );
    } catch (e) {
      console.log("[zoom] error aplicando zoom", e.message);
    }
  }
}

function getAuthToken() {
  const authCookie = cachedCookies.find((c) => c.name === "auth-token");
  return authCookie && authCookie.value ? authCookie.value : null;
}

function getDeviceId() {
  const deviceCookie = cachedCookies.find((c) => c.name === "device_id");
  return ENV_DEVICE_ID || (deviceCookie && deviceCookie.value) || null;
}

function getDeviceIdOrGenerate() {
  const existing = getDeviceId();
  if (existing) return existing;
  return crypto.randomUUID();
}

async function ensureIntegrityToken(token, clientId, deviceId) {
  const now = Date.now();
  if (integrityToken && integrityExpires > now) {
    return integrityToken;
  }
  if (ENV_CLIENT_INTEGRITY) {
    integrityToken = ENV_CLIENT_INTEGRITY;
    integrityExpires = now + 30 * 60 * 1000;
    return integrityToken;
  }

  const res = await fetch("https://gql.twitch.tv/integrity", {
    method: "POST",
    headers: {
      Authorization: `OAuth ${token}`,
      "Client-Id": clientId,
      "X-Device-Id": deviceId,
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
      "Content-Type": "application/json",
    },
    body: "{}",
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Could not fetch Client-Integrity (${res.status}): ${text}`);
  }

  const data = await res.json();
  const tokenValue = data?.token;
  if (!tokenValue) {
    throw new Error("Integrity response did not include a token.");
  }
  integrityToken = tokenValue;
  integrityExpires = Date.now() + (data?.expiration || 20 * 60 * 1000);
  console.log("[integrity] new token obtained, expires in ms:", integrityExpires - Date.now());
  return integrityToken;
}

async function fetchAccountStats() {
  if (!cachedCookies.length) {
    throw new Error("No cookies captured yet.");
  }
  const token = getAuthToken();
  if (!token) {
    throw new Error("Missing auth-token cookie. Sign in and capture again.");
  }

  const validateRes = await fetch("https://id.twitch.tv/oauth2/validate", {
    headers: {
      Authorization: `OAuth ${token}`,
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    },
  });

  if (!validateRes.ok) {
    const text = await validateRes.text();
    throw new Error(`Invalid token (${validateRes.status}). Sign in again and recapture. Response: ${text}`);
  }

  const validate = await validateRes.json();
  const clientId = validate.client_id || ENV_CLIENT_ID;

  const body = {
    operationName: "CurrentUser",
    variables: {},
    query:
      "query CurrentUser { currentUser { id login displayName description createdAt profileImageURL(width:300) bannerImageURL roles { isAffiliate isPartner } } }",
  };

  const res = await fetch("https://gql.twitch.tv/gql", {
    method: "POST",
    headers: {
      "Client-Id": clientId,
      Authorization: `OAuth ${token}`,
      "Content-Type": "application/json",
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
      Origin: "https://www.twitch.tv",
      Referer: "https://www.twitch.tv/",
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Twitch responded ${res.status}: ${text}`);
  }

  const data = await res.json();
  const user = data?.data?.currentUser;
  if (!user) {
    const errors = data?.errors ? JSON.stringify(data.errors) : "no details";
    throw new Error(`Could not fetch the user. Check your login/cookies. Errors: ${errors}`);
  }

  return {
    id: user.id,
    login: user.login,
    displayName: user.displayName,
    description: user.description,
    createdAt: user.createdAt,
    profileImageURL: user.profileImageURL,
    bannerImageURL: user.bannerImageURL,
    affiliate: user.roles?.isAffiliate || false,
    partner: user.roles?.isPartner || false,
  };
}

async function fetchActiveDrops() {
  if (!cachedCookies.length) {
    throw new Error("No cookies captured yet.");
  }
  const token = getAuthToken();
  if (!token) {
    throw new Error("Missing auth-token. Please log in and capture again.");
  }

  const validateRes = await fetch("https://id.twitch.tv/oauth2/validate", {
    headers: {
      Authorization: `OAuth ${token}`,
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    },
  });
  if (!validateRes.ok) {
    const text = await validateRes.text();
    console.log("[drops] validate error", validateRes.status, text);
    throw new Error("Invalid token; capture cookies again.");
  }
  const validate = await validateRes.json();
  const clientId = ENV_CLIENT_ID || validate.client_id || "kimne78kx3ncx6brgo4mv6wki5h1ko";
  const device = getDeviceIdOrGenerate();
  const integrity = await ensureIntegrityToken(token, clientId, device);
  console.log("[drops] token validated, clientId:", clientId, "device:", device, "integrity:", Boolean(integrity));

  const headers = {
    Authorization: `OAuth ${token}`,
    "Client-Id": clientId,
    "Client-Integrity": integrity,
    "X-Device-Id": device,
    "Content-Type": "application/json",
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    Origin: "https://www.twitch.tv",
    Referer: "https://www.twitch.tv/",
  };

  const tryGql = async (body) => {
    console.log("[drops] GQL request", body.operationName || "unknown");
    const res = await fetch("https://gql.twitch.tv/gql", {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      console.log("[drops] GQL error", res.status, text);
      throw new Error(`GQL error ${res.status}: ${text}`);
    }
    const json = await res.json();
    console.log("[drops] GQL ok", body.operationName || "unknown");
    return json;
  };

  // 1) Persisted query "Inventory" that returns dropCampaignsInProgress
  try {
    const gqlBody = {
      operationName: "Inventory",
      variables: { fetchRewardCampaigns: true },
      extensions: {
        persistedQuery: {
          version: 1,
          sha256Hash: "d86775d0ef16a63a33ad52e80eaff963b2d5b72fada7c991504a57496e1d8e4b",
        },
      },
    };
    const payload = await tryGql(gqlBody);
    const campaigns =
      payload?.data?.currentUser?.inventory?.dropCampaignsInProgress || [];
    console.log("[drops] Inventory campaigns length:", campaigns.length || 0);
    if (Array.isArray(campaigns) && campaigns.length) {
      return campaigns.map((c) => {
        const benefits =
          (c.timeBasedDrops || []).map((d) => ({
            id: d.id,
            name: d.name,
            requiredMinutes: d.requiredMinutesWatched,
            currentMinutes: d.self?.currentMinutesWatched || 0,
            image: d.benefitEdges?.[0]?.benefit?.imageAssetURL || null,
            progressText: d.localizedContent?.progress || null,
          })) || [];
        return {
        id: c.id,
        name: c.name || "Campaign",
        game: c.game?.name || c.game?.displayName || c.game?.id || "Game",
        gameId: c.game?.id || null,
        gameName: c.game?.name || c.game?.displayName || null,
        status: c.status || "ACTIVE",
        startAt: c.startAt || null,
        endAt: c.endAt || null,
        benefits,
        requiredMinutes:
          (c.timeBasedDrops && c.timeBasedDrops[0]?.requiredMinutesWatched) ||
          null,
        imageURL: c.imageURL || null,
        detailsURL: c.detailsURL || null,
        channels: c.allow?.channels || [],
        gameSlug: c.game?.slug || null,
        gameId: c.game?.id || null,
        gameName: c.game?.name || c.game?.displayName || null,
      };
    });
    }
  } catch (e) {
    console.log("[drops] Inventory hash failed", e.message);
  }

  // 2) Persisted query for available campaigns
  try {
    const gqlBody = {
      operationName: "DropsHighlightService_AvailableDropCampaigns",
      variables: {},
      extensions: {
        persistedQuery: {
          version: 1,
          sha256Hash:
            "6c2d76f0d8e5f2f4d30c8b0177b36c6f5434a06df22b58c4a9b74eb58f2d46b0",
        },
      },
    };
    const payload = await tryGql(gqlBody);
    const campaigns =
      payload?.data?.dropsHighlightService?.availableDropCampaigns ||
      payload?.data?.availableDropCampaigns ||
      payload?.data?.currentUser?.dropCampaigns ||
      [];
    console.log("[drops] persisted campaigns length:", campaigns.length || 0);
    if (Array.isArray(campaigns) && campaigns.length) {
      return campaigns.map((c) => {
        const benefits =
          (c.timeBasedDrops || c.benefits || []).map((d) => ({
            id: d.id,
            name: d.name,
            requiredMinutes: d.requiredMinutesWatched || d.required_minutes,
            currentMinutes: d.self?.currentMinutesWatched || 0,
            image: d.benefitEdges?.[0]?.benefit?.imageAssetURL || d.imageAssetURL || null,
            progressText: d.localizedContent?.progress || null,
          })) || [];
        return {
        id: c.id,
        name: c.name || c.displayName || c.statusText || "Campaign",
        game: c.game?.name || c.game?.displayName || c.game?.id || "Game",
        gameId: c.game?.id || null,
        gameName: c.game?.name || c.game?.displayName || null,
        gameSlug: c.game?.slug || null,
        status: c.status || c.state || "ACTIVE",
        startAt: c.start_at || c.startAt || c.startTime || null,
        endAt: c.end_at || c.endAt || c.endTime || null,
        benefits,
        requiredMinutes: c.required_minutes || c.requiredMinutes || null,
        channels: c.allow?.channels || [],
      };
    });
    }
  } catch (e) {
    console.log("[drops] persisted drops failed", e.message);
  }

  // 3) Helix inventory como ultimo recurso
  try {
    const url = "https://api.twitch.tv/helix/drops/inventory";
    const dropsRes = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Client-Id": clientId,
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
      },
    });
    if (dropsRes.ok) {
      const payload = await dropsRes.json();
      const data = payload?.data || [];
      console.log("[drops] helix inventory length:", data.length || 0);
      if (data.length) {
        return data.map((d) => ({
          id: d.id || d.campaign_id || "drop",
          name: d.name || d.benefit_id || "Drop",
          game: d.game_name || d.game_id || "Game",
          status: d.status || "ACTIVE",
          startAt: d.unlocked_at || null,
          endAt: d.expires_at || null,
          benefits: [],
          requiredMinutes: null,
        }));
      }
    } else {
      const text = await dropsRes.text();
      console.log("[drops] helix status", dropsRes.status, text);
    }
  } catch (e) {
    console.log("[drops] helix inventory failed", e.message);
  }

  throw new Error(
    "No drop campaigns were found. Check the server logs to see which steps failed."
  );
}

app.post("/api/drops/channels", async (req, res) => {
  try {
    const { gameSlug, gameName } = req.body || {};
    if (!gameSlug && !gameName) {
      return res.status(400).json({ ok: false, error: "Missing gameSlug or gameName." });
    }
    const token = getAuthToken();
    if (!token) {
      return res.status(400).json({ ok: false, error: "auth-token cookie not found." });
    }
    const validateRes = await fetch("https://id.twitch.tv/oauth2/validate", {
      headers: { Authorization: `OAuth ${token}` },
    });
    if (!validateRes.ok) {
      return res.status(400).json({ ok: false, error: "Invalid token." });
    }
    const validate = await validateRes.json();
    const clientId = ENV_CLIENT_ID || validate.client_id || "kimne78kx3ncx6brgo4mv6wki5h1ko";
    const device = getDeviceIdOrGenerate();
    const integrity = await ensureIntegrityToken(token, clientId, device);

    const slug =
      gameSlug ||
      (gameName ? gameName.toLowerCase().replace(/\s+/g, "-") : null) ||
      null;
    if (!slug) {
      return res.status(400).json({ ok: false, error: "Game slug not available." });
    }

    const headers = {
      Authorization: `OAuth ${token}`,
      "Client-Id": clientId,
      "Client-Integrity": integrity,
      "X-Device-Id": device,
      "Content-Type": "application/json",
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
      Origin: "https://www.twitch.tv",
      Referer: "https://www.twitch.tv/",
    };

    const queryDirectory = async (withDropsTag = true) => {
      const dropsTag = "c2542d6d-cd10-4532-919b-3d19f30a768b";
      const tagsArray = withDropsTag ? [dropsTag] : [];
      const gqlBody = {
        operationName: "DirectoryPage_Game",
        variables: {
          slug,
          imageWidth: 50,
          includeCostreaming: true,
          includeRestricted: ["SUB_ONLY_LIVE"],
          sort: "RELEVANCE",
          recommendationsContext: { platform: "web" },
          requestID: "JIRA-VXP-2397",
          sortTypeIsRecency: false,
          freeformTags: null,
          tags: tagsArray,
          broadcasterLanguages: [],
          limit: 30,
          options: {
            includeRestricted: ["SUB_ONLY_LIVE"],
            sort: "RELEVANCE",
            recommendationsContext: { platform: "web" },
            requestID: "JIRA-VXP-2397",
            sortTypeIsRecency: false,
            freeformTags: null,
            tags: tagsArray,
            broadcasterLanguages: [],
            systemFilters: [],
            limit: 30,
          },
        },
        extensions: {
          persistedQuery: {
            version: 1,
            sha256Hash:
              "76cb069d835b8a02914c08dc42c421d0dafda8af5b113a3f19141824b901402f",
          },
        },
      };

      const gqlRes = await fetch("https://gql.twitch.tv/gql", {
        method: "POST",
        headers,
        body: JSON.stringify([gqlBody]),
      });
      if (!gqlRes.ok) {
        const t = await gqlRes.text();
        console.log("[auto-channel] gql directory status", gqlRes.status, t);
        return [];
      }
      const arr = await gqlRes.json();
      const data = Array.isArray(arr) ? arr[0] : arr;
      const edges = data?.data?.game?.streams?.edges || [];
      console.log("[auto-channel] directory edges:", edges.length, "dropsTag:", withDropsTag);
      return edges;
    };

    let edges = await queryDirectory(true);
    if (!edges.length) {
      edges = await queryDirectory(false);
    }
    if (!edges.length) {
      return res.status(404).json({ ok: false, error: "No live streams found in the directory." });
    }
    const list = edges.map((e) => ({
      channel: e?.node?.broadcaster?.login,
      displayName: e?.node?.broadcaster?.displayName,
      title: e?.node?.title,
      viewers: e?.node?.viewersCount,
      tags: (e?.node?.freeformTags || []).map((t) => t.name),
      profileImage: e?.node?.broadcaster?.profileImageURL,
      preview: e?.node?.previewImageURL || e?.node?.verticalPreviewImageURL,
    }));
    res.json({ ok: true, channels: list });
  } catch (err) {
    console.log("[auto-channel] error", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

async function startFarmStream(channel, profileId = activeProfileId) {
  const state = getFarmState(profileId);
  const context = await ensureContextForFarm(profileId);
  if (!channel) {
    throw new Error("Channel to farm is missing.");
  }
  if (state.page && !state.page.isClosed()) {
    try {
      await state.page.close();
    } catch (e) {
      console.log("[farm] error closing previous farmPage", e.message);
    }
  }

  const openAndPlay = async () => {
    state.page = await context.newPage();
    await state.page.goto(`https://www.twitch.tv/${channel}`, { waitUntil: "domcontentloaded" });
    await state.page.waitForTimeout(3000);
    if (state.page.isClosed()) throw new Error("Farm page closed right after opening.");
    try {
      await state.page.evaluate(() => {
        const btn = document.querySelector('[data-a-target="player-play-pause-button"]');
        if (btn && btn.getAttribute("data-paused") === "true") {
          btn.click();
        }
        const video = document.querySelector("video");
        if (video) {
          video.muted = true;
          video.play().catch(() => {});
        }
      });
    } catch (e) {
      console.log("[farm] unable to force play", e.message);
    }
  };

  try {
    await openAndPlay();
  } catch (e) {
    console.log("[farm] retrying channel open", e.message);
    await openAndPlay();
  }

  state.channel = channel;
  state.inProgress = true;
  state.queue = state.queue || [];
  farmSessions.set(profileId, state);
  return getFarmStatus(profileId);
}

async function stopFarmStream(profileId = activeProfileId) {
  const state = getFarmState(profileId);
  if (state.page && !state.page.isClosed()) {
    try {
      await state.page.close();
    } catch (e) {
      console.log("[farm] error closing farmPage", e.message);
    }
  }
  state.page = null;
  state.channel = null;
  state.inProgress = false;
  state.queue = [];
  farmSessions.set(profileId, state);
  return { active: false, channel: null, playing: false };
}

async function getFarmStatus(profileId = activeProfileId) {
  const state = getFarmState(profileId);
  const page = state.page;
  if (!page || page.isClosed()) {
    state.page = null;
    const ch = state.channel;
    state.channel = null;
    state.inProgress = false;
    if (state.queue && state.queue.length > 0) {
      const next = state.queue.shift();
      if (next) {
        try {
          await startFarmStream(next, profileId);
        } catch (e) {
          console.log("[farm] error starting next in queue", e.message);
          state.inProgress = false;
        }
      }
    }
    farmSessions.set(profileId, state);
    return { active: false, channel: ch || null, playing: false };
  }
  try {
    const playing = await page.evaluate(() => {
      const video = document.querySelector("video");
      return video ? !video.paused : false;
    });
    if (!playing && state.queue && state.queue.length > 0) {
      const next = state.queue.shift();
      if (next) {
        console.log("[farm] switching to next in queue", next);
        await startFarmStream(next, profileId);
      }
    }
    farmSessions.set(profileId, state);
    return { active: true, channel: state.channel, playing, queue: state.queue };
  } catch (e) {
    console.log("[farm] error obteniendo status", e.message);
    return { active: false, channel: state.channel, playing: false, error: e.message };
  }
}

app.post("/api/drops/farm/start", async (req, res) => {
  try {
    const { channel, queue } = req.body || {};
    const profileId = activeProfileId;
    const state = getFarmState(profileId);
    if (!channel && !Array.isArray(queue)) {
      return res.status(400).json({ ok: false, error: "Channel or queue is required." });
    }
    if (Array.isArray(queue)) {
      state.queue = queue.filter(Boolean);
      console.log("[farm] queue updated", state.queue);
    }
    if (channel) {
      const status = await startFarmStream(channel, profileId);
      res.json({ ok: true, status });
    } else {
      res.json({ ok: true, status: await getFarmStatus(profileId) });
    }
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post("/api/drops/farm/stop", async (req, res) => {
  try {
    const profileId = activeProfileId;
    const status = await stopFarmStream(profileId);
    res.json({ ok: true, status });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.get("/api/drops/farm/status", async (req, res) => {
  try {
    const profileId = activeProfileId;
    const status = await getFarmStatus(profileId);
    const state = getFarmState(profileId);
    res.json({ ok: true, status, queue: state.queue, inProgress: state.inProgress });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.get("/api/profiles", (req, res) => {
  try {
    res.json({ ok: true, active: activeProfileId, profiles: listProfilesWithSummary() });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/profiles", async (req, res) => {
  try {
    const { name } = req.body || {};
    const label =
      typeof name === "string" && name.trim().length
        ? name.trim().slice(0, 60)
        : `Profile ${profiles.length + 1}`;
    const id = `profile-${Date.now().toString(36)}-${crypto.randomUUID().split("-")[0]}`;
    profiles.push({
      id,
      name: label,
      createdAt: Date.now(),
      lastUsed: Date.now(),
    });
    ensureDir(getProfileDir(id));
    await setActiveProfile(id);
    res.json({ ok: true, active: activeProfileId, profiles: listProfilesWithSummary() });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post("/api/profiles/active", async (req, res) => {
  try {
    const { id } = req.body || {};
    if (!id) {
      return res.status(400).json({ ok: false, error: "Profile id is missing." });
    }
    await setActiveProfile(id);
    res.json({ ok: true, active: activeProfileId, profiles: listProfilesWithSummary() });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.delete("/api/profiles/:id", async (req, res) => {
  try {
    const { id } = req.params || {};
    if (!id) return res.status(400).json({ ok: false, error: "Profile id is missing." });
    const idx = profiles.findIndex((p) => p.id === id);
    if (idx === -1) return res.status(404).json({ ok: false, error: "Profile not found." });
    if (profiles.length <= 1) {
      return res.status(400).json({ ok: false, error: "At least one profile must remain." });
    }
    const deletingActive = id === activeProfileId;
    const farmState = farmSessions.get(id);
    if (farmState) {
      if (farmState.page && !farmState.page.isClosed()) {
        try {
          await farmState.page.close();
        } catch (e) {
          console.log("[profiles] error closing farm page while deleting profile", e.message);
        }
      }
      if (farmState.context) {
        try {
          await farmState.context.close();
        } catch (e) {
          console.log("[profiles] error closing farm context while deleting profile", e.message);
        }
      }
      farmSessions.delete(id);
    }
    profiles.splice(idx, 1);
    removeProfileDir(id);
    if (deletingActive) {
      await stopEmbeddedSession();
      integrityToken = ENV_CLIENT_INTEGRITY || null;
      integrityExpires = 0;
      activeProfileId = profiles[0].id;
      cachedCookies = loadCachedCookiesFromDisk(activeProfileId);
    }
    saveProfilesMeta();
    res.json({ ok: true, active: activeProfileId, profiles: listProfilesWithSummary() });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/status", (req, res) => {
  const activeProfile = profiles.find((p) => p.id === activeProfileId);
  const farmState = getFarmState(activeProfileId);
  res.json({
    browserOpen: Boolean(browserContext),
    hasPage: Boolean(page),
    cookies: summarizeCookies(cachedCookies),
    farm: { channel: farmState.channel, inProgress: farmState.inProgress },
    profile: {
      id: activeProfileId,
      name: activeProfile?.name || "Profile",
    },
  });
});

app.post("/api/login/start", async (req, res) => {
  try {
    await startEmbeddedLogin();
    console.log("[api] /login/start ok");
    res.json({
      ok: true,
      message: "Embedded browser ready. Use the built-in viewer to sign in to Twitch.",
      viewport: EMBED_VIEWPORT,
    });
  } catch (err) {
    console.log("[api] /login/start error", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/login/stop", async (req, res) => {
  try {
    await stopEmbeddedSession();
    res.json({ ok: true, message: "Embedded session closed." });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/login/frame", async (req, res) => {
  try {
    console.log("[api] /login/frame hit");
    if (!page || page.isClosed()) {
      return res.status(400).json({ ok: false, error: "No embedded session is active." });
    }
    if (!lastFrame) {
      console.log("[frame] no previous frame available, capturing in /frame");
      const vp = page.viewportSize() || EMBED_VIEWPORT;
      const buffer = await page.screenshot({
        type: "jpeg",
        quality: 50,
        fullPage: false,
        clip: { x: 0, y: 0, width: vp.width, height: vp.height },
      });
      lastFrame = buffer.toString("base64");
      lastViewport = vp;
    }
    res.json({
      ok: true,
      image: lastFrame,
      viewport: lastViewport,
    });
  } catch (err) {
    console.log("[api] /login/frame error", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/login/click", async (req, res) => {
  try {
    const { x, y } = req.body || {};
    if (!page || page.isClosed()) {
      return res.status(400).json({ ok: false, error: "No embedded session is active." });
    }
    if (typeof x !== "number" || typeof y !== "number") {
      return res.status(400).json({ ok: false, error: "Invalid coordinates." });
    }
    await page.mouse.click(x, y);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/login/type", async (req, res) => {
  try {
    const { text } = req.body || {};
    if (!page || page.isClosed()) {
      return res.status(400).json({ ok: false, error: "No embedded session is active." });
    }
    await page.keyboard.type(text || "");
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/login/key", async (req, res) => {
  try {
    const { key } = req.body || {};
    if (!page || page.isClosed()) {
      return res.status(400).json({ ok: false, error: "No embedded session is active." });
    }
    await page.keyboard.press(key || "Enter");
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/login/scroll", async (req, res) => {
  try {
    const { deltaY } = req.body || {};
    if (!page || page.isClosed()) {
      return res.status(400).json({ ok: false, error: "No embedded session is active." });
    }
    await page.mouse.wheel(0, Number(deltaY) || 400);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/login/zoom", async (req, res) => {
  try {
    const { delta } = req.body || {};
    if (!page || page.isClosed()) {
      return res.status(400).json({ ok: false, error: "No embedded session is active." });
    }
    const num = Number(delta) || 0;
    currentZoom = Math.min(2, Math.max(0.5, currentZoom + num));
    await applyZoom();
    res.json({ ok: true, zoom: currentZoom });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/drops/auto-channel", async (req, res) => {
  try {
    const { gameId, gameName, gameSlug } = req.body || {};
    if (!gameId && !gameName && !gameSlug) {
      return res.status(400).json({ ok: false, error: "Missing gameId or gameName/slug." });
    }
    const token = getAuthToken();
    if (!token) {
      return res.status(400).json({ ok: false, error: "auth-token cookie not found." });
    }
    const validateRes = await fetch("https://id.twitch.tv/oauth2/validate", {
      headers: {
        Authorization: `OAuth ${token}`,
      },
    });
    if (!validateRes.ok) {
      return res.status(400).json({ ok: false, error: "Invalid token." });
    }
    const validate = await validateRes.json();
    const clientId = ENV_CLIENT_ID || validate.client_id || "kimne78kx3ncx6brgo4mv6wki5h1ko";

    const headers = {
      Authorization: `Bearer ${token}`,
      "Client-Id": clientId,
      "User-Agent": "Mozilla/5.0",
    };

    // Attempt 1: GQL DirectoryPage_Game (streams with drops tag)
    try {
      const slug =
        gameSlug ||
        (gameName ? gameName.toLowerCase().replace(/\s+/g, "-") : null) ||
        null;
      if (slug) {
        const dropsTag = "c2542d6d-cd10-4532-919b-3d19f30a768b";
        const tagsArray = [dropsTag];
        const gqlBody = {
          operationName: "DirectoryPage_Game",
          variables: {
            slug,
            imageWidth: 50,
            includeCostreaming: true,
            includeRestricted: ["SUB_ONLY_LIVE"],
            sort: "RELEVANCE",
            recommendationsContext: { platform: "web" },
            requestID: "JIRA-VXP-2397",
            sortTypeIsRecency: false,
            freeformTags: null,
            tags: tagsArray,
            broadcasterLanguages: [],
            limit: 30,
            options: {
              includeRestricted: ["SUB_ONLY_LIVE"],
              sort: "RELEVANCE",
              recommendationsContext: { platform: "web" },
              requestID: "JIRA-VXP-2397",
              sortTypeIsRecency: false,
              freeformTags: null,
              tags: tagsArray,
              broadcasterLanguages: [],
              systemFilters: [],
              limit: 30,
            },
          },
          extensions: {
            persistedQuery: {
              version: 1,
              sha256Hash:
                "76cb069d835b8a02914c08dc42c421d0dafda8af5b113a3f19141824b901402f",
            },
          },
        };
        const gqlRes = await fetch("https://gql.twitch.tv/gql", {
          method: "POST",
          headers,
          body: JSON.stringify([gqlBody]), // la web envia array
        });
        if (gqlRes.ok) {
          const arr = await gqlRes.json();
          const data = Array.isArray(arr) ? arr[0] : arr;
          const edges = data?.data?.game?.streams?.edges || [];
          console.log("[auto-channel] directory edges:", edges.length);
          const streamNode =
            edges.find((e) =>
              e?.node?.freeformTags?.some(
                (t) => (t.name || "").toLowerCase() === "dropsactivados"
              )
            ) || edges[0];
          if (streamNode?.node?.broadcaster?.login) {
            return res.json({
              ok: true,
              channel: streamNode.node.broadcaster.login,
            });
          }
        } else {
          const t = await gqlRes.text();
          console.log("[auto-channel] gql directory status", gqlRes.status, t);
        }
      }
    } catch (e) {
      console.log("[auto-channel] gql directory error", e.message);
    }

    // Attempt 1b: search channels by game name (avoids stream 404s)
    if (gameName) {
      const searchRes = await fetch(
        `https://api.twitch.tv/helix/search/channels?query=${encodeURIComponent(gameName)}&first=5&live_only=true`,
        { headers }
      );
      if (searchRes.ok) {
        const payload = await searchRes.json();
        const found = payload?.data?.find((c) => c.is_live);
        if (found) {
          return res.json({ ok: true, channel: found.broadcaster_login || found.display_name || found.id });
        }
      } else {
        const txt = await searchRes.text();
        console.log("[auto-channel] search status", searchRes.status, txt);
      }
    }

    // Attempt 2: GQL DirectoryPage_Game (more reliable for drops-enabled channels)
    try {
      const slug =
        gameSlug ||
        (gameName ? gameName.toLowerCase().replace(/\s+/g, "-") : null) ||
        null;
      if (slug) {
        const tagsArray = [];
        const gqlBody = {
          operationName: "DirectoryPage_Game",
          variables: {
            slug,
            imageWidth: 50,
            includeCostreaming: true,
            includeRestricted: ["SUB_ONLY_LIVE"],
            sort: "RELEVANCE",
            recommendationsContext: { platform: "web" },
            requestID: "JIRA-VXP-2397",
            sortTypeIsRecency: false,
            freeformTags: null,
            tags: tagsArray,
            broadcasterLanguages: [],
            limit: 30,
            options: {
              includeRestricted: ["SUB_ONLY_LIVE"],
              sort: "RELEVANCE",
              recommendationsContext: { platform: "web" },
              requestID: "JIRA-VXP-2397",
              sortTypeIsRecency: false,
              freeformTags: null,
              tags: tagsArray,
              broadcasterLanguages: [],
              systemFilters: [],
              limit: 30,
            },
          },
          extensions: {
            persistedQuery: {
              version: 1,
              sha256Hash:
                "76cb069d835b8a02914c08dc42c421d0dafda8af5b113a3f19141824b901402f",
            },
          },
        };
        const gqlRes = await fetch("https://gql.twitch.tv/gql", {
          method: "POST",
          headers,
          body: JSON.stringify(gqlBody),
        });
        if (gqlRes.ok) {
          const data = await gqlRes.json();
          const edges = data?.data?.game?.streams?.edges || [];
          const streamNode = edges.find((e) =>
            e?.node?.freeformTags?.some(
              (t) => (t.name || "").toLowerCase() === "dropsactivados"
            )
          ) || edges[0];
          if (streamNode?.node?.broadcaster?.login) {
            return res.json({
              ok: true,
              channel: streamNode.node.broadcaster.login,
            });
          }
        } else {
          const t = await gqlRes.text();
          console.log("[auto-channel] gql directory status", gqlRes.status, t);
        }
      }
    } catch (e) {
      console.log("[auto-channel] gql directory error", e.message);
    }

    // Attempt 3: streams by game_id
    if (gameId) {
      const streamsRes = await fetch(
        `https://api.twitch.tv/helix/streams?game_id=${encodeURIComponent(gameId)}&first=5`,
        { headers }
      );
      if (streamsRes.ok) {
        const payload = await streamsRes.json();
        const stream = payload?.data?.find((s) => s.type === "live");
        if (stream) {
          return res.json({ ok: true, channel: stream.user_login || stream.user_name || stream.user_id });
        }
      } else {
        const txt = await streamsRes.text();
        console.log("[auto-channel] streams status", streamsRes.status, txt);
      }
    }

    return res.status(404).json({ ok: false, error: "No live streams are currently available for this game/drop." });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/login/cookies", async (req, res) => {
  try {
    const summary = await captureCookies();
    res.json({ ok: true, cookies: summary, all: cachedCookies });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.get("/api/account/stats", async (req, res) => {
  try {
    const stats = await fetchAccountStats();
    res.json({ ok: true, stats });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.get("/api/drops/active", async (req, res) => {
  try {
    const drops = await fetchActiveDrops();
    res.json({ ok: true, drops });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.use((req, res, next) => {
  if (req.method === "GET" && !req.path.startsWith("/api")) {
    res.sendFile(path.join(__dirname, "..", "public", "index.html"));
  } else {
    next();
  }
});

const server = app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

const wss = new WebSocket.Server({ server, path: "/ws/embedded" });

wss.on("connection", (ws, req) => {
  const data = loadAuthData();
  const cookies = parseCookies({ headers: { cookie: req.headers.cookie || "" } });
  const verified = data?.secret ? verifyToken(cookies[AUTH_COOKIE], data.secret) : null;
  if (!verified) {
    ws.close(1008, "Unauthorized");
    return;
  }
  wsClients.add(ws);
  if (lastFrame) {
    ws.send(JSON.stringify({ type: "frame", image: lastFrame, viewport: lastViewport }));
  }
  ws.on("close", () => wsClients.delete(ws));
});

const cleanUp = async () => {
  if (browserContext) {
    await browserContext.close();
  }
  browserContext = null;
  browserProfileId = null;
  stopFrameCapture();
  for (const [pid, state] of farmSessions.entries()) {
    if (state.page && !state.page.isClosed()) {
      try {
        await state.page.close();
      } catch (e) {
        console.log("[clean] error closing page for profile", pid, e.message);
      }
    }
    if (state.context) {
      try {
        await state.context.close();
      } catch (e) {
        console.log("[clean] error closing context for profile", pid, e.message);
      }
    }
  }
  farmSessions.clear();
  wsClients.clear();
  server.close(() => process.exit(0));
};

process.on("SIGINT", cleanUp);
process.on("SIGTERM", cleanUp);
