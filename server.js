"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const SITE_DIR = process.env.SITE_DIR || "/site";
const DATA_DIR = process.env.DATA_DIR || "/data";
const CONFIG_PATH = process.env.CONFIG_PATH || path.join(SITE_DIR, "config.json");
const STATUS_PATH = process.env.STATUS_PATH || path.join(SITE_DIR, "status.json");
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(DATA_DIR, "backups");
const SECURITY_PATH = process.env.SECURITY_PATH || path.join(DATA_DIR, "security.json");
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "false").toLowerCase() === "true";
const DEFAULT_TIMEOUT_MINUTES = clampNumber(Number(process.env.SESSION_TIMEOUT_MINUTES || 30), 10, 480);
const MAX_JSON_BYTES = 1024 * 1024;
const SESSION_COOKIE = "dashboard_session";

const MIME_TYPES = new Map([
    [".html", "text/html; charset=utf-8"],
    [".css", "text/css; charset=utf-8"],
    [".js", "application/javascript; charset=utf-8"],
    [".json", "application/json; charset=utf-8"],
    [".ico", "image/x-icon"],
    [".png", "image/png"],
    [".jpg", "image/jpeg"],
    [".jpeg", "image/jpeg"],
    [".webp", "image/webp"],
    [".svg", "image/svg+xml; charset=utf-8"]
]);

const sessions = new Map();
const loginAttempts = new Map();

ensureStartupFiles();
setInterval(cleanExpiredSessions, 60 * 1000).unref();

const server = http.createServer(async (req, res) => {
    try {
        setSecurityHeaders(res);

        const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
        const pathname = decodeURIComponent(parsedUrl.pathname);

        if (pathname.startsWith("/api/")) {
            await handleApi(req, res, pathname);
            return;
        }

        await serveStatic(req, res, pathname);
    } catch (error) {
        const status = Number(error.status || 500);
        if (status >= 500) {
            console.error(error);
        }
        sendJson(res, status, { error: status >= 500 ? "Internal server error" : error.message });
    }
});

server.listen(PORT, () => {
    console.log(`Dashboard server listening on port ${PORT}`);
    console.log(`Site directory: ${SITE_DIR}`);
    console.log(`Config path: ${CONFIG_PATH}`);
    console.log(`Backup directory: ${BACKUP_DIR}`);
});

async function handleApi(req, res, pathname) {
    if (req.method === "GET" && pathname === "/api/config") {
        sendJson(res, 200, { config: readJsonFile(CONFIG_PATH, { sections: [] }) });
        return;
    }

    if (req.method === "GET" && pathname === "/api/status") {
        sendJson(res, 200, { status: readJsonFile(STATUS_PATH, {}) });
        return;
    }

    if (req.method === "GET" && pathname === "/api/session") {
        const session = getSession(req);
        if (!session) {
            sendJson(res, 200, { authenticated: false });
            return;
        }
        sendJson(res, 200, {
            authenticated: true,
            csrfToken: session.csrfToken,
            expiresAt: new Date(session.expiresAt).toISOString()
        });
        return;
    }

    if (req.method === "POST" && pathname === "/api/login") {
        await handleLogin(req, res);
        return;
    }

    if (req.method === "POST" && pathname === "/api/logout") {
        const sid = getCookie(req, SESSION_COOKIE);
        if (sid) sessions.delete(sid);
        clearSessionCookie(res);
        sendJson(res, 200, { success: true });
        return;
    }

    const session = requireAuth(req, res);
    if (!session) return;

    if (req.method === "GET" && pathname === "/api/security") {
        const security = loadSecurityConfig();
        sendJson(res, 200, {
            requirePassword: true,
            sessionTimeoutMinutes: security.sessionTimeoutMinutes,
            passwordManaged: true
        });
        return;
    }

    if (req.method === "POST" && pathname === "/api/security") {
        if (!requireCsrf(req, res, session)) return;
        await handleSecurityUpdate(req, res);
        return;
    }

    if (req.method === "GET" && pathname === "/api/backups") {
        sendJson(res, 200, { backups: listBackups() });
        return;
    }

    if (req.method === "POST" && pathname === "/api/backup") {
        if (!requireCsrf(req, res, session)) return;
        const backup = createBackup();
        sendJson(res, 200, { success: true, ...backup });
        return;
    }

    if (req.method === "POST" && pathname === "/api/save-config") {
        if (!requireCsrf(req, res, session)) return;
        const body = await readJsonBody(req);
        const sanitized = sanitizeConfig(body);
        createBackup();
        writeJsonAtomic(CONFIG_PATH, sanitized, 0o644);
        sendJson(res, 200, { success: true, config: sanitized });
        return;
    }

    if (req.method === "POST" && pathname === "/api/restore") {
        if (!requireCsrf(req, res, session)) return;
        const body = await readJsonBody(req);
        const name = String(body.name || "");
        const file = backupPath(name);
        if (!file || !fs.existsSync(file)) {
            sendJson(res, 404, { error: "Backup not found" });
            return;
        }
        const config = sanitizeConfig(readJsonFile(file, null));
        createBackup();
        writeJsonAtomic(CONFIG_PATH, config, 0o644);
        sendJson(res, 200, { success: true, config });
        return;
    }

    const backupMatch = pathname.match(/^\/api\/backup\/([^/]+)$/);
    if (backupMatch) {
        const name = decodeURIComponent(backupMatch[1]);
        const file = backupPath(name);
        if (!file || !fs.existsSync(file)) {
            sendJson(res, 404, { error: "Backup not found" });
            return;
        }

        if (req.method === "GET") {
            res.writeHead(200, {
                "Content-Type": "application/json; charset=utf-8",
                "Content-Disposition": `attachment; filename="${name}"`,
                "Cache-Control": "no-store"
            });
            fs.createReadStream(file).pipe(res);
            return;
        }

        if (req.method === "DELETE") {
            if (!requireCsrf(req, res, session)) return;
            fs.unlinkSync(file);
            sendJson(res, 200, { success: true });
            return;
        }
    }

    sendJson(res, 404, { error: "Not found" });
}

async function handleLogin(req, res) {
    const ip = getClientIp(req);
    if (!allowLoginAttempt(ip)) {
        sendJson(res, 429, { error: "Too many login attempts. Try again later." });
        return;
    }

    const body = await readJsonBody(req);
    const password = String(body.password || "");
    const security = loadSecurityConfig();

    if (!verifyPassword(password, security.password)) {
        registerFailedLogin(ip);
        sendJson(res, 401, { error: "Invalid password" });
        return;
    }

    clearLoginAttempts(ip);
    const sessionTimeoutMinutes = security.sessionTimeoutMinutes || DEFAULT_TIMEOUT_MINUTES;
    const sid = randomToken(32);
    const csrfToken = randomToken(32);
    const expiresAt = Date.now() + sessionTimeoutMinutes * 60 * 1000;
    sessions.set(sid, { csrfToken, expiresAt });
    setSessionCookie(res, sid, sessionTimeoutMinutes);
    sendJson(res, 200, {
        success: true,
        authenticated: true,
        csrfToken,
        expiresAt: new Date(expiresAt).toISOString()
    });
}

async function handleSecurityUpdate(req, res) {
    const body = await readJsonBody(req);
    const security = loadSecurityConfig();
    const currentPassword = String(body.currentPassword || "");
    const newPassword = String(body.newPassword || "");
    const timeout = clampNumber(Number(body.sessionTimeoutMinutes || security.sessionTimeoutMinutes || DEFAULT_TIMEOUT_MINUTES), 10, 480);

    if (newPassword) {
        if (newPassword.length < 10 || newPassword.length > 200) {
            sendJson(res, 400, { error: "New password must be between 10 and 200 characters." });
            return;
        }
        if (!verifyPassword(currentPassword, security.password)) {
            sendJson(res, 401, { error: "Current password is incorrect." });
            return;
        }
        security.password = hashPassword(newPassword);
    }

    security.sessionTimeoutMinutes = timeout;
    security.updatedAt = new Date().toISOString();
    writeJsonAtomic(SECURITY_PATH, security, 0o600);
    sendJson(res, 200, {
        requirePassword: true,
        sessionTimeoutMinutes: timeout,
        passwordManaged: true
    });
}

async function serveStatic(req, res, pathname) {
    if (!["GET", "HEAD"].includes(req.method)) {
        sendJson(res, 405, { error: "Method not allowed" });
        return;
    }

    let requested = pathname === "/" ? "/index.html" : pathname;
    if (requested.includes("\0")) {
        sendJson(res, 400, { error: "Bad request" });
        return;
    }

    const filePath = path.normalize(path.join(SITE_DIR, requested));
    const relative = path.relative(SITE_DIR, filePath);

    if (relative.startsWith("..") || path.isAbsolute(relative)) {
        sendJson(res, 403, { error: "Forbidden" });
        return;
    }

    const ext = path.extname(filePath).toLowerCase();
    if (!MIME_TYPES.has(ext)) {
        sendJson(res, 404, { error: "Not found" });
        return;
    }

    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
        sendJson(res, 404, { error: "Not found" });
        return;
    }

    res.writeHead(200, {
        "Content-Type": MIME_TYPES.get(ext),
        "Cache-Control": ext === ".html" ? "no-store" : "public, max-age=300"
    });

    if (req.method === "HEAD") {
        res.end();
        return;
    }

    fs.createReadStream(filePath).pipe(res);
}

function ensureStartupFiles() {
    fs.mkdirSync(SITE_DIR, { recursive: true });
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.mkdirSync(BACKUP_DIR, { recursive: true });

    if (!fs.existsSync(CONFIG_PATH) && !fs.existsSync(STATUS_PATH)) {
        // Copy over all sample files if the site directory is empty
        const sampleDir = "/sample-site";
        if (fs.existsSync(sampleDir) && fs.statSync(sampleDir).isDirectory()) {
            for (const entry of fs.readdirSync(sampleDir)) {
                const src = path.join(sampleDir, entry);
                const dest = path.join(SITE_DIR, entry);
                if (fs.statSync(src).isFile()) {
                    fs.copyFileSync(src, dest);
                    fs.chmodSync(dest, 0o644);
                }
            }
        }
    }

    if (!fs.existsSync(CONFIG_PATH)) {
        writeJsonAtomic(CONFIG_PATH, { sections: [] }, 0o644);
    }

    if (!fs.existsSync(STATUS_PATH)) {
        writeJsonAtomic(STATUS_PATH, {}, 0o644);
    }

    if (!fs.existsSync(SECURITY_PATH)) {
        const initialPassword = process.env.DASHBOARD_ADMIN_PASSWORD || "change-me-now";
        if (!process.env.DASHBOARD_ADMIN_PASSWORD) {
            console.warn("WARNING: DASHBOARD_ADMIN_PASSWORD is not set. Default password is 'change-me-now'. Change it immediately.");
        }
        const security = {
            password: hashPassword(initialPassword),
            sessionTimeoutMinutes: DEFAULT_TIMEOUT_MINUTES,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        writeJsonAtomic(SECURITY_PATH, security, 0o600);
    }
}

function loadSecurityConfig() {
    const security = readJsonFile(SECURITY_PATH, null);
    if (!security || !security.password || !security.password.hash || !security.password.salt) {
        throw new Error("Security configuration is invalid");
    }
    security.sessionTimeoutMinutes = clampNumber(Number(security.sessionTimeoutMinutes || DEFAULT_TIMEOUT_MINUTES), 10, 480);
    return security;
}

function sanitizeConfig(config) {
    if (!config || typeof config !== "object" || Array.isArray(config)) {
        throw httpError(400, "Configuration must be an object.");
    }

    const sections = Array.isArray(config.sections) ? config.sections : [];
    if (sections.length > 100) {
        throw httpError(400, "Too many sections. Maximum is 100.");
    }

    const usedSectionIds = new Set();
    const usedHostIds = new Set();

    const sanitizedSections = sections.map((section, sectionIndex) => {
        if (!section || typeof section !== "object" || Array.isArray(section)) {
            throw httpError(400, `Section ${sectionIndex + 1} is invalid.`);
        }

        const title = cleanString(section.title, 1, 80, `Section ${sectionIndex + 1} title`);
        let id = cleanOptionalId(section.id) || slugify(title) || `section-${sectionIndex + 1}`;
        id = uniqueId(id, usedSectionIds);
        usedSectionIds.add(id);

        const icon = cleanIcon(section.icon, "▦");
        const color = ["blue", "green", "purple", "pink", "orange", "red", "slate", "cyan"].includes(section.color) ? section.color : "blue";
        const items = Array.isArray(section.items) ? section.items : [];

        if (items.length > 200) {
            throw httpError(400, `Section ${title} has too many hosts. Maximum is 200.`);
        }

        const sanitizedItems = items.map((item, itemIndex) => {
            if (!item || typeof item !== "object" || Array.isArray(item)) {
                throw httpError(400, `Host ${itemIndex + 1} in ${title} is invalid.`);
            }

            const hostId = cleanString(item.id, 1, 64, `Host ID in ${title}`);
            if (!/^[a-zA-Z0-9_-]{1,64}$/.test(hostId)) {
                throw httpError(400, `Invalid host ID: ${hostId}`);
            }
            if (usedHostIds.has(hostId)) {
                throw httpError(400, `Duplicate host ID: ${hostId}`);
            }
            usedHostIds.add(hostId);

            const name = cleanString(item.name, 1, 100, `Host name for ${hostId}`);
            const description = cleanString(item.description || "", 0, 180, `Host description for ${hostId}`);
            const url = cleanString(item.url, 1, 300, `URL / IP for ${hostId}`);
            if (!isValidTarget(url)) {
                throw httpError(400, `Invalid URL / IP for ${hostId}.`);
            }

            return {
                id: hostId,
                name,
                description,
                url,
                icon: cleanIcon(item.icon, "🌍"),
                invertStatus: Boolean(item.invertStatus)
            };
        });

        return { id, title, icon, color, items: sanitizedItems };
    });

    return { sections: sanitizedSections };
}

function cleanString(value, min, max, field) {
    const text = String(value ?? "").trim();
    if (text.length < min) {
        throw httpError(400, `${field} is required.`);
    }
    if (text.length > max) {
        throw httpError(400, `${field} is too long.`);
    }
    if (/[\u0000-\u001f\u007f]/.test(text)) {
        throw httpError(400, `${field} contains invalid characters.`);
    }
    return text;
}

function cleanOptionalId(value) {
    const text = String(value || "").trim();
    if (!text) return "";
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(text)) return "";
    return text;
}

function cleanIcon(value, fallback) {
    const text = String(value || fallback).trim();
    if (!text || text.length > 16 || /[\u0000-\u001f\u007f]/.test(text)) return fallback;
    return text;
}

function isValidTarget(target) {
    const value = String(target || "").trim();
    if (!value || value.length > 300 || /[\u0000-\u001f<>"']/.test(value)) return false;
    if (/^https?:\/\//i.test(value)) {
        try {
            const parsed = new URL(value);
            return parsed.protocol === "http:" || parsed.protocol === "https:";
        } catch (_) {
            return false;
        }
    }
    return /^[a-zA-Z0-9_.-]+$/.test(value);
}

function createBackup() {
    if (!fs.existsSync(CONFIG_PATH)) {
        return { name: null, createdAt: null, size: 0 };
    }
    const name = `config-${formatDateForFile(new Date())}.json`;
    const target = path.join(BACKUP_DIR, name);
    fs.copyFileSync(CONFIG_PATH, target);
    const stat = fs.statSync(target);
    return { name, createdAt: stat.mtime.toISOString(), size: stat.size };
}

function listBackups() {
    if (!fs.existsSync(BACKUP_DIR)) return [];
    return fs.readdirSync(BACKUP_DIR)
        .filter((name) => /^config-\d{8}-\d{6}-\d{3}\.json$/.test(name))
        .map((name) => {
            const file = path.join(BACKUP_DIR, name);
            const stat = fs.statSync(file);
            return { name, createdAt: stat.mtime.toISOString(), size: stat.size };
        })
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function backupPath(name) {
    if (!/^config-\d{8}-\d{6}-\d{3}\.json$/.test(name)) return null;
    const file = path.join(BACKUP_DIR, name);
    const relative = path.relative(BACKUP_DIR, file);
    if (relative.startsWith("..") || path.isAbsolute(relative)) return null;
    return file;
}

function readJsonFile(file, fallback) {
    try {
        return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (error) {
        if (fallback !== null) return fallback;
        throw error;
    }
}

function writeJsonAtomic(file, data, mode) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { encoding: "utf8", mode });
    fs.renameSync(tmp, file);
    fs.chmodSync(file, mode);
}

function readJsonBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";
        req.on("data", (chunk) => {
            body += chunk;
            if (Buffer.byteLength(body) > MAX_JSON_BYTES) {
                req.destroy();
                reject(httpError(413, "Request body is too large."));
            }
        });
        req.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (_) {
                reject(httpError(400, "Invalid JSON."));
            }
        });
        req.on("error", reject);
    });
}

function requireAuth(req, res) {
    const session = getSession(req);
    if (!session) {
        sendJson(res, 401, { error: "Authentication required" });
        return null;
    }
    return session;
}

function requireCsrf(req, res, session) {
    const token = req.headers["x-csrf-token"];
    if (!token || token !== session.csrfToken) {
        sendJson(res, 403, { error: "Invalid CSRF token" });
        return false;
    }
    return true;
}

function getSession(req) {
    const sid = getCookie(req, SESSION_COOKIE);
    if (!sid) return null;
    const session = sessions.get(sid);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
        sessions.delete(sid);
        return null;
    }
    return session;
}

function setSessionCookie(res, sid, minutes) {
    const parts = [
        `${SESSION_COOKIE}=${sid}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Strict",
        `Max-Age=${Math.floor(minutes * 60)}`
    ];
    if (COOKIE_SECURE) parts.push("Secure");
    res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
    res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${COOKIE_SECURE ? "; Secure" : ""}`);
}

function getCookie(req, name) {
    const header = req.headers.cookie || "";
    const cookies = header.split(";").map((entry) => entry.trim());
    for (const cookie of cookies) {
        const index = cookie.indexOf("=");
        if (index === -1) continue;
        const key = cookie.slice(0, index);
        const value = cookie.slice(index + 1);
        if (key === name) return value;
    }
    return "";
}

function hashPassword(password) {
    const salt = randomToken(16);
    const hash = crypto.scryptSync(password, salt, 64).toString("base64");
    return { algorithm: "scrypt", salt, hash };
}

function verifyPassword(password, stored) {
    try {
        const candidate = crypto.scryptSync(String(password), stored.salt, 64);
        const expected = Buffer.from(stored.hash, "base64");
        return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
    } catch (_) {
        return false;
    }
}

function allowLoginAttempt(ip) {
    const now = Date.now();
    const windowMs = 10 * 60 * 1000;
    const attempts = (loginAttempts.get(ip) || []).filter((timestamp) => now - timestamp < windowMs);
    loginAttempts.set(ip, attempts);
    return attempts.length < 8;
}

function registerFailedLogin(ip) {
    const attempts = loginAttempts.get(ip) || [];
    attempts.push(Date.now());
    loginAttempts.set(ip, attempts);
}

function clearLoginAttempts(ip) {
    loginAttempts.delete(ip);
}

function cleanExpiredSessions() {
    const now = Date.now();
    for (const [sid, session] of sessions.entries()) {
        if (session.expiresAt <= now) sessions.delete(sid);
    }
}

function getClientIp(req) {
    const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    return forwarded || req.socket.remoteAddress || "unknown";
}

function setSecurityHeaders(res) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Content-Security-Policy", [
        "default-src 'self'",
        "img-src 'self' data:",
        "style-src 'self' 'unsafe-inline'",
        "script-src 'self'",
        "connect-src 'self'",
        "form-action 'self' https://www.google.com",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'"
    ].join("; "));
}

function sendJson(res, statusCode, payload) {
    if (payload instanceof Error) payload = { error: payload.message };
    res.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store"
    });
    res.end(JSON.stringify(payload));
}

function httpError(status, message) {
    const error = new Error(message);
    error.status = status;
    return error;
}

function randomToken(bytes) {
    return crypto.randomBytes(bytes).toString("base64url");
}

function clampNumber(value, min, max) {
    if (!Number.isFinite(value)) return min;
    return Math.max(min, Math.min(max, Math.round(value)));
}

function slugify(value) {
    return String(value || "item")
        .toLowerCase()
        .normalize("NFKD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 48) || "item";
}

function uniqueId(base, used) {
    let candidate = base;
    let index = 2;
    while (used.has(candidate)) {
        candidate = `${base}-${index}`;
        index += 1;
    }
    return candidate;
}

function formatDateForFile(date) {
    const pad = (number, length = 2) => String(number).padStart(length, "0");
    return [
        date.getFullYear(),
        pad(date.getMonth() + 1),
        pad(date.getDate()),
        "-",
        pad(date.getHours()),
        pad(date.getMinutes()),
        pad(date.getSeconds()),
        "-",
        pad(date.getMilliseconds(), 3)
    ].join("");
}
