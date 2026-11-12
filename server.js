const express = require("express");
const http = require("http");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const db = new Database("city.sqlite");
const PORT = process.env.PORT || 3000;

db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  balance INTEGER NOT NULL DEFAULT 1000,
  role TEXT NOT NULL DEFAULT 'citizen',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS votes (
  voter_id INTEGER PRIMARY KEY,
  candidate_id INTEGER NOT NULL,
  FOREIGN KEY(voter_id) REFERENCES users(id),
  FOREIGN KEY(candidate_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS city_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);
const getState = db.prepare("SELECT value FROM city_state WHERE key = ?");
const setState = db.prepare("INSERT INTO city_state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
if (!getState.get("mayor_id")) setState.run("mayor_id", "0");

app.use(express.json({ limit: "20kb" }));
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "replace-this-secret-before-deployment",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7 * 24 * 60 * 60 * 1000 }
});
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

const publicUser = (u) => ({
  id: u.id, username: u.username, balance: u.balance, role: u.role
});
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "سجّل الدخول أولاً." });
  next();
}
function userById(id) {
  return db.prepare("SELECT id, username, balance, role FROM users WHERE id=?").get(id);
}
function mayorId() {
  return Number(getState.get("mayor_id")?.value || 0);
}
function cityInfo() {
  const mayor = userById(mayorId());
  const candidates = db.prepare(`
    SELECT u.id,u.username,COUNT(v.voter_id) AS votes
    FROM users u LEFT JOIN votes v ON v.candidate_id=u.id
    GROUP BY u.id ORDER BY votes DESC,u.username ASC LIMIT 10
  `).all();
  return { mayor: mayor ? mayor.username : "لا يوجد عمدة بعد", candidates };
}

app.post("/api/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!/^[\u0600-\u06FFa-zA-Z0-9_]{3,18}$/.test(username))
    return res.status(400).json({ error: "اسم اللاعب من 3 إلى 18 حرفاً أو رقماً." });
  if (password.length < 8) return res.status(400).json({ error: "كلمة المرور يجب أن تكون 8 أحرف على الأقل." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare("INSERT INTO users(username,password_hash) VALUES(?,?)").run(username, hash);
    req.session.userId = Number(info.lastInsertRowid);
    res.json({ user: publicUser(userById(req.session.userId)), city: cityInfo() });
  } catch {
    res.status(409).json({ error: "اسم اللاعب مستخدم بالفعل." });
  }
});
app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const row = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if (!row || !(await bcrypt.compare(password, row.password_hash)))
    return res.status(401).json({ error: "اسم اللاعب أو كلمة المرور غير صحيحة." });
  req.session.userId = row.id;
  res.json({ user: publicUser(userById(row.id)), city: cityInfo() });
});
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  res.json({ user: publicUser(userById(req.session.userId)), city: cityInfo() });
});
app.get("/api/city", (req, res) => res.json(cityInfo()));

app.post("/api/work", requireAuth, (req, res) => {
  const jobs = ["عامل خدمات", "بائع", "مهندس مبتدئ", "موظف بلدية"];
  const job = String(req.body.job || "");
  if (!jobs.includes(job)) return res.status(400).json({ error: "الوظيفة غير متاحة." });
  const pay = 120;
  db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(pay, req.session.userId);
  res.json({ user: publicUser(userById(req.session.userId)), message: `تم إنجاز وردية ${job}. أضيف ${pay} عملة إلى محفظتك.` });
});
app.post("/api/vote", requireAuth, (req, res) => {
  const candidateId = Number(req.body.candidateId);
  if (!Number.isInteger(candidateId) || candidateId === req.session.userId)
    return res.status(400).json({ error: "اختر لاعباً آخر للترشح أو التصويت له." });
  if (!userById(candidateId)) return res.status(404).json({ error: "المرشح غير موجود." });
  db.prepare("INSERT INTO votes(voter_id,candidate_id) VALUES(?,?) ON CONFLICT(voter_id) DO UPDATE SET candidate_id=excluded.candidate_id")
    .run(req.session.userId, candidateId);
  res.json({ city: cityInfo(), message: "تم تسجيل صوتك." });
});
app.post("/api/election/close", requireAuth, (req, res) => {
  const current = userById(req.session.userId);
  if (current.role !== "admin") return res.status(403).json({ error: "إغلاق الانتخابات متاح لإدارة الخادم فقط حالياً." });
  const winner = db.prepare(`
    SELECT candidate_id,COUNT(*) AS n FROM votes GROUP BY candidate_id ORDER BY n DESC LIMIT 1
  `).get();
  if (!winner) return res.status(400).json({ error: "لا توجد أصوات بعد." });
  db.prepare("UPDATE users SET role='citizen' WHERE role='mayor'").run();
  db.prepare("UPDATE users SET role='mayor' WHERE id=?").run(winner.candidate_id);
  setState.run("mayor_id", String(winner.candidate_id));
  res.json({ city: cityInfo(), message: "أُعلنت نتيجة الانتخابات." });
});

// Configure the first administrator with ADMIN_USERNAME before starting the server.
if (process.env.ADMIN_USERNAME) {
  db.prepare("UPDATE users SET role='admin' WHERE username=?").run(process.env.ADMIN_USERNAME);
}

const online = new Map();
io.use((socket, next) => {
  const cookie = socket.handshake.headers.cookie || "";
  const sid = cookie.split(";").map(x => x.trim()).find(x => x.startsWith("connect.sid="));
  if (!sid) return next(new Error("auth required"));
  // Socket.IO session identity is confirmed through the session middleware below.
  next();
});
io.engine.use(sessionMiddleware);
io.use((socket, next) => {
  const userId = socket.request.session?.userId;
  const user = userId ? userById(userId) : null;
  if (!user) return next(new Error("سجّل الدخول أولاً."));
  socket.user = publicUser(user);
  next();
});
io.on("connection", socket => {
  online.set(socket.id, { id: socket.user.id, username: socket.user.username, x: 0, z: 0, rotation: 0 });
  socket.emit("world:players", [...online.values()]);
  socket.broadcast.emit("world:join", online.get(socket.id));
  socket.on("player:move", data => {
    const p = online.get(socket.id);
    if (!p || !data) return;
    p.x = Math.max(-90, Math.min(90, Number(data.x) || 0));
    p.z = Math.max(-90, Math.min(90, Number(data.z) || 0));
    p.rotation = Number(data.rotation) || 0;
    socket.broadcast.emit("world:move", p);
  });
  socket.on("chat:send", raw => {
    const message = String(raw || "").trim().slice(0, 180);
    if (message) io.emit("chat:message", { username: socket.user.username, message, at: Date.now() });
  });
  socket.on("disconnect", () => {
    online.delete(socket.id);
    io.emit("world:leave", socket.user.id);
  });
});

server.listen(PORT, () => console.log(`مدينة النخبة تعمل على http://localhost:${PORT}`));
