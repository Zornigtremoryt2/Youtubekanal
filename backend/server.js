require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const app = express();
const helmet = require('helmet');
const cors = require('cors');

const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const validator = require('validator');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security middlewares
app.use(helmet());
app.use(cors({ origin: process.env.APP_URL || true, credentials: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'devsecret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', sameSite: 'lax' }
}));

// Rate-Limiter für Auth-Endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  message: { error: 'Zu viele Anfragen, bitte kurz warten.' }
});

// MySQL Verbindung (Pool). Wir versuchen die Verbindung beim Start; falls sie fehlschlägt,
// benutzen wir einen temporären In-Memory-Store, damit Registrierung/Login lokal funktionieren.
let db = null;
let useInMemory = false;
const inMemoryUsers = [];

async function initDb() {
  try {
    db = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'express_login',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });
    // Testabfrage
    await db.query('SELECT 1');
    console.log('MySQL-Verbindung hergestellt.');
  } catch (err) {
    console.warn('Konnte keine MySQL-Verbindung herstellen, verwende In-Memory-Store. Fehler:', err.message);
    useInMemory = true;
    db = null;
  }
}

// Helper-Funktionen, die entweder MySQL oder In-Memory verwenden
async function findUserByEmail(email) {
  if (useInMemory) {
    return inMemoryUsers.filter(u => u.email === email);
  }
  const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
  return rows;
}

async function findUserById(id) {
  if (useInMemory) {
    return inMemoryUsers.find(u => u.id === id) ? [inMemoryUsers.find(u => u.id === id)] : [];
  }
  const [rows] = await db.query('SELECT id, email, phone, created_at FROM users WHERE id = ?', [id]);
  return rows;
}

async function createUser({ email, phone, passwordHash }) {
  if (useInMemory) {
    const id = inMemoryUsers.length ? inMemoryUsers[inMemoryUsers.length - 1].id + 1 : 1;
    const user = { id, email, phone, password: passwordHash, created_at: new Date() };
    inMemoryUsers.push(user);
    return { insertId: id };
  }
  const [result] = await db.query('INSERT INTO users (email, phone, password) VALUES (?, ?, ?)', [email, phone, passwordHash]);
  return result;
}

// Nodemailer Transport (Ethereal für Tests) – wenn SMTP-Variablen gesetzt sind, nutze diese
let mailTransport = null;
async function initMailer() {
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    mailTransport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: false,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    console.log('SMTP Mailer konfiguriert.');
  } else {
    const testAccount = await nodemailer.createTestAccount();
    mailTransport = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      secure: false,
      auth: { user: testAccount.user, pass: testAccount.pass }
    });
    console.log('Ethereal-Test-Mailaccount erstellt:', testAccount.user);
  }
}

async function sendVerificationEmail(email, token) {
  const verifyUrl = `${process.env.APP_URL || 'http://localhost:' + (process.env.PORT||4000)}/verify/${token}`;
  const info = await mailTransport.sendMail({
    from: process.env.EMAIL_FROM || 'no-reply@example.com',
    to: email,
    subject: 'Bitte bestätige deine E-Mail',
    text: `Bitte klicke auf den Link, um dein Konto zu bestätigen: ${verifyUrl}`,
    html: `<p>Bitte klicke auf den Link, um dein Konto zu bestätigen:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`
  });
  console.log('Verification mail sent:', nodemailer.getTestMessageUrl(info));
}

async function sendResetEmail(email, token) {
  const resetUrl = `${process.env.APP_URL || 'http://localhost:' + (process.env.PORT||4000)}/reset/${token}`;
  const info = await mailTransport.sendMail({
    from: process.env.EMAIL_FROM || 'no-reply@example.com',
    to: email,
    subject: 'Passwort zurücksetzen',
    text: `Bitte klicke auf den Link, um dein Passwort zurückzusetzen: ${resetUrl}`,
    html: `<p>Bitte klicke auf den Link, um dein Passwort zurückzusetzen:</p><p><a href="${resetUrl}">${resetUrl}</a></p>`
  });
  console.log('Reset mail sent:', nodemailer.getTestMessageUrl(info));
}


// Registrierung
app.post('/register', async (req, res) => {
  const { email, phone, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich.' });
  if (!validator.isEmail(email)) return res.status(400).json({ error: 'Ungültiges E-Mail-Format.' });
  if (!validator.isLength(password, { min: 8 })) return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen haben.' });
  try {
    const existing = await findUserByEmail(email);
    if (existing && existing.length > 0) return res.status(409).json({ error: 'E-Mail bereits registriert.' });
    const hash = await bcrypt.hash(password, 10);
    const verifyToken = crypto.randomBytes(24).toString('hex');
    const result = await createUser({ email, phone, passwordHash: hash });
    // Speichere verify_token
    if (!useInMemory) {
      await db.query('UPDATE users SET verify_token = ? WHERE id = ?', [verifyToken, result.insertId]);
    } else {
      const u = inMemoryUsers.find(x => x.id === result.insertId);
      if (u) u.verify_token = verifyToken;
    }
    await sendVerificationEmail(email, verifyToken);
    // Setze Session
    const userId = result && result.insertId ? result.insertId : (useInMemory ? result.insertId : null);
    if (userId) req.session.userId = userId;
    return res.status(201).json({ success: true, userId });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Fehler bei Registrierung.' });
  }
});

// Verifikation
app.get('/verify/:token', async (req, res) => {
  const { token } = req.params;
  if (!token) return res.status(400).send('Token fehlt');
  try {
    if (useInMemory) {
      const u = inMemoryUsers.find(x => x.verify_token === token);
      if (!u) return res.status(404).send('Token ungültig');
      u.verified = 1;
      u.verify_token = null;
      return res.send('E-Mail verifiziert');
    }
    const [rows] = await db.query('SELECT id FROM users WHERE verify_token = ?', [token]);
    if (rows.length === 0) return res.status(404).send('Token ungültig');
    await db.query('UPDATE users SET verified = 1, verify_token = NULL WHERE id = ?', [rows[0].id]);
    return res.send('E-Mail verifiziert');
  } catch (err) {
    console.error('Verify error', err);
    return res.status(500).send('Serverfehler');
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich.' });
  if (!validator.isEmail(email)) return res.status(400).json({ error: 'Ungültiges E-Mail-Format.' });
  try {
    const rows = await findUserByEmail(email);
    if (!rows || rows.length === 0) return res.status(401).json({ error: 'Ungültige Zugangsdaten.' });
    const user = Array.isArray(rows) ? rows[0] : rows;
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Ungültige Zugangsdaten.' });
    req.session.userId = user.id;
    return res.json({ success: true, userId: user.id });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Fehler beim Login.' });
  }
});

// Gastzugang
app.post('/guest', (req, res) => {
  req.session.guest = true;
  res.json({ success: true, guest: true });
});

// Forgot password
app.post('/forgot', authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'E-Mail erforderlich' });
  if (!validator.isEmail(email)) return res.status(400).json({ error: 'Ungültiges E-Mail-Format.' });
  try {
    const rows = await findUserByEmail(email);
    if (!rows || rows.length === 0) return res.json({ success: true }); // don't leak
    const user = Array.isArray(rows) ? rows[0] : rows;
    const token = crypto.randomBytes(24).toString('hex');
    const expires = new Date(Date.now() + 3600 * 1000); // 1 hour
    if (useInMemory) {
      user.reset_token = token;
      user.reset_expires = expires;
    } else {
      await db.query('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', [token, expires, user.id]);
    }
    await sendResetEmail(email, token);
    return res.json({ success: true });
  } catch (err) {
    console.error('Forgot error', err);
    return res.status(500).json({ error: 'Serverfehler' });
  }
});

// Reset password
app.post('/reset/:token', authLimiter, async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token und Passwort erforderlich' });
  if (!validator.isLength(password, { min: 8 })) return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen haben.' });
  try {
    let rows;
    if (useInMemory) {
      const u = inMemoryUsers.find(x => x.reset_token === token && new Date(x.reset_expires) > new Date());
      if (!u) return res.status(400).json({ error: 'Token ungültig oder abgelaufen' });
      const hash = await bcrypt.hash(password, 10);
      u.password = hash;
      u.reset_token = null;
      u.reset_expires = null;
      return res.json({ success: true });
    }
    [rows] = await db.query('SELECT id, reset_expires FROM users WHERE reset_token = ?', [token]);
    if (!rows || rows.length === 0) return res.status(400).json({ error: 'Token ungültig' });
    const user = rows[0];
    if (new Date(user.reset_expires) < new Date()) return res.status(400).json({ error: 'Token abgelaufen' });
    const hash = await bcrypt.hash(password, 10);
    await db.query('UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?', [hash, user.id]);
    return res.json({ success: true });
  } catch (err) {
    console.error('Reset error', err);
    return res.status(500).json({ error: 'Serverfehler' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Session-Status
app.get('/me', async (req, res) => {
  if (req.session.userId) {
    const [rows] = await db.query('SELECT id, email, phone, created_at FROM users WHERE id = ?', [req.session.userId]);
    if (rows.length > 0) return res.json({ loggedIn: true, user: rows[0] });
  }
  if (req.session.guest) return res.json({ loggedIn: false, guest: true });
  res.json({ loggedIn: false });
});

// Test-Route
app.get('/', (req, res) => {
  res.json({ status: 'OK', message: 'Login-API läuft!' });
});

const PORT = process.env.PORT || 3001;
async function start() {
  await initDb();
  await initMailer();
  app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}` + (useInMemory ? ' (In-Memory-Mode)' : ''));
  });
}
if (require.main === module) {
  start();
}

module.exports = { app, start };
