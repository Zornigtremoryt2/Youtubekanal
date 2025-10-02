require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session-Konfiguration
app.use(session({
  secret: process.env.SESSION_SECRET || 'geheim',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// MySQL-Verbindung
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
};

// Middleware: User aus Session
app.use(async (req, res, next) => {
  req.user = req.session.user || null;
  next();
});

// Registrierung
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Benutzername und Passwort erforderlich.' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash]);
    await conn.end();
    res.json({ success: true });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Benutzername existiert bereits.' });
    res.status(500).json({ error: 'Fehler bei Registrierung.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Benutzername und Passwort erforderlich.' });
  try {
    const conn = await mysql.createConnection(dbConfig);
    const [rows] = await conn.execute('SELECT * FROM users WHERE username = ?', [username]);
    await conn.end();
    if (rows.length === 0) return res.status(401).json({ error: 'Benutzer nicht gefunden.' });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Falsches Passwort.' });
    req.session.user = { id: user.id, username: user.username };
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Fehler beim Login.' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Gastzugang
app.get('/guest', (req, res) => {
  req.session.user = { id: 0, username: 'Gast' };
  res.json({ success: true, user: req.session.user });
});

// Session-Status
app.get('/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Nicht eingeloggt.' });
  res.json({ user: req.user });
});

// Server starten
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
