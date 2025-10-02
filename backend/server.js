require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'devsecret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// MySQL Verbindung
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});


// Registrierung
app.post('/register', async (req, res) => {
  const { email, phone, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich.' });
  try {
    const [rows] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (rows.length > 0) return res.status(409).json({ error: 'E-Mail bereits registriert.' });
    const hash = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users (email, phone, password) VALUES (?, ?, ?)', [email, phone, hash]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Fehler bei Registrierung.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich.' });
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Ungültige Zugangsdaten.' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Ungültige Zugangsdaten.' });
    req.session.userId = user.id;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Fehler beim Login.' });
  }
});

// Gastzugang
app.post('/guest', (req, res) => {
  req.session.guest = true;
  res.json({ success: true, guest: true });
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
app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
