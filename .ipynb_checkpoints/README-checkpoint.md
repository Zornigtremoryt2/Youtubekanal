# Express MySQL Login System

## Features
- Registrierung, Login, Sessions, Gastzugang
- Passwort-Hashing mit bcrypt
- MySQL-Datenbank
- .env für Konfiguration

## Setup
1. `npm install`
2. `.env` aus `.env.example` kopieren und anpassen
3. MySQL-Datenbank anlegen (siehe unten)
4. `npm start` oder `npm run dev`

## MySQL Datenbankstruktur
```sql
CREATE DATABASE login_system;
USE login_system;
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## API Endpunkte
- `POST /register` – Registrierung
- `POST /login` – Login
- `GET /logout` – Logout
- `GET /guest` – Gastzugang
- `GET /me` – Session-Status

## Beispiel-Requests
```bash
curl -X POST http://localhost:3000/register -d 'username=test&password=123456'
curl -X POST http://localhost:3000/login -d 'username=test&password=123456'
curl http://localhost:3000/me
```

## Hinweise
- Für Produktion sichere Passwörter und HTTPS verwenden!
