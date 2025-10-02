# Express + MySQL Login-System

## Setup

1. Im Ordner `backend` ausführen:
   ```bash
   npm install
   cp .env.example .env
   # Passe die .env an deine MySQL-Daten an
   npm start
   ```

2. MySQL-Datenbank und Tabelle anlegen (siehe unten).

## API-Endpunkte (werden noch ergänzt)
- `POST /register` – Registrierung
- `POST /login` – Login
- `POST /guest` – Gastzugang
- `GET /logout` – Logout
- `GET /me` – Session-Status

## Beispielhafte User-Tabelle
```sql
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) UNIQUE,
  phone VARCHAR(32),
  password VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
