-- Women's Safety Incident Heatmap - database schema (SQLite)
PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS trips;
DROP TABLE IF EXISTS inquiries;
DROP TABLE IF EXISTS login_log;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS incident_types;
DROP TABLE IF EXISTS areas;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'citizen'
                  CHECK (role IN ('admin', 'officer', 'citizen')),
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE areas (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    city TEXT NOT NULL,
    lat  REAL NOT NULL,
    lng  REAL NOT NULL
);

CREATE TABLE incident_types (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL UNIQUE,
    severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 5)  -- used as heat weight
);

CREATE TABLE incidents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    area_id       INTEGER NOT NULL REFERENCES areas(id),
    type_id       INTEGER NOT NULL REFERENCES incident_types(id),
    description   TEXT,
    latitude      REAL NOT NULL,
    longitude     REAL NOT NULL,
    incident_time TEXT NOT NULL,            -- 'YYYY-MM-DD HH:MM'
    hour_of_day   INTEGER NOT NULL CHECK (hour_of_day BETWEEN 0 AND 23),
    day_of_week   INTEGER NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),  -- 0=Mon
    status        TEXT NOT NULL DEFAULT 'Reported'
                  CHECK (status IN ('Reported', 'Under Review', 'Resolved', 'Rejected')),
    is_anonymous  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Inquiries: citizens ask questions, officers/admins reply
CREATE TABLE inquiries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    category    TEXT NOT NULL,
    subject     TEXT NOT NULL,
    message     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Answered', 'Closed')),
    reply       TEXT,
    replied_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    replied_at  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Trip Guardian: safety timer with a private tracking link for a trusted contact
CREATE TABLE trips (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    from_area_id  INTEGER NOT NULL REFERENCES areas(id),
    to_area_id    INTEGER NOT NULL REFERENCES areas(id),
    contact_name  TEXT NOT NULL,
    contact_phone TEXT NOT NULL,
    note          TEXT,
    token         TEXT NOT NULL UNIQUE,
    started_at    TEXT NOT NULL,
    deadline      TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Safe', 'SOS', 'Cancelled')),
    ended_at      TEXT,
    extended_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE login_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL,
    success    INTEGER NOT NULL,
    ip         TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_incidents_area ON incidents(area_id);
CREATE INDEX idx_incidents_type ON incidents(type_id);
CREATE INDEX idx_incidents_time ON incidents(incident_time);
CREATE INDEX idx_incidents_hour ON incidents(hour_of_day);
CREATE INDEX idx_login_log_email ON login_log(email, created_at);
CREATE INDEX idx_trips_user ON trips(user_id, status);
