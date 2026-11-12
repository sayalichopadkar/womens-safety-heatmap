"""Create the database and fill it with realistic SYNTHETIC sample data.

Usage:  python seed_data.py            (creates safety.db, ~1200 incidents)
        python seed_data.py 3000       (custom number of incidents)

All incidents are randomly generated for demo/learning purposes only.
"""
import os
import random
import sqlite3
import sys
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "safety.db")

# (name, city, lat, lng, relative risk weight)
AREAS = [
    ("Pune Station", "Pune", 18.5286, 73.8744, 9),
    ("Swargate", "Pune", 18.5018, 73.8636, 9),
    ("Shivajinagar", "Pune", 18.5308, 73.8475, 7),
    ("Deccan", "Pune", 18.5167, 73.8416, 5),
    ("Camp", "Pune", 18.5136, 73.8786, 6),
    ("Hadapsar", "Pune", 18.5089, 73.9260, 6),
    ("Katraj", "Pune", 18.4575, 73.8677, 6),
    ("Kothrud", "Pune", 18.5074, 73.8077, 3),
    ("Baner", "Pune", 18.5590, 73.7868, 3),
    ("Wakad", "Pune", 18.5974, 73.7898, 4),
    ("Hinjewadi", "Pune", 18.5912, 73.7389, 5),
    ("Viman Nagar", "Pune", 18.5679, 73.9143, 4),
]

# (name, severity 1-5, relative frequency)
TYPES = [
    ("Verbal Harassment", 2, 30),
    ("Stalking", 3, 14),
    ("Eve Teasing", 2, 22),
    ("Groping / Inappropriate Touch", 4, 12),
    ("Chain / Phone Snatching", 3, 9),
    ("Domestic Violence (reported)", 4, 4),
    ("Attempted Assault", 5, 3),
    ("Cyber Harassment", 2, 6),
]

# hour -> relative weight (peaks in the evening / late night)
HOUR_WEIGHTS = [6, 4, 3, 2, 1, 1, 2, 3, 4, 3, 3, 3, 3, 3, 3, 4, 5, 7, 10, 12, 12, 11, 9, 8]

STATUS_CHOICES = ["Reported", "Under Review", "Resolved", "Rejected"]
STATUS_WEIGHTS = [25, 20, 50, 5]

DEMO_USERS = [
    ("Admin User", "admin@safety.local", "Admin@123", "admin"),
    ("Officer Patil", "officer@safety.local", "Officer@123", "officer"),
    ("Citizen Demo", "citizen@safety.local", "Citizen@123", "citizen"),
]


def seed(n_incidents=1200, db_path=DB_PATH):
    random.seed(42)
    if os.path.exists(db_path):
        os.remove(db_path)
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA foreign_keys = ON")
    with open(os.path.join(BASE, "schema.sql"), encoding="utf-8") as f:
        con.executescript(f.read())

    for name, email, pwd, role in DEMO_USERS:
        con.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,?)",
            (name, email, generate_password_hash(pwd), role),
        )
    for name, city, lat, lng, _ in AREAS:
        con.execute("INSERT INTO areas (name, city, lat, lng) VALUES (?,?,?,?)", (name, city, lat, lng))
    for name, sev, _ in TYPES:
        con.execute("INSERT INTO incident_types (name, severity) VALUES (?,?)", (name, sev))

    area_ids = list(range(1, len(AREAS) + 1))
    area_w = [a[4] for a in AREAS]
    type_ids = list(range(1, len(TYPES) + 1))
    type_w = [t[2] for t in TYPES]
    descriptions = [
        "Incident reported near the main road.",
        "Happened close to the bus stop.",
        "Occurred in a poorly lit lane.",
        "Reported outside a market area.",
        "Happened while walking home.",
        "Occurred near the railway/transport stop.",
    ]

    now = datetime.now()
    rows = []
    for _ in range(n_incidents):
        aid = random.choices(area_ids, area_w)[0]
        tid = random.choices(type_ids, type_w)[0]
        _, _, lat, lng, _ = AREAS[aid - 1]
        day = now - timedelta(days=random.randint(0, 180))
        hour = random.choices(range(24), HOUR_WEIGHTS)[0]
        ts = day.replace(hour=hour, minute=random.randint(0, 59), second=0, microsecond=0)
        if ts > now:
            ts -= timedelta(days=1)
        # scatter around the area centre (~1 km)
        rows.append((
            random.choice([None, 3]), aid, tid, random.choice(descriptions),
            round(lat + random.gauss(0, 0.0055), 6), round(lng + random.gauss(0, 0.0055), 6),
            ts.strftime("%Y-%m-%d %H:%M"), ts.hour, ts.weekday(),
            random.choices(STATUS_CHOICES, STATUS_WEIGHTS)[0], random.choice([0, 0, 1]),
        ))
    con.executemany(
        """INSERT INTO incidents (user_id, area_id, type_id, description, latitude, longitude,
                                  incident_time, hour_of_day, day_of_week, status, is_anonymous)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    con.commit()
    con.close()
    print(f"Database created: {db_path}  ({n_incidents} incidents)")
    print("Demo logins:")
    for _, email, pwd, role in DEMO_USERS:
        print(f"  {role:8s} {email}  /  {pwd}")


if __name__ == "__main__":
    seed(int(sys.argv[1]) if len(sys.argv) > 1 else 1200)
