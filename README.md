# Women's Safety Incident Heatmap

Area-wise and time-wise analysis of reported women's-safety incidents, with a live heatmap,
role-based login, incident reporting, summary reports and CSV export.
Built with **Python (Flask)**, **SQL (SQLite)**, Leaflet.js (heatmap) and Chart.js (charts).

> The sample data is **synthetic** (randomly generated for Pune areas) and is meant for demo/learning only.

## Features

| Module | What it does |
|---|---|
| Authentication | Register, login, logout; hashed passwords; CSRF protection; account lockout after 5 failed logins in 15 min; login log |
| Roles | **citizen** (report + see own reports + dashboard), **officer** (all incidents, update status, reports), **admin** (everything + user management) |
| **Safe Journey Planner** ⭐ | `/journey` (all roles): pick start, destination and departure time. Scores every area on the way **for the hour you will be there**, suggests a safer route via another area when one exists, shows risk for every departure hour and the safest time to leave (next 12 h), lists what is most reported on that route around that time, gives safety tips and a copyable trip summary. API: `/api/journey?from=ID&to=ID&when=YYYY-MM-DDTHH:MM` |
| **Trip Guardian** ⭐ | `/guardian` (all roles): start a trip timer with a trusted contact. A private **tracking link** (no login, no phone/email shown) auto-refreshes for the contact. Tap **I'm safe** on arrival, **+15 min** to extend (max 4), or **SOS**. If the deadline passes the trip becomes **Overdue** and appears on the officers' **🚨 Alerts** board (`/guardian/alerts`). Can be started directly from the Safe Journey Planner |
| Report incident | Area, type, date/time, description, optional map pin, anonymous option, validation |
| Heatmap dashboard | Leaflet heatmap weighted by severity, area risk markers, KPIs, filters (area, type, slot, status, dates) |
| Area-wise analysis | Incidents, severity-weighted risk score, resolution %, High/Medium/Low hotspot level |
| Time-wise analysis | Hour of day, time slot, day of week, monthly trend, **Area × Time-slot matrix** |
| Analysis dashboard | Power BI style page: slicers, KPI cards, 7 charts (area, hour, time slot, weekday, type, monthly trend, type × slot), area × hour heat grid; **click any bar/slice/cell to filter everything**; PDF/Excel reports include the same charts |
| Power BI kit | `/powerbi` page (officer/admin): star-schema CSV zip and Excel (fact + 4 dimensions, no personal data), `powerbi/POWERBI_GUIDE.md`, `measures.dax` (25 measures), `safety_theme.json`, `load_from_db.py` (live refresh from the database) |
| Analysis text | Automatic explanation of **what** is happening, **where**, **when**, **how** (patterns), the 30-day trend, possible reasons to investigate, and suggested actions; peak hour per area; type and severity by time slot |
| Report generation | Summary report with analysis, downloadable as **PDF**, **Excel (multi-sheet)** and **CSV**, or printed; all respect the filters (officer/admin) |
| Inquiries | Citizens submit inquiries (case status, safety concern, suggestion...), optionally linked to their incident; officers/admins reply; citizens see the reply and can close it. Citizens only see their own inquiries |
| Incident management | Search/filter/paginate incidents, status updates (Reported / Under Review / Resolved / Rejected) |
| Admin | Change user roles, activate/deactivate users |

## Project structure

```
womens_safety_heatmap/
├── app.py              # Flask app: auth, roles, APIs, reports
├── schema.sql          # Database schema (users, areas, incident_types, incidents, inquiries, trips, login_log)
├── queries.sql         # 10 documented analytical SQL queries
├── seed_data.py        # Creates safety.db with demo users + synthetic incidents
├── powerbi/            # Power BI guide, DAX measures, theme, Python loader
├── test_app.py         # Automated tests (pytest)
├── requirements.txt
├── templates/          # HTML pages
└── static/style.css
```

## Run it

**Windows (easiest):** double-click `run.bat`. It installs packages, creates the database and opens the browser.

Or manually:

```bash
pip install -r requirements.txt
python seed_data.py          # creates safety.db with ~1200 sample incidents
python app.py                # open http://127.0.0.1:5000
```

Demo logins:

| Role | Email | Password |
|---|---|---|
| Admin | admin@safety.local | Admin@123 |
| Officer | officer@safety.local | Officer@123 |
| Citizen | citizen@safety.local | Citizen@123 |

Run tests: `pytest -q`

## Using SQL directly

```bash
sqlite3 safety.db < queries.sql
```

## Using real data

Replace the seed data: insert real rows into `incidents` (keep `hour_of_day` and `day_of_week`
consistent with `incident_time`; `day_of_week` 0 = Monday). Add your city's areas to the `areas` table.

## Production notes

- Set a strong `SECRET_KEY` environment variable; run behind HTTPS with gunicorn/waitress, not the dev server.
- Change the demo passwords (or delete the demo users) before real use.
- Incident data is sensitive: restrict access, keep backups, and follow your local privacy laws.
- The heatmap uses OpenStreetMap tiles; follow their tile usage policy for heavy traffic.

## Possible extensions

Email alerts for new high-severity reports, real road routing (OSRM) in the Safe Journey Planner, ML hotspot prediction (DBSCAN / Prophet), real SMS/WhatsApp alerts for Trip Guardian (Twilio),
multilingual UI, MySQL/PostgreSQL via SQLAlchemy.
