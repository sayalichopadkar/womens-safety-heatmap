import os
import re
import tempfile

import pytest

_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "test.db")

import app as app_module  # noqa: E402
import seed_data  # noqa: E402


@pytest.fixture(scope="module")
def client():
    seed_data.seed(300, db_path=os.environ["DB_PATH"])
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def token(client, url="/login"):
    html = client.get(url).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, email, pwd):
    return client.post("/login", data={"email": email, "password": pwd, "csrf_token": token(client)},
                       follow_redirects=True)


def logout(client):
    client.post("/logout", data={"csrf_token": token(client, "/dashboard")})


def test_requires_login(client):
    assert client.get("/dashboard").status_code == 302
    assert client.get("/api/stats").status_code == 302


def test_csrf_blocks_post(client):
    assert client.post("/login", data={"email": "a", "password": "b"}).status_code == 400


def test_bad_login(client):
    r = login(client, "admin@safety.local", "wrong")
    assert r.status_code == 401


def test_admin_flow(client):
    r = login(client, "admin@safety.local", "Admin@123")
    assert b"Incident Heatmap" in r.data
    stats = client.get("/api/stats").get_json()
    assert stats["kpis"]["total"] == 300
    assert len(stats["by_hour"]) == 24 and len(stats["by_weekday"]) == 7
    assert sum(stats["by_slot"]) == 300
    assert stats["by_area"][0]["level"] == "High"
    pts = client.get("/api/heatmap").get_json()
    assert len(pts) == 300
    # filters
    area_id = stats["by_area"][0]["id"]
    filtered = client.get(f"/api/stats?area_id={area_id}").get_json()
    assert filtered["kpis"]["total"] == stats["by_area"][0]["incidents"]
    assert client.get("/reports").status_code == 200
    csv = client.get("/reports/export.csv")
    assert csv.mimetype == "text/csv" and csv.get_data(as_text=True).count("\n") == 301
    assert client.get("/admin/users").status_code == 200
    assert client.get("/incidents?page=2").status_code == 200
    logout(client)


def test_citizen_permissions_and_report(client):
    login(client, "citizen@safety.local", "Citizen@123")
    assert client.get("/reports").status_code == 403
    assert client.get("/admin/users").status_code == 403
    t = token(client, "/report")
    r = client.post("/report", data={"csrf_token": t, "area_id": 1, "type_id": 1,
                                     "incident_time": "2026-01-05T21:30", "description": "test",
                                     "is_anonymous": "1"}, follow_redirects=True)
    assert b"reported" in r.data
    bad = client.post("/report", data={"csrf_token": t, "area_id": 99, "type_id": 1,
                                       "incident_time": "2999-01-01T10:00"})
    assert bad.status_code == 400
    logout(client)


def test_analysis_and_exports(client):
    login(client, "officer@safety.local", "Officer@123")
    r = client.get("/analysis")
    assert r.status_code == 200
    for canvas in (b'id="areaChart"', b'id="hourChart"', b'id="slotChart"', b'id="dayChart"',
                   b'id="typeChart"', b'id="trendChart"', b'id="typeSlotChart"', b'id="heat"'):
        assert canvas in r.data
    api = client.get("/api/analysis").get_json()
    headings = {f["heading"] for f in api["findings"]}
    assert {"What is happening", "Where it happens", "When it happens", "How it happens (patterns)",
            "Trend", "Suggested actions"} <= headings
    assert len(api["area_hour"]["grid"]) == len(api["stats"]["by_area"]) and len(api["area_hour"]["grid"][0]) == 24
    assert sum(sum(r) for r in api["type_slot"]["data"]) == api["total"]
    assert "id" in api["stats"]["by_type"][0]
    # click-to-filter keys: hour and weekday
    h = api["stats"]["kpis"]["peak_hour"]
    by_hour = client.get(f"/api/analysis?hour={h}").get_json()
    assert by_hour["total"] == api["stats"]["by_hour"][h]
    by_day = client.get("/api/analysis?weekday=2").get_json()
    assert by_day["total"] == api["stats"]["by_weekday"][2]
    both = client.get(f"/api/analysis?area_id=1&hour={h}").get_json()
    assert both["total"] <= by_hour["total"]
    assert client.get("/api/analysis?date_from=2999-01-01").get_json()["total"] == 0
    assert client.get("/api/analysis?hour=99&weekday=x").get_json()["total"] == api["total"]   # invalid ignored
    rep = client.get("/reports")
    assert b"Inquiries overview" in rep.data and b"PDF" in rep.data
    pdf = client.get("/reports/export.pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")
    assert client.get("/reports/export.pdf?date_from=2999-01-01").data.startswith(b"%PDF")
    xl = client.get("/reports/export.xlsx")
    assert xl.status_code == 200 and xl.data.startswith(b"PK")
    import io
    from openpyxl import load_workbook
    wb = load_workbook(io.BytesIO(xl.data))
    assert {"Summary", "Areas", "Area x Time slot", "Incidents"} <= set(wb.sheetnames)
    total = client.get("/api/stats").get_json()["kpis"]["total"]
    assert wb["Incidents"].max_row == total + 1   # header + one row per incident
    assert len(wb["Areas"]._charts) == 1 and len(wb["By hour"]._charts) == 1 and len(wb["Trend"]._charts) == 1
    # Power BI kit
    assert client.get("/powerbi").status_code == 200
    import zipfile
    z = zipfile.ZipFile(io.BytesIO(client.get("/powerbi/export.zip").data))
    names = set(z.namelist())
    assert {"fact_incidents.csv", "dim_area.csv", "dim_type.csv", "dim_date.csv", "dim_hour.csv",
            "measures.dax", "POWERBI_GUIDE.md", "safety_theme.json"} <= names
    fact = z.read("fact_incidents.csv").decode("utf-8-sig").splitlines()
    assert len(fact) == total + 1
    assert fact[0].startswith("incident_id,incident_date,incident_datetime,hour,time_slot")
    assert "user" not in fact[0] and "email" not in fact[0]            # no personal data
    assert len(z.read("dim_hour.csv").decode("utf-8-sig").splitlines()) == 25
    pbx = load_workbook(io.BytesIO(client.get("/powerbi/export.xlsx").data))
    assert set(pbx.sheetnames) == {"fact_incidents", "dim_area", "dim_type", "dim_date", "dim_hour"}
    for fname in ("POWERBI_GUIDE.md", "measures.dax", "safety_theme.json", "load_from_db.py"):
        assert client.get(f"/powerbi/files/{fname}").status_code == 200
    assert client.get("/powerbi/files/app.py").status_code == 404
    import json
    json.loads(client.get("/powerbi/files/safety_theme.json").data)
    logout(client)
    # citizens cannot export
    login(client, "citizen@safety.local", "Citizen@123")
    assert client.get("/reports/export.pdf").status_code == 403
    assert client.get("/reports/export.xlsx").status_code == 403
    for url in ("/powerbi", "/powerbi/export.zip", "/powerbi/export.xlsx", "/powerbi/files/measures.dax"):
        assert client.get(url).status_code == 403
    assert client.get("/analysis").status_code == 200
    assert client.get("/api/analysis").status_code == 200
    logout(client)


def test_inquiry_flow(client):
    # citizen submits
    login(client, "citizen@safety.local", "Citizen@123")
    t = token(client, "/inquiries/new")
    bad = client.post("/inquiries/new", data={"csrf_token": t, "category": "Other", "subject": "x", "message": "short"})
    assert bad.status_code == 400
    r = client.post("/inquiries/new", data={"csrf_token": t, "category": "Case status",
                                            "subject": "Status of my report",
                                            "message": "Please tell me what happened with my report."},
                    follow_redirects=True)
    assert b"Inquiry #1 submitted" in r.data
    assert b"Status of my report" in client.get("/inquiries").data
    # citizen cannot reply
    t = token(client, "/inquiries/1")
    assert client.post("/inquiries/1/reply", data={"csrf_token": t, "reply": "hack"}).status_code == 403
    logout(client)
    # officer replies
    login(client, "officer@safety.local", "Officer@123")
    assert b"Status of my report" in client.get("/inquiries").data
    t = token(client, "/inquiries/1")
    r = client.post("/inquiries/1/reply", data={"csrf_token": t, "reply": "We are reviewing it."}, follow_redirects=True)
    assert b"Reply sent" in r.data and b"Answered" in r.data
    logout(client)
    # citizen sees reply, another user cannot see it, citizen closes
    login(client, "citizen@safety.local", "Citizen@123")
    assert b"We are reviewing it." in client.get("/inquiries/1").data
    t = token(client, "/inquiries/1")
    r = client.post("/inquiries/1/close", data={"csrf_token": t}, follow_redirects=True)
    assert b"Closed" in r.data
    logout(client)
    login(client, "t@x.com", "Passw0rd123") if False else None


def test_inquiry_privacy(client):
    t = token(client, "/register")
    client.post("/register", data={"csrf_token": t, "name": "Other User", "email": "o@x.com",
                                   "password": "Passw0rd123", "confirm": "Passw0rd123"})
    login(client, "o@x.com", "Passw0rd123")
    assert client.get("/inquiries/1").status_code == 404
    logout(client)


def test_register_and_lockout(client):
    t = token(client, "/register")
    r = client.post("/register", data={"csrf_token": t, "name": "Test User", "email": "t@x.com",
                                       "password": "Passw0rd123", "confirm": "Passw0rd123"}, follow_redirects=True)
    assert b"Account created" in r.data
    for _ in range(5):
        login(client, "t@x.com", "bad")
    r = login(client, "t@x.com", "Passw0rd123")
    assert r.status_code == 429


def test_safe_journey(client):
    assert client.get("/journey").status_code == 302          # login required
    assert client.get("/api/journey?from=1&to=2").status_code == 302
    login(client, "citizen@safety.local", "Citizen@123")      # every role may use it
    page = client.get("/journey")
    assert page.status_code == 200 and b"Safe Journey Planner" in page.data
    r = client.get("/api/journey?from=1&to=8&when=2026-01-10T22:30")  # Pune Station -> Kothrud, night
    assert r.status_code == 200
    j = r.get_json()
    rec = j["recommended"]
    assert 0 <= rec["risk"] <= 100 and rec["level"] in ("Low", "Medium", "High")
    assert rec["stops"][0]["name"] == "Pune Station" and rec["stops"][-1]["name"] == "Kothrud"
    assert len(j["leave"]["hourly"]) == 24 and j["tips"]
    assert rec["risk"] <= j["direct"]["risk"]                 # never worse than the direct route
    # night should not be safer than the safest hour of the day for the same route
    assert j["leave"]["best_risk"] <= j["leave"]["hourly"][22]
    # validation
    assert client.get("/api/journey?from=1&to=1").status_code == 400
    assert client.get("/api/journey?from=x&to=2").status_code == 400
    assert client.get("/api/journey?from=1&to=2&when=bad").status_code == 400
    logout(client)


def _set_deadline(minutes_from_now):
    import sqlite3
    from datetime import datetime, timedelta
    con = sqlite3.connect(os.environ["DB_PATH"])
    dl = (datetime.now() + timedelta(minutes=minutes_from_now)).strftime("%Y-%m-%d %H:%M:%S")
    con.execute("UPDATE trips SET deadline = ? WHERE status = 'Active'", (dl,))
    con.commit(); con.close()


def test_trip_guardian(client):
    assert client.get("/guardian").status_code == 302                       # login required
    assert client.get("/guardian/alerts").status_code == 302
    login(client, "citizen@safety.local", "Citizen@123")
    t = token(client, "/guardian")
    bad = client.post("/guardian/start", data={"csrf_token": t, "from_area_id": "1", "to_area_id": "1",
                      "minutes": "30", "contact_name": "Mom", "contact_phone": "123"}, follow_redirects=True)
    assert b"must be different" in bad.data and b"valid contact phone" in bad.data
    ok = client.post("/guardian/start", data={"csrf_token": t, "from_area_id": "1", "to_area_id": "8",
                     "minutes": "30", "contact_name": "Mom", "contact_phone": "98765 43210"}, follow_redirects=True)
    assert b"Trip Guardian is ON" in ok.data
    html = ok.get_data(as_text=True)
    link = re.search(r"/track/([\w-]+)", html).group(1)
    # second trip while one is active is refused
    dup = client.post("/guardian/start", data={"csrf_token": t, "from_area_id": "2", "to_area_id": "8",
                      "minutes": "30", "contact_name": "Mom", "contact_phone": "9876543210"}, follow_redirects=True)
    assert b"already have a trip" in dup.data
    # extend
    r = client.post("/guardian/1/extend", data={"csrf_token": t}, follow_redirects=True)
    assert b"extended by 15" in r.data
    logout(client)

    # public tracking link needs no login and hides the phone number
    pub = client.get(f"/track/{link}")
    assert pub.status_code == 200 and b"9876543210" not in pub.data and b"Pune Station" in pub.data
    js = client.get(f"/track/{link}/status.json").get_json()
    assert js["status"] == "Active" and js["remaining"] > 0
    assert client.get("/track/not-a-real-token").status_code == 404

    # simulate a missed check-in -> OVERDUE, visible to officers but not citizens
    _set_deadline(-10)
    assert client.get(f"/track/{link}/status.json").get_json()["status"] == "Overdue"
    login(client, "citizen@safety.local", "Citizen@123")
    assert client.get("/guardian/alerts").status_code == 403
    logout(client)
    login(client, "officer@safety.local", "Officer@123")
    alerts = client.get("/guardian/alerts")
    assert alerts.status_code == 200 and b"Overdue" in alerts.data and b"9876543210" in alerts.data
    logout(client)

    # another user cannot touch this trip; owner raises SOS then marks safe
    login(client, "o@x.com", "Passw0rd123")
    t2 = token(client, "/guardian")
    assert client.post("/guardian/1/safe", data={"csrf_token": t2}).status_code == 404
    logout(client)
    login(client, "citizen@safety.local", "Citizen@123")
    t = token(client, "/guardian")
    assert b"SOS raised" in client.post("/guardian/1/sos", data={"csrf_token": t}, follow_redirects=True).data
    assert client.get(f"/track/{link}/status.json").get_json()["status"] == "SOS"
    assert b"Glad you reached" in client.post("/guardian/1/safe", data={"csrf_token": t}, follow_redirects=True).data
    assert client.get(f"/track/{link}/status.json").get_json()["status"] == "Safe"
    logout(client)
