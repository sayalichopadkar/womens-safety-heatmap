"""Power BI: load the Women's Safety database directly (Python script data source).

How to use in Power BI Desktop:
  1. File > Options and settings > Options > Python scripting: choose your Python folder.
     (pip install pandas   must be done in that Python first.)
  2. Home > Get data > More... > Other > Python script > Connect.
  3. Paste this whole file, change DB_PATH below to your safety.db, click OK.
  4. In the Navigator tick all five tables (fact_incidents, dim_area, dim_type, dim_date, dim_hour) > Load.
Refresh the report any time to pull the latest incidents.
"""
import sqlite3
from datetime import timedelta

import pandas as pd

DB_PATH = r"C:\Users\SAYALI\Downloads\womens_safety_heatmap\womens_safety_heatmap\safety.db"   # <-- change this

SLOTS = ["Morning (5AM-12PM)", "Afternoon (12PM-5PM)", "Evening (5PM-10PM)", "Night (10PM-5AM)"]


def slot_for_hour(h):
    return SLOTS[3] if h >= 22 or h < 5 else SLOTS[0] if h < 12 else SLOTS[1] if h < 17 else SLOTS[2]


con = sqlite3.connect(DB_PATH)
raw = pd.read_sql_query(
    """SELECT i.id AS incident_id, i.incident_time AS incident_datetime, i.hour_of_day AS hour,
              i.day_of_week AS dow, i.area_id, i.type_id, t.severity, i.status, i.latitude, i.longitude
       FROM incidents i JOIN incident_types t ON t.id = i.type_id ORDER BY i.id""", con)
dim_area = pd.read_sql_query("SELECT id AS area_id, name AS area_name, city, lat AS latitude, lng AS longitude FROM areas", con)
dim_type = pd.read_sql_query("SELECT id AS type_id, name AS type_name, severity FROM incident_types", con)
con.close()

fact_incidents = raw.copy()
fact_incidents["incident_date"] = pd.to_datetime(fact_incidents["incident_datetime"]).dt.normalize()
fact_incidents["time_slot"] = fact_incidents["hour"].map(slot_for_hour)
fact_incidents["weekday_no"] = fact_incidents["dow"] + 1
fact_incidents["is_open"] = fact_incidents["status"].isin(["Reported", "Under Review"]).astype(int)
fact_incidents["is_severe"] = (fact_incidents["severity"] >= 4).astype(int)
fact_incidents = fact_incidents.drop(columns=["dow"])

if len(fact_incidents):
    days = pd.date_range(fact_incidents["incident_date"].min(), fact_incidents["incident_date"].max(), freq="D")
else:
    days = pd.DatetimeIndex([])
dim_date = pd.DataFrame({"date": days})
dim_date["year"] = dim_date["date"].dt.year
dim_date["month_no"] = dim_date["date"].dt.month
dim_date["month_name"] = dim_date["date"].dt.strftime("%B")
dim_date["year_month"] = dim_date["date"].dt.strftime("%Y-%m")
dim_date["day"] = dim_date["date"].dt.day
dim_date["weekday_no"] = dim_date["date"].dt.weekday + 1
dim_date["weekday_name"] = dim_date["date"].dt.strftime("%A")
dim_date["is_weekend"] = (dim_date["date"].dt.weekday >= 5).astype(int)

dim_hour = pd.DataFrame({"hour": range(24)})
dim_hour["hour_label"] = dim_hour["hour"].map(lambda h: f"{h:02d}:00")
dim_hour["time_slot"] = dim_hour["hour"].map(slot_for_hour)
dim_hour["slot_order"] = dim_hour["time_slot"].map(lambda s: SLOTS.index(s) + 1)
