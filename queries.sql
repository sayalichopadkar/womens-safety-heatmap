-- Women's Safety Incident Heatmap - analytical SQL queries
-- Run with:  sqlite3 safety.db < queries.sql   (or paste individual queries)

-- 1. AREA-WISE: incident count, severity-weighted risk score, resolution rate
SELECT a.name AS area,
       COUNT(i.id)                                   AS incidents,
       SUM(t.severity)                               AS risk_score,
       ROUND(100.0 * SUM(i.status = 'Resolved') / COUNT(i.id), 1) AS resolved_pct
FROM incidents i
JOIN areas a          ON a.id = i.area_id
JOIN incident_types t ON t.id = i.type_id
GROUP BY a.id
ORDER BY risk_score DESC;

-- 2. TIME-WISE: incidents by hour of day
SELECT hour_of_day AS hour, COUNT(*) AS incidents
FROM incidents
GROUP BY hour_of_day
ORDER BY hour_of_day;

-- 3. TIME-WISE: incidents by time slot
SELECT CASE
         WHEN hour_of_day >= 22 OR hour_of_day < 5 THEN 'Night (10PM-5AM)'
         WHEN hour_of_day < 12 THEN 'Morning (5AM-12PM)'
         WHEN hour_of_day < 17 THEN 'Afternoon (12PM-5PM)'
         ELSE 'Evening (5PM-10PM)'
       END AS time_slot,
       COUNT(*) AS incidents
FROM incidents
GROUP BY time_slot
ORDER BY incidents DESC;

-- 4. TIME-WISE: incidents by weekday (0 = Monday)
SELECT day_of_week, COUNT(*) AS incidents
FROM incidents
GROUP BY day_of_week
ORDER BY day_of_week;

-- 5. AREA x TIME SLOT matrix (the heart of the heatmap analysis)
SELECT a.name AS area,
       SUM(i.hour_of_day >= 22 OR i.hour_of_day < 5)  AS night,
       SUM(i.hour_of_day BETWEEN 5 AND 11)            AS morning,
       SUM(i.hour_of_day BETWEEN 12 AND 16)           AS afternoon,
       SUM(i.hour_of_day BETWEEN 17 AND 21)           AS evening
FROM incidents i
JOIN areas a ON a.id = i.area_id
GROUP BY a.id
ORDER BY (night + evening) DESC;

-- 6. Monthly trend
SELECT substr(incident_time, 1, 7) AS month, COUNT(*) AS incidents
FROM incidents
GROUP BY month
ORDER BY month;

-- 7. Incident type breakdown
SELECT t.name AS type, t.severity, COUNT(i.id) AS incidents
FROM incident_types t
LEFT JOIN incidents i ON i.type_id = t.id
GROUP BY t.id
ORDER BY incidents DESC;

-- 8. Peak hour for each area (window function; SQLite 3.25+)
SELECT area, hour_of_day, incidents FROM (
    SELECT a.name AS area, i.hour_of_day, COUNT(*) AS incidents,
           ROW_NUMBER() OVER (PARTITION BY a.id ORDER BY COUNT(*) DESC) AS rn
    FROM incidents i JOIN areas a ON a.id = i.area_id
    GROUP BY a.id, i.hour_of_day
) WHERE rn = 1
ORDER BY incidents DESC;

-- 9. Hotspots: areas with a rising trend (last 30 days vs previous 30 days)
SELECT a.name AS area,
       SUM(i.incident_time >= date('now', '-30 day'))                                   AS last_30,
       SUM(i.incident_time <  date('now', '-30 day')
           AND i.incident_time >= date('now', '-60 day'))                               AS prev_30
FROM incidents i JOIN areas a ON a.id = i.area_id
GROUP BY a.id
ORDER BY last_30 - prev_30 DESC;

-- 10. Security: failed logins in the last 15 minutes per email
SELECT email, COUNT(*) AS failures
FROM login_log
WHERE success = 0 AND created_at >= datetime('now', '-15 minutes')
GROUP BY email
HAVING failures >= 3;
