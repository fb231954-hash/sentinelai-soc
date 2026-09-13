
import sqlite3, json
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path("sentinelai.db")

def connect():
    c=sqlite3.connect(DB_PATH)
    c.row_factory=sqlite3.Row
    return c

def init_db():
    c=connect()
    c.execute("""CREATE TABLE IF NOT EXISTS incidents(
        incident_id TEXT PRIMARY KEY, created_at TEXT, incident_type TEXT, severity TEXT,
        risk INTEGER, confidence INTEGER, source_ip TEXT, target TEXT, mitre_id TEXT,
        mitre_name TEXT, tactic TEXT, status TEXT, summary TEXT, evidence TEXT,
        recommended_action TEXT, approved INTEGER DEFAULT 0, action_executed INTEGER DEFAULT 0,
        verified INTEGER DEFAULT 0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, event_type TEXT, user TEXT,
        source_ip TEXT, destination TEXT, service TEXT, status TEXT, raw TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, detail TEXT)""")
    c.commit(); c.close()

def audit(action, detail, actor="SentinelAI"):
    c=connect()
    c.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
              (datetime.now(timezone.utc).isoformat(),actor,action,detail))
    c.commit(); c.close()

def save_events(events):
    c=connect()
    for e in events:
        c.execute("""INSERT INTO events(ts,event_type,user,source_ip,destination,service,status,raw)
                     VALUES(?,?,?,?,?,?,?,?)""",
                  (e.timestamp,e.event_type,e.user,e.source_ip,e.destination,e.service,e.status,e.raw))
    c.commit(); c.close()

def save_incident(row):
    c=connect()
    c.execute("""INSERT OR REPLACE INTO incidents
      (incident_id,created_at,incident_type,severity,risk,confidence,source_ip,target,
       mitre_id,mitre_name,tactic,status,summary,evidence,recommended_action,approved,
       action_executed,verified)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", row)
    c.commit(); c.close()

def update_incident(iid, **fields):
    if not fields: return
    c=connect()
    sets=", ".join(f"{k}=?" for k in fields)
    c.execute(f"UPDATE incidents SET {sets} WHERE incident_id=?", [*fields.values(),iid])
    c.commit(); c.close()

def incidents():
    c=connect(); r=c.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall(); c.close(); return r

def audit_rows(limit=60):
    c=connect(); r=c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?",(limit,)).fetchall(); c.close(); return r

def event_count():
    c=connect(); n=c.execute("SELECT COUNT(*) FROM events").fetchone()[0]; c.close(); return n
