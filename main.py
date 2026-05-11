from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import psycopg2
import psycopg2.extras
import os
import json
import hashlib
import hmac
import base64
import time
import uuid
from typing import Optional, Generator
from datetime import datetime, timezone

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://apexfit-frontend.vercel.app", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "apexfit-secret-change-in-prod")
security = HTTPBearer(auto_error=False)

# ── DB ────────────────────────────────────────────────────────────────────────

def _new_conn():
    """Raw connection — only used internally (init_db, endpoints managing their own conn)."""
    return psycopg2.connect(os.getenv("DATABASE_URL"))

def get_db():
    """FastAPI dependency — yields a connection and guarantees it is closed after the request."""
    conn = _new_conn()
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    conn = _new_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            google_id TEXT,
            name TEXT,
            avatar_initials TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS workouts (
            id SERIAL PRIMARY KEY,
            user_id TEXT REFERENCES users(id),
            workout_date TEXT,
            data JSONB
        );
        CREATE TABLE IF NOT EXISTS active_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT REFERENCES users(id),
            started_at TIMESTAMPTZ DEFAULT NOW(),
            data JSONB
        );
        CREATE TABLE IF NOT EXISTS user_goals (
            id SERIAL PRIMARY KEY,
            user_id TEXT REFERENCES users(id) UNIQUE,
            goals JSONB,
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS journal_entries (
            id SERIAL PRIMARY KEY,
            user_id TEXT REFERENCES users(id),
            workout_id INT,
            note TEXT,
            mood TEXT,
            energy_level INT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS progress_photos (
            id SERIAL PRIMARY KEY,
            user_id TEXT REFERENCES users(id),
            photo_url TEXT,
            note TEXT,
            body_weight NUMERIC,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS friendships (
            id SERIAL PRIMARY KEY,
            user_id TEXT REFERENCES users(id),
            friend_id TEXT REFERENCES users(id),
            status TEXT DEFAULT 'accepted',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(user_id, friend_id)
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

try:
    init_db()
except Exception as e:
    print("DB init error:", e)

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(salt + key).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        data = base64.b64decode(stored.encode())
        salt, key = data[:16], data[16:]
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return hmac.compare_digest(key, new_key)
    except:
        return False

def make_token(user_id: str) -> str:
    payload = f"{user_id}:{int(time.time()) + 86400 * 30}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{payload}:{sig}".encode()).decode()

def verify_token(token: str) -> Optional[str]:
    try:
        decoded = base64.b64decode(token.encode()).decode()
        parts = decoded.rsplit(':', 2)
        user_id, exp, sig = parts[0], parts[1], parts[2]
        if int(exp) < time.time():
            return None
        payload = f"{user_id}:{exp}"
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            return user_id
    except:
        pass
    return None

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> str:
    if not creds:
        raise HTTPException(401, "Not authenticated")
    uid = verify_token(creds.credentials)
    if not uid:
        raise HTTPException(401, "Invalid or expired token")
    return uid

# ── STAT COMPUTATION (no hardcoded values) ────────────────────────────────────

def compute_workout_stats(exercises: list, started_at_iso: str, ended_at_iso: str) -> dict:
    """
    Derives all chart-feeding stats purely from the exercises/sets data.
    - totalVolume  : sum of weight * reps for every completed set
    - totalSets    : count of completed sets
    - totalReps    : sum of reps for every completed set
    - durationMinutes: wall-clock time between start and end
    - muscleVolumes : per-muscle volume breakdown (feeds muscle-split chart)
    """
    total_volume = 0.0
    total_sets = 0
    total_reps = 0
    muscle_volumes: dict[str, float] = {}

    for ex in exercises:
        muscle = (ex.get("muscle") or "Other").strip()
        ex_volume = 0.0
        for s in ex.get("sets", []):
            if not s.get("completed"):
                continue
            weight = float(s.get("weight") or 0)
            reps   = int(s.get("reps") or 0)
            ex_volume  += weight * reps
            total_sets += 1
            total_reps += reps
        total_volume += ex_volume
        muscle_volumes[muscle] = muscle_volumes.get(muscle, 0.0) + ex_volume
        # write computed volume back onto the exercise object so it's stored
        ex["totalVolume"] = ex_volume

    # duration from real timestamps
    fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
    def _parse(ts):
        # handle both with and without microseconds, with and without Z
        ts = ts.replace("Z", "+00:00")
        for f in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(ts, f)
            except ValueError:
                continue
        raise ValueError(f"Cannot parse timestamp: {ts}")

    try:
        duration_minutes = round(
            (_parse(ended_at_iso) - _parse(started_at_iso)).total_seconds() / 60, 1
        )
    except Exception:
        duration_minutes = 0.0

    return {
        "totalVolume":     round(total_volume, 2),
        "totalSets":       total_sets,
        "totalReps":       total_reps,
        "durationMinutes": duration_minutes,
        "muscleVolumes":   muscle_volumes,   # stored in JSONB, used by muscle-split
    }

# ── HEALTH ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "ApexFit API Online"}

# ── AUTH ──────────────────────────────────────────────────────────────────────

@app.post("/auth/register")
async def register(request: Request):
    data = await request.json()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password", "")
    name = data.get("name", "").strip()
    if not email or not password or not name:
        raise HTTPException(400, "Name, email, and password required")
    if len(password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    if cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(409, "Email already registered")
    uid = str(uuid.uuid4())
    initials = "".join(w[0].upper() for w in name.split()[:2])
    cur.execute(
        "INSERT INTO users (id, email, password_hash, name, avatar_initials) VALUES (%s,%s,%s,%s,%s)",
        (uid, email, hash_password(password), name, initials)
    )
    conn.commit(); cur.close(); conn.close()
    return {"token": make_token(uid), "user": {"id": uid, "name": name, "email": email, "initials": initials}, "isNewUser": True}

@app.post("/auth/login")
async def login(request: Request):
    data = await request.json()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password", "")
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone(); cur.close(); conn.close()
    if not user or not verify_password(password, user["password_hash"] or ""):
        raise HTTPException(401, "Invalid email or password")
    return {"token": make_token(user["id"]),
            "user": {"id": user["id"], "name": user["name"], "email": user["email"], "initials": user["avatar_initials"]},
            "isNewUser": False}

@app.post("/auth/google")
async def google_auth(request: Request):
    data = await request.json()
    google_id = data.get("googleId")
    email = (data.get("email") or "").strip().lower()
    name = data.get("name", "")
    if not google_id or not email:
        raise HTTPException(400, "Invalid Google data")
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email=%s OR google_id=%s", (email, google_id))
    user = cur.fetchone()
    is_new = False
    if not user:
        is_new = True
        uid = str(uuid.uuid4())
        initials = "".join(w[0].upper() for w in name.split()[:2])
        cur.execute("INSERT INTO users (id, email, google_id, name, avatar_initials) VALUES (%s,%s,%s,%s,%s)",
                    (uid, email, google_id, name, initials))
        conn.commit()
        user = {"id": uid, "name": name, "email": email, "avatar_initials": initials}
    else:
        if not user["google_id"]:
            cur.execute("UPDATE users SET google_id=%s WHERE id=%s", (google_id, user["id"]))
            conn.commit()
    cur.close(); conn.close()
    return {"token": make_token(user["id"]),
            "user": {"id": user["id"], "name": user["name"], "email": user["email"], "initials": user["avatar_initials"]},
            "isNewUser": is_new}

@app.get("/auth/me")
def get_me(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, name, email, avatar_initials FROM users WHERE id=%s", (uid,))
    user = cur.fetchone(); cur.close(); conn.close()
    if not user:
        raise HTTPException(404, "User not found")
    return dict(user)

# ── GOALS ─────────────────────────────────────────────────────────────────────

@app.get("/goals")
def get_goals(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT goals FROM user_goals WHERE user_id=%s", (uid,))
    row = cur.fetchone(); cur.close(); conn.close()
    return row["goals"] if row else None

@app.post("/goals")
async def save_goals(request: Request, uid: str = Depends(get_current_user)):
    goals = await request.json()
    conn = _new_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO user_goals (user_id, goals) VALUES (%s,%s)
        ON CONFLICT (user_id) DO UPDATE SET goals=%s, updated_at=NOW()
    """, (uid, json.dumps(goals), json.dumps(goals)))
    conn.commit(); cur.close(); conn.close()
    return {"status": "saved"}

# ── ACTIVE WORKOUT SESSION ────────────────────────────────────────────────────

@app.post("/workout/start")
async def start_workout(request: Request, uid: str = Depends(get_current_user)):
    """
    Begin a new workout session.

    Request body (all optional):
      {
        "sessionName": "Push Day",
        "sessionType": "push",   // push | pull | legs | upper | lower | full | custom
        "exercises": []          // pre-loaded template exercises, or empty
      }

    Returns:
      { "sessionId": "<uuid>", "startedAt": "<ISO timestamp>", "data": { ... } }
    """
    body = await request.json()
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Only one active session per user at a time — discard any stale ones
    cur.execute("DELETE FROM active_sessions WHERE user_id=%s", (uid,))

    session_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    session_data = {
        "sessionId":   session_id,
        "sessionName": body.get("sessionName", "Workout"),
        "sessionType": body.get("sessionType", "custom"),
        "sessionDate": started_at,
        "startedAt":   started_at,
        "exercises":   body.get("exercises", []),
    }

    cur.execute(
        "INSERT INTO active_sessions (id, user_id, started_at, data) VALUES (%s, %s, %s, %s)",
        (session_id, uid, started_at, json.dumps(session_data))
    )
    conn.commit(); cur.close(); conn.close()
    return {"sessionId": session_id, "startedAt": started_at, "data": session_data}


@app.get("/workout/active")
def get_active_workout(uid: str = Depends(get_current_user)):
    """
    Returns the user's current in-progress session, or 404 if none.
    """
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM active_sessions WHERE user_id=%s", (uid,))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row:
        raise HTTPException(404, "No active workout session")
    return row["data"]


@app.patch("/workout/{session_id}")
async def update_active_workout(session_id: str, request: Request, uid: str = Depends(get_current_user)):
    """
    Save incremental progress during a workout (e.g. after each set is completed).

    Request body — send the full updated exercises array:
      {
        "exercises": [ { "name": "Bench Press", "muscle": "Chest", "sets": [...] } ],
        "sessionName": "Push Day",   // optional override
        "sessionType": "push"        // optional override
      }
    """
    body = await request.json()
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT data FROM active_sessions WHERE id=%s AND user_id=%s", (session_id, uid))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        raise HTTPException(404, "Active session not found")

    session_data = row["data"]
    if "exercises" in body:
        session_data["exercises"] = body["exercises"]
    if "sessionName" in body:
        session_data["sessionName"] = body["sessionName"]
    if "sessionType" in body:
        session_data["sessionType"] = body["sessionType"]

    cur.execute("UPDATE active_sessions SET data=%s WHERE id=%s AND user_id=%s",
                (json.dumps(session_data), session_id, uid))
    conn.commit(); cur.close(); conn.close()
    return {"status": "updated", "data": session_data}


@app.post("/workout/{session_id}/end")
async def end_workout(session_id: str, request: Request, uid: str = Depends(get_current_user)):
    """
    Finish the workout, compute ALL stats from real data, persist to workouts table,
    and clean up the active session.

    Request body (optional — send final exercises state if you haven't PATCH'd it):
      {
        "exercises": [...],    // final exercises with completed sets
        "sessionName": "...",
        "sessionType": "..."
      }

    Returns the fully computed workout record (same shape as /history/sessions rows).
    Every chart-feeding field is derived — nothing is hardcoded.
    """
    body = await request.json()
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("SELECT * FROM active_sessions WHERE id=%s AND user_id=%s", (session_id, uid))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        raise HTTPException(404, "Active session not found")

    session_data = row["data"]
    started_at   = str(row["started_at"])

    # Apply any final-moment updates from the request body
    if "exercises" in body:
        session_data["exercises"] = body["exercises"]
    if "sessionName" in body:
        session_data["sessionName"] = body["sessionName"]
    if "sessionType" in body:
        session_data["sessionType"] = body["sessionType"]

    ended_at = datetime.now(timezone.utc).isoformat()

    exercises = session_data.get("exercises", [])
    stats = compute_workout_stats(exercises, started_at, ended_at)

    # Build the complete workout record
    workout_record = {
        **session_data,
        "sessionDate":     session_data.get("startedAt", started_at),
        "endedAt":         ended_at,
        "totalVolume":     stats["totalVolume"],
        "totalSets":       stats["totalSets"],
        "totalReps":       stats["totalReps"],
        "durationMinutes": stats["durationMinutes"],
        "muscleVolumes":   stats["muscleVolumes"],
        "exercises":       exercises,  # now carries computed ex["totalVolume"]
    }

    cur.execute(
        "INSERT INTO workouts (user_id, workout_date, data) VALUES (%s, %s, %s) RETURNING id",
        (uid, workout_record["sessionDate"], json.dumps(workout_record))
    )
    workout_db_id = cur.fetchone()["id"]
    workout_record["workoutId"] = workout_db_id

    # Remove the active session
    cur.execute("DELETE FROM active_sessions WHERE id=%s AND user_id=%s", (session_id, uid))
    conn.commit(); cur.close(); conn.close()

    return workout_record


@app.delete("/workout/{session_id}/discard")
def discard_workout(session_id: str, uid: str = Depends(get_current_user)):
    """
    Cancel a workout without saving it.
    """
    conn = _new_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM active_sessions WHERE id=%s AND user_id=%s", (session_id, uid))
    conn.commit(); cur.close(); conn.close()
    return {"status": "discarded"}


# ── WORKOUTS (legacy save — kept for backwards compatibility) ─────────────────

@app.post("/save-workout")
async def save_workout(
    request: Request,
    uid: str = Depends(get_current_user),
):
    """
    Legacy endpoint. Prefer POST /workout/start -> PATCH -> POST /workout/{id}/end.
    Stats are recomputed here too so even legacy saves feed the charts correctly.
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    exercises = data.get("exercises", [])
    started_at = data.get("sessionDate", data.get("startedAt", ""))
    ended_at   = data.get("endedAt", started_at)

    # Recompute stats from real exercise data
    stats = compute_workout_stats(exercises, started_at, ended_at)

    # Merge computed stats into the record
    data.update({
        "totalVolume":     stats.get("totalVolume", 0),
        "totalSets":       stats.get("totalSets", 0),
        "totalReps":       stats.get("totalReps", 0),
        "durationMinutes": stats.get("durationMinutes", 0),
        "muscleVolumes":   stats.get("muscleVolumes", {}),
        "exercises":       exercises,
    })

    # Safely parse the date -- PostgreSQL needs a proper timestamptz, not a raw JS string
    session_date_str = data.get("sessionDate")
    if session_date_str:
        try:
            parsed_date = datetime.fromisoformat(session_date_str.replace("Z", "+00:00"))
        except ValueError:
            parsed_date = datetime.now(timezone.utc)
    else:
        parsed_date = datetime.now(timezone.utc)

    conn = _new_conn()
    cur = None
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO workouts (user_id, workout_date, data) VALUES (%s, %s, %s) RETURNING id",
            (uid, parsed_date, json.dumps(data))
        )
        wid = cur.fetchone()[0]
        conn.commit()
        return {"status": "success", "workoutId": wid}

    except Exception as e:
        conn.rollback()
        print(f"CRITICAL DB ERROR in /save-workout: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cur:
            cur.close()
        conn.close()

@app.get("/today/latest-session")
def get_latest(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT data FROM workouts WHERE user_id=%s ORDER BY (data->>'sessionDate')::timestamptz DESC LIMIT 1", (uid,))
    row = cur.fetchone(); cur.close(); conn.close()
    return row["data"] if row else {}

# ── STATS (all derived from stored data — zero hardcoding) ───────────────────

@app.get("/stats/summary")
def get_summary(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT COUNT(*) AS total_sessions,
               SUM((data->>'totalVolume')::numeric)     AS total_volume,
               AVG((data->>'durationMinutes')::numeric) AS avg_duration,
               SUM((data->>'totalSets')::numeric)       AS total_sets
        FROM workouts WHERE user_id=%s
    """, (uid,))
    row = cur.fetchone(); cur.close(); conn.close()
    return {
        "totalSessions": int(row["total_sessions"] or 0),
        "totalVolume":   int(row["total_volume"] or 0),
        "avgDuration":   round(float(row["avg_duration"] or 0), 1),
        "totalSets":     int(row["total_sets"] or 0),
    }

@app.get("/stats/weekly-volume")
def get_weekly_volume(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT TO_CHAR(DATE_TRUNC('week',(data->>'sessionDate')::timestamptz),'Mon DD') AS week,
               SUM((data->>'totalVolume')::numeric) AS volume
        FROM workouts WHERE user_id=%s
        GROUP BY DATE_TRUNC('week',(data->>'sessionDate')::timestamptz)
        ORDER BY DATE_TRUNC('week',(data->>'sessionDate')::timestamptz) DESC LIMIT 10
    """, (uid,))
    rows = cur.fetchall(); cur.close(); conn.close()
    rows.reverse()
    return [{"week": r["week"], "volume": int(r["volume"])} for r in rows]

@app.get("/stats/muscle-split")
def get_muscle_split(uid: str = Depends(get_current_user)):
    """
    Uses the computed muscleVolumes JSONB field written by compute_workout_stats,
    so results always match actual completed sets.
    """
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT key AS muscle, SUM(value::numeric) AS volume
        FROM workouts,
             jsonb_each_text(data->'muscleVolumes') AS kv(key, value)
        WHERE user_id=%s
        GROUP BY key
        ORDER BY volume DESC
    """, (uid,))
    rows = cur.fetchall()
    if not rows:
        # Fallback: derive from exercises array for older rows that pre-date muscleVolumes
        cur.execute("""
            SELECT ex->>'muscle' AS muscle, SUM((ex->>'totalVolume')::numeric) AS volume
            FROM workouts, jsonb_array_elements(data->'exercises') AS ex
            WHERE user_id=%s GROUP BY muscle ORDER BY volume DESC
        """, (uid,))
        rows = cur.fetchall()
    cur.close(); conn.close()
    total = sum(float(r["volume"]) for r in rows)
    return [{"muscle": r["muscle"], "volume": int(r["volume"]),
             "percent": round(float(r["volume"]) / total * 100, 1) if total else 0} for r in rows]

@app.get("/stats/lift-history")
def get_lift_history(exercise: str, uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT TO_CHAR((data->>'sessionDate')::timestamptz,'Mon DD') AS session_date,
               MAX((s->>'weight')::numeric) AS max_weight
        FROM workouts,
             jsonb_array_elements(data->'exercises') AS ex,
             jsonb_array_elements(ex->'sets') AS s
        WHERE user_id=%s
          AND LOWER(ex->>'name')=LOWER(%s)
          AND (s->>'completed')::boolean=true
        GROUP BY (data->>'sessionDate')::timestamptz
        ORDER BY (data->>'sessionDate')::timestamptz LIMIT 12
    """, (uid, exercise))
    rows = cur.fetchall(); cur.close(); conn.close()
    return [{"date": r["session_date"], "weight": float(r["max_weight"])} for r in rows]

@app.get("/stats/duration-by-day")
def get_duration_by_day(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT TO_CHAR((data->>'sessionDate')::timestamptz,'Dy') AS day_name,
               EXTRACT(DOW FROM (data->>'sessionDate')::timestamptz) AS day_num,
               AVG((data->>'durationMinutes')::numeric) AS avg_minutes
        FROM workouts WHERE user_id=%s GROUP BY day_name, day_num ORDER BY day_num
    """, (uid,))
    rows = cur.fetchall(); cur.close(); conn.close()
    day_map = {r["day_name"]: round(float(r["avg_minutes"]), 1) for r in rows}
    return [{"day": d, "minutes": day_map.get(d, 0)} for d in ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"]]

@app.get("/stats/consistency")
def get_consistency(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT TO_CHAR(DATE_TRUNC('month',(data->>'sessionDate')::timestamptz),'Mon YY') AS month,
               COUNT(*) AS sessions
        FROM workouts WHERE user_id=%s
        GROUP BY DATE_TRUNC('month',(data->>'sessionDate')::timestamptz)
        ORDER BY DATE_TRUNC('month',(data->>'sessionDate')::timestamptz) DESC LIMIT 6
    """, (uid,))
    rows = cur.fetchall(); cur.close(); conn.close()
    rows.reverse()
    return [{"month": r["month"], "percent": min(round(int(r["sessions"]) / 22 * 100, 1), 100)} for r in rows]

@app.get("/stats/personal-records")
def get_prs(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT ex->>'name' AS exercise, ex->>'muscle' AS muscle,
               MAX((s->>'weight')::numeric) AS max_weight,
               TO_CHAR(MAX((data->>'sessionDate')::timestamptz),'Mon DD, YYYY') AS last_date
        FROM workouts,
             jsonb_array_elements(data->'exercises') AS ex,
             jsonb_array_elements(ex->'sets') AS s
        WHERE user_id=%s AND (s->>'completed')::boolean=true
        GROUP BY exercise, muscle ORDER BY max_weight DESC
    """, (uid,))
    rows = cur.fetchall(); cur.close(); conn.close()
    return [{"exercise": r["exercise"], "muscle": r["muscle"],
             "maxWeight": float(r["max_weight"]), "lastDate": r["last_date"]} for r in rows]

# ── HISTORY ───────────────────────────────────────────────────────────────────

@app.get("/history/sessions")
def get_sessions(limit: int = 20, uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT w.id, data->>'sessionName' AS session_name, data->>'sessionType' AS session_type,
               data->>'sessionDate' AS session_date, (data->>'totalVolume')::numeric AS total_volume,
               (data->>'durationMinutes')::numeric AS duration_minutes,
               (data->>'totalSets')::numeric AS total_sets, (data->>'totalReps')::numeric AS total_reps,
               j.note AS journal_note, j.mood, j.energy_level
        FROM workouts w LEFT JOIN journal_entries j ON j.workout_id=w.id AND j.user_id=w.user_id
        WHERE w.user_id=%s ORDER BY (data->>'sessionDate')::timestamptz DESC LIMIT %s
    """, (uid, limit))
    rows = cur.fetchall(); cur.close(); conn.close()
    return [dict(r) for r in rows]

@app.get("/history/volume-by-type")
def get_volume_by_type(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT TO_CHAR(DATE_TRUNC('week',(data->>'sessionDate')::timestamptz),'Mon DD') AS week,
               data->>'sessionType' AS session_type, SUM((data->>'totalVolume')::numeric) AS volume
        FROM workouts WHERE user_id=%s
        GROUP BY DATE_TRUNC('week',(data->>'sessionDate')::timestamptz), session_type
        ORDER BY DATE_TRUNC('week',(data->>'sessionDate')::timestamptz) DESC LIMIT 20
    """, (uid,))
    rows = cur.fetchall(); cur.close(); conn.close()
    weeks = {}
    for r in rows:
        w = r["week"]
        if w not in weeks:
            weeks[w] = {"week": w, "push": 0, "pull": 0, "legs": 0}
        t = (r["session_type"] or "").lower()
        if t in weeks[w]:
            weeks[w][t] = int(r["volume"])
    return list(reversed(list(weeks.values())))

# ── JOURNAL ───────────────────────────────────────────────────────────────────

@app.post("/journal")
async def save_journal(request: Request, uid: str = Depends(get_current_user)):
    data = await request.json()
    conn = _new_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO journal_entries (user_id, workout_id, note, mood, energy_level) VALUES (%s,%s,%s,%s,%s)",
                (uid, data.get("workoutId"), data.get("note"), data.get("mood"), data.get("energyLevel")))
    conn.commit(); cur.close(); conn.close()
    return {"status": "saved"}

@app.get("/journal")
def get_journal(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT j.*, w.data->>'sessionName' AS session_name, w.data->>'sessionDate' AS session_date
        FROM journal_entries j LEFT JOIN workouts w ON w.id=j.workout_id
        WHERE j.user_id=%s ORDER BY j.created_at DESC LIMIT 30
    """, (uid,))
    rows = cur.fetchall(); cur.close(); conn.close()
    return [dict(r) for r in rows]

# ── PROGRESS PHOTOS ───────────────────────────────────────────────────────────

@app.post("/photos")
async def save_photo(request: Request, uid: str = Depends(get_current_user)):
    data = await request.json()
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("INSERT INTO progress_photos (user_id, photo_url, note, body_weight) VALUES (%s,%s,%s,%s) RETURNING id, created_at",
                (uid, data.get("photoUrl"), data.get("note"), data.get("bodyWeight")))
    row = cur.fetchone(); conn.commit(); cur.close(); conn.close()
    return {"id": row["id"], "createdAt": str(row["created_at"])}

@app.get("/photos")
def get_photos(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM progress_photos WHERE user_id=%s ORDER BY created_at DESC LIMIT 20", (uid,))
    rows = cur.fetchall(); cur.close(); conn.close()
    return [dict(r) for r in rows]

# ── LEADERBOARD ───────────────────────────────────────────────────────────────

@app.get("/leaderboard")
def get_leaderboard(uid: str = Depends(get_current_user)):
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT u.id, u.name, u.avatar_initials,
               COALESCE(SUM((w.data->>'totalVolume')::numeric),0) AS monthly_volume,
               COUNT(w.id) AS sessions_this_month
        FROM users u
        LEFT JOIN workouts w ON w.user_id=u.id
            AND DATE_TRUNC('month',(w.data->>'sessionDate')::timestamptz)=DATE_TRUNC('month',NOW())
        WHERE u.id=%s
           OR u.id IN (SELECT friend_id FROM friendships WHERE user_id=%s AND status='accepted')
           OR u.id IN (SELECT user_id FROM friendships WHERE friend_id=%s AND status='accepted')
        GROUP BY u.id, u.name, u.avatar_initials
        ORDER BY monthly_volume DESC LIMIT 20
    """, (uid, uid, uid))
    rows = cur.fetchall(); cur.close(); conn.close()
    return [{"rank": i+1, **dict(r), "isMe": r["id"]==uid} for i, r in enumerate(rows)]

@app.post("/friends/add")
async def add_friend(request: Request, uid: str = Depends(get_current_user)):
    data = await request.json()
    email = (data.get("email") or "").strip().lower()
    conn = _new_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, name FROM users WHERE email=%s", (email,))
    friend = cur.fetchone()
    if not friend:
        cur.close(); conn.close(); raise HTTPException(404, "No user with that email")
    if friend["id"] == uid:
        cur.close(); conn.close(); raise HTTPException(400, "Can't add yourself")
    cur.execute("INSERT INTO friendships (user_id, friend_id, status) VALUES (%s,%s,'accepted') ON CONFLICT DO NOTHING",
                (uid, friend["id"]))
    conn.commit(); cur.close(); conn.close()
    return {"status": "added", "friendName": friend["name"]}
