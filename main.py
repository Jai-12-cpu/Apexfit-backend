from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
import os
import json

app = FastAPI()

# IMPORTANT: This allows your Vercel frontend to talk to this Railway backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For production, you can replace "*" with your Vercel URL
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to the Postgres database using the link in your Railway variables
def get_db_connection():
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    return conn

@app.post("/save-workout")
async def save_workout(request: Request):
    data = await request.json()
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Create the table automatically if it doesn't exist
    cur.execute("""
        CREATE TABLE IF NOT EXISTS workouts (
            id SERIAL PRIMARY KEY,
            workout_date TEXT,
            data JSONB
        )
    """)
    
    # Insert the workout data sent from your JS frontend
    cur.execute(
        "INSERT INTO workouts (workout_date, data) VALUES (%s, %s)",
        (data.get("sessionDate"), json.dumps(data))
    )
    
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "success", "message": "Workout saved to Railway!"}

@app.get("/")
def read_root():
    return {"message": "ApexFit API is Online"}
