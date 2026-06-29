# =============================================================
#  PROMPTIFY — Database Connection
#  File: database.py
# =============================================================
#
#  HOW MONGODB WORKS (simple explanation):
#  ----------------------------------------
#  MongoDB stores data as "documents" (like Python dicts / JSON).
#  A "collection" is like a table in SQL.
#  No fixed schema — each document can have different fields.
#
#  We use TWO collections:
#    users            → stores accounts (name, email, hashed password)
#    prompt_history   → stores every prompt scan (linked to a user)
#
#  CONNECTION OPTIONS:
#  ───────────────────
#  Option A — MongoDB Atlas (FREE cloud, recommended for FYP demo):
#    1. Go to https://www.mongodb.com/cloud/atlas/register
#    2. Create a FREE cluster
#    3. Click "Connect" → "Drivers" → copy the connection string
#    4. Paste it in .env as MONGO_URI=mongodb+srv://...
#
#  Option B — Local MongoDB:
#    1. Install from https://www.mongodb.com/try/download/community
#    2. Start with: mongod
#    3. MONGO_URI=mongodb://localhost:27017/ (the default below)
#
# =============================================================

from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure
import os
from dotenv import load_dotenv

load_dotenv()  # loads values from .env file

# ── Connection URI ───────────────────────────────────────────
# Reads from .env file. Falls back to local if not set.
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
DB_NAME   = os.getenv('DB_NAME',   'promptify')

# ── Connect ──────────────────────────────────────────────────
client = None
db = None
users_col = None
history_col = None

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    client.admin.command('ping')   # test the connection
    db = client[DB_NAME]
    users_col = db['users']
    history_col = db['prompt_history']
    print(f"[DB] Connected to MongoDB — database: '{DB_NAME}'")
except Exception as e:
    print("[DB] ERROR: Could not connect to MongoDB.")
    print(f"[DB] Details: {e}")
    print("[DB] Check your MONGO_URI in the .env file.")
    client = None
    db = None
    users_col = None
    history_col = None

# ── Indexes (speeds up searches) ─────────────────────────────
# Create a unique index on email so duplicate accounts are blocked
if users_col is not None and history_col is not None:
    try:
        users_col.create_index([('email', ASCENDING)], unique=True)
        history_col.create_index([('user_email', ASCENDING)])
        print("[DB] Indexes ready.")
    except Exception as e:
        print(f"[DB] Warning: Could not create indexes: {e}")
