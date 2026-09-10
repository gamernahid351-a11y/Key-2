import os
import secrets
import string
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

DB_FILE = os.environ.get("DB_FILE", "keys.db")
PORT = int(os.environ.get("PORT", "10000"))

# Optional protection for key generation/revoke.
# Set ADMIN_TOKEN in Render Environment Variables.
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")


def now_utc():
    return datetime.now(timezone.utc)


def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            validity_hours REAL NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            used INTEGER NOT NULL DEFAULT 0,
            used_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0,
            revoked_at TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


def admin_required():
    """
    If ADMIN_TOKEN is configured, require:
    Authorization: Bearer YOUR_TOKEN
    """

    if not ADMIN_TOKEN:
        return True

    auth = request.headers.get("Authorization", "")

    return auth == f"Bearer {ADMIN_TOKEN}"


def generate_key():
    chars = string.ascii_uppercase + string.digits

    conn = db()

    try:
        while True:
            suffix = "".join(
                secrets.choice(chars)
                for _ in range(5)
            )

            key = f"MEHEDI-{suffix}"

            row = conn.execute(
                "SELECT id FROM keys WHERE key = ?",
                (key,)
            ).fetchone()

            if row is None:
                return key

    finally:
        conn.close()


@app.get("/")
def home():
    return jsonify({
        "success": True,
        "name": "MEHEDI KEY API",
        "version": "1.0",
        "status": "online",
        "endpoints": {
            "generate": "POST /gen-key?validity=24",
            "check": "GET /check?key=MEHEDI-XXXXX",
            "revoke": "POST /revoke?key=MEHEDI-XXXXX"
        }
    })


@app.post("/gen-key")
def gen_key():

    if not admin_required():
        return jsonify({
            "success": False,
            "error": "unauthorized"
        }), 401

    validity_raw = request.args.get("validity")

    if validity_raw is None:
        return jsonify({
            "success": False,
            "error": "validity is required"
        }), 400

    try:
        validity = float(validity_raw)
    except ValueError:
        return jsonify({
            "success": False,
            "error": "validity must be a number"
        }), 400

    if validity <= 0:
        return jsonify({
            "success": False,
            "error": "validity must be greater than 0"
        }), 400

    if validity > 8760:
        return jsonify({
            "success": False,
            "error": "maximum validity is 8760 hours"
        }), 400

    created = now_utc()
    expires = created + timedelta(hours=validity)

    key = generate_key()

    conn = db()

    conn.execute("""
        INSERT INTO keys (
            key,
            validity_hours,
            created_at,
            expires_at,
            status,
            used,
            revoked
        )
        VALUES (?, ?, ?, ?, 'active', 0, 0)
    """, (
        key,
        validity,
        created.isoformat(),
        expires.isoformat()
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "key": key,
        "status": "active",
        "one_time": True,
        "validity_hours": validity,
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat()
    })


@app.get("/check")
def check_key():

    key = request.args.get("key", "").strip().upper()

    if not key:
        return jsonify({
            "success": False,
            "valid": False,
            "error": "key is required"
        }), 400

    conn = db()

    # BEGIN IMMEDIATE makes the check + use operation atomic.
    # This helps prevent two simultaneous requests using the same key.
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute("""
            SELECT *
            FROM keys
            WHERE key = ?
        """, (key,)).fetchone()

        if row is None:
            conn.rollback()

            return jsonify({
                "success": True,
                "valid": False,
                "reason": "key_not_found"
            })

        data = dict(row)

        if data["revoked"]:
            conn.rollback()

            return jsonify({
                "success": True,
                "valid": False,
                "reason": "revoked",
                "key": key
            })

        if data["used"]:
            conn.rollback()

            return jsonify({
                "success": True,
                "valid": False,
                "reason": "already_used",
                "key": key,
                "used_at": data["used_at"]
            })

        expires = datetime.fromisoformat(data["expires_at"])
        current = now_utc()

        if current >= expires:

            conn.execute("""
                UPDATE keys
                SET status = 'expired'
                WHERE key = ?
            """, (key,))

            conn.commit()

            return jsonify({
                "success": True,
                "valid": False,
                "reason": "expired",
                "key": key,
                "expires_at": data["expires_at"]
            })

        # ==========================================
        # FIRST VALID USE -> IMMEDIATELY CONSUME KEY
        # ==========================================

        used_at = current.isoformat()

        conn.execute("""
            UPDATE keys
            SET
                status = 'used',
                used = 1,
                used_at = ?
            WHERE key = ?
        """, (
            used_at,
            key
        ))

        conn.commit()

        remaining_seconds = int(
            (expires - current).total_seconds()
        )

        return jsonify({
            "success": True,
            "valid": True,
            "status": "used",
            "first_use": True,
            "key": key,
            "expires_at": data["expires_at"],
            "used_at": used_at,
            "remaining_seconds": remaining_seconds
        })

    except Exception as e:

        conn.rollback()

        return jsonify({
            "success": False,
            "valid": False,
            "error": str(e)
        }), 500

    finally:
        conn.close()


@app.post("/revoke")
def revoke_key():

    if not admin_required():
        return jsonify({
            "success": False,
            "error": "unauthorized"
        }), 401

    key = request.args.get("key", "").strip().upper()

    if not key:
        return jsonify({
            "success": False,
            "error": "key is required"
        }), 400

    conn = db()

    row = conn.execute(
        "SELECT id FROM keys WHERE key = ?",
        (key,)
    ).fetchone()

    if row is None:
        conn.close()

        return jsonify({
            "success": False,
            "error": "key not found"
        }), 404

    revoked_at = now_utc().isoformat()

    conn.execute("""
        UPDATE keys
        SET
            status = 'revoked',
            revoked = 1,
            revoked_at = ?
        WHERE key = ?
    """, (
        revoked_at,
        key
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "key": key,
        "status": "revoked",
        "revoked_at": revoked_at
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=PORT
    )