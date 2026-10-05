"""
PENYLI — BEYOND REALMS v10.0
PAYMENT SERVER — Stripe Checkout + Webhook

Environment:
  STRIPE_SECRET_KEY=sk_...
  STRIPE_WEBHOOK_SECRET=whsec_...
  BASE_URL=https://your-domain.example
  PORT=4242

Install:
  pip install flask stripe python-dotenv

Run:
  python PENYLI_BEYOND_REALMS_v10_0_PAYMENT_SERVER.py
"""

import os, sqlite3, uuid, hashlib, json, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from datetime import datetime, timezone
from flask import Flask, request, jsonify, redirect
from dotenv import load_dotenv
import stripe

load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH']=64*1024
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]
BASE_URL = os.environ.get("BASE_URL", "http://localhost:4242")
DB = os.environ.get("PENYLI_DB", "penyli_payment_v84.db")
AMOUNT_CENTS = 100
CURRENCY = "usd"

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.execute("""
      CREATE TABLE IF NOT EXISTS payments (
        payment_id TEXT PRIMARY KEY,
        client_request_id TEXT UNIQUE NOT NULL,
        checkout_session_id TEXT UNIQUE,
        payment_intent_id TEXT UNIQUE,
        creation_id TEXT UNIQUE,
        amount_cents INTEGER NOT NULL,
        currency TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        paid_at TEXT
      )
    """)

    con.execute("""
      CREATE TABLE IF NOT EXISTS creations (
        creation_id TEXT PRIMARY KEY,
        payment_id TEXT UNIQUE NOT NULL,
        realm_id TEXT,
        gene_id TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        status TEXT NOT NULL
      )
    """)

    con.execute("""
      CREATE TABLE IF NOT EXISTS realms (
        realm_id TEXT PRIMARY KEY,
        world_version INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        state_hash TEXT NOT NULL,
        last_creation_id TEXT,
        updated_at TEXT NOT NULL
      )
    """)
    con.execute("""
      CREATE TABLE IF NOT EXISTS realm_mutations (
        mutation_id TEXT PRIMARY KEY,
        realm_id TEXT NOT NULL,
        creation_id TEXT UNIQUE NOT NULL,
        gene_id TEXT UNIQUE NOT NULL,
        parent_world_version INTEGER NOT NULL,
        world_version INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        mutation_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    """)

    con.execute("""
      CREATE TABLE IF NOT EXISTS realm_state (
        realm_id TEXT PRIMARY KEY,
        state_json TEXT NOT NULL,
        state_hash TEXT NOT NULL,
        state_version INTEGER NOT NULL,
        updated_at TEXT NOT NULL
      )
    """)

    con.execute("""
      CREATE TABLE IF NOT EXISTS realm_replay_audits (
        audit_id TEXT PRIMARY KEY,
        realm_id TEXT NOT NULL,
        stored_state_hash TEXT,
        replayed_state_hash TEXT,
        mutation_count INTEGER NOT NULL,
        status TEXT NOT NULL,
        audited_at TEXT NOT NULL
      )
    """)

    con.execute("""
      CREATE TABLE IF NOT EXISTS realm_genomes (
        realm_id TEXT PRIMARY KEY,
        genome_hash TEXT NOT NULL,
        mutation_count INTEGER NOT NULL,
        world_version INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    """)

    con.execute("""
      CREATE TABLE IF NOT EXISTS realm_identities (
        realm_id TEXT PRIMARY KEY,
        identity_hash TEXT UNIQUE NOT NULL,
        genesis_hash TEXT NOT NULL,
        genome_hash TEXT NOT NULL,
        identity_version INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    """)

    con.execute("""
      CREATE TABLE IF NOT EXISTS realm_signatures (
        realm_id TEXT PRIMARY KEY,
        identity_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        key_id TEXT NOT NULL,
        signed_at TEXT NOT NULL
      )
    """)
    con.commit()
    con.close()

def now():
    return datetime.now(timezone.utc).isoformat()



ALLOWED_ORIGINS={x.strip() for x in os.environ.get("PENYLI_ALLOWED_ORIGINS","").split(",") if x.strip()}





@app.get("/api/mvp/readiness")
def mvp_readiness():
    checks={
        "stripe_secret_configured":bool(os.environ.get("STRIPE_SECRET_KEY")),
        "stripe_webhook_configured":bool(os.environ.get("STRIPE_WEBHOOK_SECRET")),
        "base_url_configured":bool(os.environ.get("BASE_URL")),
        "signing_key_configured":os.path.exists(SIGNING_KEY_PATH),
        "allowed_origins_configured":bool(ALLOWED_ORIGINS),
        "production_mode":PRODUCTION
    }
    return jsonify({
        "ready":all(checks.values()),
        "checks":checks,
        "note":"No secret values are returned."
    })

@app.get("/api/mvp/status")
def mvp_status():
    return jsonify({
        "product":"PENYLI — BEYOND REALMS",
        "version":"v10.0",
        "status":"MVP",
        "flow":[
            "PAYMENT","CREATION","GENE","REALM","STATE",
            "HISTORY","REPLAY","GENOME","IDENTITY","SIGNATURE",
            "PUBLIC_VERIFICATION","CERTIFICATE"
        ],
        "price_usd":1.00,
        "live_payment_required":True
    })

@app.get("/health")
def health():
    con=db()
    try:
        con.execute("SELECT 1").fetchone()
        return jsonify({"status":"ok","service":"PENYLI","version":"v10.0"})
    finally:
        con.close()

@app.errorhandler(413)
def request_too_large(error):
    return jsonify({"error":"REQUEST_TOO_LARGE"}),413

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error":"INTERNAL_SERVER_ERROR"}),500

@app.before_request
def enforce_origin_policy():
    if request.method in ("POST","PUT","PATCH","DELETE") and ALLOWED_ORIGINS:
        origin=request.headers.get("Origin")
        if origin and origin not in ALLOWED_ORIGINS:
            return jsonify({"error":"ORIGIN_NOT_ALLOWED"}),403

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"]="no-store"
    if request.is_secure:
        response.headers["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
    return response

@app.get("/api/payment/create")
def create_payment():
    client_request_id = request.args.get("client_request_id") or str(uuid.uuid4())

    con = db()
    row = con.execute(
        "SELECT * FROM payments WHERE client_request_id=?",
        (client_request_id,)
    ).fetchone()

    if row:
        con.close()
        return jsonify({
            "payment_id": row["payment_id"],
            "checkout_session_id": row["checkout_session_id"],
            "status": row["status"]
        })

    payment_id = "PAY-" + uuid.uuid4().hex.upper()
    con.execute("""
      INSERT INTO payments
      (payment_id,client_request_id,amount_cents,currency,status,created_at)
      VALUES (?,?,?,?,?,?)
    """, (payment_id, client_request_id, AMOUNT_CENTS, CURRENCY, "CREATED", now()))
    con.commit()
    con.close()

    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{
            "price_data": {
                "currency": CURRENCY,
                "product_data": {"name": "PENYLI — BEYOND REALMS Creation"},
                "unit_amount": AMOUNT_CENTS
            },
            "quantity": 1
        }],
        metadata={
            "payment_id": payment_id,
            "client_request_id": client_request_id,
            "purpose": "REALM_CREATION"
        },
        success_url=BASE_URL + "/payment/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=BASE_URL + "/payment/cancel"
    )

    con = db()
    con.execute("""
      UPDATE payments SET checkout_session_id=?, status='CHECKOUT_CREATED'
      WHERE payment_id=?
    """, (session.id, payment_id))
    con.commit()
    con.close()

    return jsonify({
        "payment_id": payment_id,
        "checkout_url": session.url,
        "status": "CHECKOUT_CREATED"
    })

@app.post("/api/payment/webhook")
def webhook():
    payload = request.data
    signature = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload, signature, WEBHOOK_SECRET
        )
    except Exception:
        return jsonify({"error": "invalid webhook"}), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        if session.get("payment_status") != "paid":
            return jsonify({"received": True})

        meta = session.get("metadata") or {}
        payment_id = meta.get("payment_id")
        if not payment_id or meta.get("purpose") != "REALM_CREATION":
            return jsonify({"error": "invalid payment metadata"}), 400

        con = db()
        row = con.execute(
            "SELECT * FROM payments WHERE payment_id=?",
            (payment_id,)
        ).fetchone()

        if row and row["status"] != "PAID":
            creation_id = "CREATION-" + uuid.uuid4().hex.upper()
            gene_id = "GENE-" + uuid.uuid4().hex.upper()
            con.execute("""
              UPDATE payments
              SET payment_intent_id=?, creation_id=?, status='PAID', paid_at=?
              WHERE payment_id=?
            """, (
                session.get("payment_intent"),
                creation_id,
                now(),
                payment_id
            ))
            con.execute("""
              INSERT INTO creations
              (creation_id,payment_id,realm_id,gene_id,created_at,status)
              VALUES (?,?,?,?,?,?)
            """, (
                creation_id, payment_id, None, gene_id, now(), "CREATED"
            ))
            con.commit()
        con.close()

    return jsonify({"received": True})



def canonical_json(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",",":"))

def evolve_realm_state(previous, mutation):
    previous = previous or {
        "gene_count": 0,
        "generation": 0,
        "world_version": 0,
        "density": 0,
        "motion": 0,
        "form": 0,
        "rhythm": 0,
        "texture": 0
    }
    # Deterministic projection from the immutable Gene ID.
    seed = int(hashlib.sha256(
        mutation["gene_id"].encode("utf-8")
    ).hexdigest()[:16],16)
    return {
        "gene_count": previous["gene_count"] + 1,
        "generation": mutation["generation"],
        "world_version": mutation["world_version"],
        "density": (previous["density"] + seed % 101) % 101,
        "motion": (previous["motion"] + (seed >> 8) % 101) % 101,
        "form": (previous["form"] + (seed >> 16) % 101) % 101,
        "rhythm": (previous["rhythm"] + (seed >> 24) % 101) % 101,
        "texture": (previous["texture"] + (seed >> 32) % 101) % 101
    }

def get_realm_state(con, realm_id):
    row=con.execute(
        "SELECT * FROM realm_state WHERE realm_id=?", (realm_id,)
    ).fetchone()
    if not row:
        return None
    return json.loads(row["state_json"])

def persist_realm_state(con, realm_id, state):
    raw=canonical_json(state)
    state_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest()
    con.execute(
        "INSERT INTO realm_state(realm_id,state_json,state_hash,state_version,updated_at) "
        "VALUES(?,?,?,?,?) "
        "ON CONFLICT(realm_id) DO UPDATE SET state_json=excluded.state_json,"
        "state_hash=excluded.state_hash,state_version=excluded.state_version,"
        "updated_at=excluded.updated_at",
        (realm_id,raw,state_hash,state["world_version"],now())
    )
    return state_hash






PRODUCTION = os.environ.get("PENYLI_ENV","production").lower()=="production"

SIGNING_KEY_PATH = os.environ.get("PENYLI_SIGNING_KEY_PATH", "penyli_ed25519_private.pem")
SIGNING_KEY_ID = os.environ.get("PENYLI_SIGNING_KEY_ID", "PENYLI-ROOT-2026-V1")

def load_signing_key():
    if not os.path.exists(SIGNING_KEY_PATH):
        key=ed25519.Ed25519PrivateKey.generate()
        with open(SIGNING_KEY_PATH,"wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        try:
            os.chmod(SIGNING_KEY_PATH,0o600)
        except Exception:
            pass
        return key
    with open(SIGNING_KEY_PATH,"rb") as f:
        return serialization.load_pem_private_key(f.read(),password=None)



def build_realm_certificate(con, realm_id):
    identity=persist_realm_identity(con,realm_id)
    genome=persist_realm_genome(con,realm_id)
    state_row=con.execute("SELECT state_hash,generation,world_version FROM realm_state WHERE realm_id=?",(realm_id,)).fetchone()
    if not state_row: raise ValueError("REALM_STATE_NOT_FOUND")
    sig=con.execute("SELECT signature,algorithm,key_id,signed_at FROM realm_signatures WHERE realm_id=?",(realm_id,)).fetchone()
    if not sig:
        sign_realm_identity(con,realm_id); con.commit()
        sig=con.execute("SELECT signature,algorithm,key_id,signed_at FROM realm_signatures WHERE realm_id=?",(realm_id,)).fetchone()
    payload={"certificate_version":"1","realm_id":realm_id,"identity_hash":identity["identity_hash"],"genome_hash":genome["genome_hash"],"state_hash":state_row[0],"generation":state_row[1],"world_version":state_row[2],"signature":sig[0],"algorithm":sig[1],"key_id":sig[2],"signed_at":sig[3]}
    return {**payload,"certificate_hash":hashlib.sha256(canonical_json(payload).encode()).hexdigest()}

def get_signing_public_key_b64():
    key=load_signing_key()
    public=key.public_key()
    raw=public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")

def verify_realm_signature_record(con, realm_id):
    row=con.execute(
        "SELECT realm_id,identity_hash,signature,algorithm,key_id,signed_at "
        "FROM realm_signatures WHERE realm_id=?",(realm_id,)
    ).fetchone()
    if not row:
        return {"valid":False,"reason":"SIGNATURE_NOT_FOUND","realm_id":realm_id}

    payload=canonical_json({
        "realm_id":row[0],
        "identity_hash":row[1],
        "identity_version":1
    }).encode("utf-8")

    try:
        public=load_signing_key().public_key()
        public.verify(base64.b64decode(row[2]),payload)
        return {
            "valid":True,
            "realm_id":row[0],
            "identity_hash":row[1],
            "algorithm":row[3],
            "key_id":row[4],
            "signed_at":row[5]
        }
    except Exception:
        return {
            "valid":False,
            "realm_id":row[0],
            "identity_hash":row[1],
            "algorithm":row[3],
            "key_id":row[4],
            "signed_at":row[5],
            "reason":"SIGNATURE_INVALID"
        }

def sign_realm_identity(con, realm_id):
    identity=persist_realm_identity(con,realm_id)
    message=canonical_json({
        "realm_id":identity["realm_id"],
        "identity_hash":identity["identity_hash"],
        "identity_version":identity["identity_version"]
    }).encode("utf-8")
    key=load_signing_key()
    signature=base64.b64encode(key.sign(message)).decode("ascii")

    con.execute(
        "INSERT INTO realm_signatures "
        "(realm_id,identity_hash,signature,algorithm,key_id,signed_at) "
        "VALUES (?,?,?,?,?,?) "
        "ON CONFLICT(realm_id) DO UPDATE SET identity_hash=excluded.identity_hash,"
        "signature=excluded.signature,algorithm=excluded.algorithm,"
        "key_id=excluded.key_id,signed_at=excluded.signed_at",
        (realm_id,identity["identity_hash"],signature,"Ed25519",SIGNING_KEY_ID,now())
    )
    return {
        "realm_id":realm_id,
        "identity_hash":identity["identity_hash"],
        "signature":signature,
        "algorithm":"Ed25519",
        "key_id":SIGNING_KEY_ID,
        "signed_at":now()
    }

def calculate_realm_identity(con, realm_id):
    genesis = con.execute(
        "SELECT * FROM realm_mutations WHERE realm_id=? ORDER BY world_version ASC LIMIT 1",
        (realm_id,)
    ).fetchone()
    genome = con.execute(
        "SELECT * FROM realm_genomes WHERE realm_id=?", (realm_id,)
    ).fetchone()

    genesis_material = (
        (genesis["mutation_hash"] if genesis else "GENESIS-EMPTY")
        + "|"
        + (genesis["creation_id"] if genesis else "NO-CREATION")
        + "|"
        + realm_id
    )
    genesis_hash = hashlib.sha256(genesis_material.encode("utf-8")).hexdigest()
    genome_hash = genome["genome_hash"] if genome else hashlib.sha256(
        ("EMPTY-GENOME|"+realm_id).encode("utf-8")
    ).hexdigest()

    identity_material = "|".join([
        "PENYLI-BEYOND-REALMS",
        "REALM-IDENTITY-V1",
        realm_id,
        genesis_hash,
        genome_hash
    ])
    identity_hash = hashlib.sha256(
        identity_material.encode("utf-8")
    ).hexdigest()

    return {
        "realm_id":realm_id,
        "identity_hash":identity_hash,
        "genesis_hash":genesis_hash,
        "genome_hash":genome_hash,
        "identity_version":1
    }

def persist_realm_identity(con, realm_id):
    identity=calculate_realm_identity(con,realm_id)
    existing=con.execute(
        "SELECT * FROM realm_identities WHERE realm_id=?", (realm_id,)
    ).fetchone()
    timestamp=now()
    if existing:
        con.execute(
            "UPDATE realm_identities SET identity_hash=?,genesis_hash=?,"
            "genome_hash=?,identity_version=?,updated_at=? WHERE realm_id=?",
            (identity["identity_hash"],identity["genesis_hash"],
             identity["genome_hash"],identity["identity_version"],
             timestamp,realm_id)
        )
    else:
        con.execute(
            "INSERT INTO realm_identities "
            "(realm_id,identity_hash,genesis_hash,genome_hash,identity_version,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (realm_id,identity["identity_hash"],identity["genesis_hash"],
             identity["genome_hash"],identity["identity_version"],
             timestamp,timestamp)
        )
    return identity

def calculate_realm_genome(con, realm_id):
    mutations=con.execute(
        "SELECT creation_id,gene_id,world_version,generation,mutation_hash "
        "FROM realm_mutations WHERE realm_id=? ORDER BY world_version ASC",
        (realm_id,)
    ).fetchall()

    chain=[]
    for m in mutations:
        chain.append({
            "creation_id":m["creation_id"],
            "gene_id":m["gene_id"],
            "world_version":m["world_version"],
            "generation":m["generation"],
            "mutation_hash":m["mutation_hash"]
        })

    canonical=canonical_json({
        "realm_id":realm_id,
        "mutations":chain
    })
    genome_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    last=mutations[-1] if mutations else None
    return {
        "realm_id":realm_id,
        "genome_hash":genome_hash,
        "mutation_count":len(mutations),
        "world_version":last["world_version"] if last else 0,
        "generation":last["generation"] if last else 0
    }

def persist_realm_genome(con, realm_id):
    genome=calculate_realm_genome(con,realm_id)
    existing=con.execute(
        "SELECT * FROM realm_genomes WHERE realm_id=?", (realm_id,)
    ).fetchone()
    timestamp=now()
    if existing:
        con.execute(
            "UPDATE realm_genomes SET genome_hash=?,mutation_count=?,"
            "world_version=?,generation=?,updated_at=? WHERE realm_id=?",
            (genome["genome_hash"],genome["mutation_count"],
             genome["world_version"],genome["generation"],timestamp,realm_id)
        )
    else:
        con.execute(
            "INSERT INTO realm_genomes "
            "(realm_id,genome_hash,mutation_count,world_version,generation,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (realm_id,genome["genome_hash"],genome["mutation_count"],
             genome["world_version"],genome["generation"],timestamp,timestamp)
        )
    return genome

def replay_realm_state(con, realm_id):
    mutations=con.execute(
        "SELECT * FROM realm_mutations WHERE realm_id=? ORDER BY world_version ASC",
        (realm_id,)
    ).fetchall()

    state=None
    for mutation in mutations:
        state=evolve_realm_state(state,dict(mutation))

    stored=con.execute(
        "SELECT * FROM realm_state WHERE realm_id=?", (realm_id,)
    ).fetchone()

    if state is None:
        return {
            "realm_id":realm_id,
            "mutation_count":0,
            "replayed_state":None,
            "replayed_state_hash":None,
            "stored_state_hash":stored["state_hash"] if stored else None,
            "status":"EMPTY"
        }

    replayed_raw=canonical_json(state)
    replayed_hash=hashlib.sha256(replayed_raw.encode("utf-8")).hexdigest()
    stored_hash=stored["state_hash"] if stored else None
    status="VALID" if stored_hash==replayed_hash else "DIVERGENCE"

    return {
        "realm_id":realm_id,
        "mutation_count":len(mutations),
        "replayed_state":state,
        "replayed_state_hash":replayed_hash,
        "stored_state_hash":stored_hash,
        "status":status
    }

def realm_hash(realm_id, world_version, generation, creation_id, gene_id):
    payload = "|".join([
        realm_id, str(world_version), str(generation),
        creation_id, gene_id
    ]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def apply_creation_to_realm(creation_id, realm_id=None):
    con = db()
    creation = con.execute(
        "SELECT * FROM creations WHERE creation_id=?",
        (creation_id,)
    ).fetchone()
    if not creation:
        con.close()
        return None, "CREATION_NOT_FOUND"

    # Idempotent: the same Creation can mutate the Realm only once.
    existing = con.execute(
        "SELECT * FROM realm_mutations WHERE creation_id=?",
        (creation_id,)
    ).fetchone()
    if existing:
        con.close()
        return dict(existing), None

    realm_id = realm_id or creation["realm_id"] or "REALM-GLOBAL"
    realm = con.execute(
        "SELECT * FROM realms WHERE realm_id=?",
        (realm_id,)
    ).fetchone()

    if realm:
        parent_version = realm["world_version"]
        generation = realm["generation"] + 1
    else:
        parent_version = 0
        generation = 1
        con.execute(
            "INSERT INTO realms(realm_id,world_version,generation,state_hash,last_creation_id,updated_at) "
            "VALUES(?,?,?,?,?,?)",
            (realm_id, 0, 0, hashlib.sha256(realm_id.encode()).hexdigest(), None, now())
        )

    new_version = parent_version + 1
    mutation_id = "MUTATION-" + uuid.uuid4().hex.upper()
    mutation_hash = realm_hash(
        realm_id, new_version, generation,
        creation_id, creation["gene_id"]
    )

    con.execute(
        "UPDATE creations SET realm_id=?, status='APPLIED_TO_REALM' WHERE creation_id=?",
        (realm_id, creation_id)
    )
    con.execute(
        "INSERT INTO realm_mutations "
        "(mutation_id,realm_id,creation_id,gene_id,parent_world_version,"
        "world_version,generation,mutation_hash,created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (mutation_id, realm_id, creation_id, creation["gene_id"],
         parent_version, new_version, generation, mutation_hash, now())
    )
    con.execute(
        "UPDATE realms SET world_version=?,generation=?,state_hash=?,"
        "last_creation_id=?,updated_at=? WHERE realm_id=?",
        (new_version, generation, mutation_hash, creation_id, now(), realm_id)
    )

    mutation_row = con.execute(
        "SELECT * FROM realm_mutations WHERE mutation_id=?",
        (mutation_id,)
    ).fetchone()
    previous_state = get_realm_state(con, realm_id)
    new_state = evolve_realm_state(previous_state, dict(mutation_row))
    state_hash = persist_realm_state(con, realm_id, new_state)

    con.execute(
        "UPDATE realms SET state_hash=? WHERE realm_id=?",
        (state_hash, realm_id)
    )
    persist_realm_genome(con, realm_id)
    persist_realm_identity(con, realm_id)
    sign_realm_identity(con, realm_id)
    con.commit()

    row=con.execute(
        "SELECT * FROM realm_mutations WHERE mutation_id=?",
        (mutation_id,)
    ).fetchone()
    con.close()
    return dict(row), None

@app.get("/api/payment/status/<payment_id>")
def payment_status(payment_id):
    con = db()
    row = con.execute(
        "SELECT payment_id,creation_id,status,amount_cents,currency,paid_at "
        "FROM payments WHERE payment_id=?",
        (payment_id,)
    ).fetchone()
    con.close()

    if not row:
        return jsonify({"error": "not found"}), 404

    return jsonify(dict(row))










@app.get("/api/realm/<realm_id>/certificate")
def realm_certificate(realm_id):
    con=db()
    try:
        result=build_realm_certificate(con,realm_id); con.close(); return jsonify(result)
    except ValueError as e:
        con.close(); return jsonify({"error":str(e),"realm_id":realm_id}),404

@app.get("/api/realm/<realm_id>/certificate/export")
def realm_certificate_export(realm_id):
    con=db()
    try:
        result=build_realm_certificate(con,realm_id); con.close()
        response=make_response(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))
        response.headers["Content-Type"]="application/json; charset=utf-8"
        response.headers["Content-Disposition"]='attachment; filename="PENYLI_REALM_CERTIFICATE_'+realm_id+'.json"'
        return response
    except ValueError as e:
        con.close(); return jsonify({"error":str(e),"realm_id":realm_id}),404

@app.get("/api/realm/public-key")
def realm_public_key():
    return jsonify({
        "algorithm":"Ed25519",
        "key_id":SIGNING_KEY_ID,
        "public_key":get_signing_public_key_b64()
    })

@app.get("/api/realm/<realm_id>/signature/verify")
def realm_signature_verify(realm_id):
    con=db()
    result=verify_realm_signature_record(con,realm_id)
    con.close()
    return jsonify(result)

@app.get("/api/realm/<realm_id>/signature")
def realm_signature(realm_id):
    con=db()
    result=sign_realm_identity(con,realm_id)
    con.commit()
    con.close()
    return jsonify(result)

@app.get("/api/realm/<realm_id>/identity")
def realm_identity(realm_id):
    con=db()
    identity=persist_realm_identity(con,realm_id)
    con.commit()
    con.close()
    return jsonify(identity)

@app.get("/api/realm/<realm_id>/genome")
def realm_genome(realm_id):
    con=db()
    genome=persist_realm_genome(con,realm_id)
    con.commit()
    con.close()
    return jsonify(genome)

@app.post("/api/realm/<realm_id>/integrity")
def realm_integrity(realm_id):
    con=db()
    result=replay_realm_state(con,realm_id)
    audit_id="AUDIT-"+uuid.uuid4().hex.upper()
    con.execute(
        "INSERT INTO realm_replay_audits "
        "(audit_id,realm_id,stored_state_hash,replayed_state_hash,"
        "mutation_count,status,audited_at) VALUES (?,?,?,?,?,?,?)",
        (audit_id,realm_id,result.get("stored_state_hash"),
         result.get("replayed_state_hash"),result["mutation_count"],
         result["status"],now())
    )
    con.commit()
    con.close()
    result["audit_id"]=audit_id
    return jsonify(result)

@app.get("/api/realm/<realm_id>/state")
def realm_state_status(realm_id):
    con=db()
    row=con.execute(
        "SELECT * FROM realm_state WHERE realm_id=?", (realm_id,)
    ).fetchone()
    con.close()
    if not row:
        return jsonify({"error":"state not found"}),404
    return jsonify({
        "realm_id":row["realm_id"],
        "state":json.loads(row["state_json"]),
        "state_hash":row["state_hash"],
        "state_version":row["state_version"],
        "updated_at":row["updated_at"]
    })

@app.post("/api/creation/<creation_id>/apply")
def apply_creation(creation_id):
    payload=request.get_json(silent=True) or {}
    realm_id=payload.get("realm_id") or "REALM-GLOBAL"
    result,error=apply_creation_to_realm(creation_id,realm_id)
    if error:
        return jsonify({"error":error}),404
    return jsonify({
        "status":"APPLIED_TO_REALM",
        "mutation":result
    })

@app.get("/api/creation/<creation_id>")
def creation_status(creation_id):
    con = db()
    row = con.execute(
        "SELECT creation_id,payment_id,realm_id,gene_id,created_at,status "
        "FROM creations WHERE creation_id=?", (creation_id,)
    ).fetchone()
    con.close()
    if not row:
        return jsonify({"error":"not found"}), 404
    return jsonify(dict(row))

@app.get("/payment/success")
def success():
    session_id = request.args.get("session_id")
    return redirect("/")

@app.get("/payment/cancel")
def cancel():
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","10000")), debug=False)
