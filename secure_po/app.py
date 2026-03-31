from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash
from models import db, User, PurchaseOrder, AuditLog
from crypto_utils import generate_po_hash, recompute_hash_for_po
from key_utils import (
    sign_po_hash,
    verify_po_signature,
    rsa_encrypt_session_key,
    rsa_decrypt_session_key,
    generate_nonce,
    sign_nonce,
    verify_nonce
)
from hybrid_crypto import aes_encrypt_payload, aes_decrypt_payload
from functools import wraps
from datetime import datetime, timedelta, UTC
from zoneinfo import ZoneInfo
from dotenv import load_dotenv
load_dotenv()
import hashlib
import uuid
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_fallback_key")

db.init_app(app)

MAX_MESSAGE_AGE_MINUTES = 10


def log_action(actor, action, po_number=None, details=None):
    last_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
    previous_hash = last_log.current_hash if last_log and last_log.current_hash else "0"

    timestamp = datetime.now(UTC)

    log_string = f"{actor}|{action}|{po_number}|{details}|{timestamp.isoformat()}|{previous_hash}"
    current_hash = hashlib.sha256(log_string.encode("utf-8")).hexdigest()

    log = AuditLog(
        actor=actor,
        action=action,
        po_number=po_number,
        details=details,
        timestamp=timestamp,
        previous_hash=previous_hash,
        current_hash=current_hash
    )
    db.session.add(log)
    db.session.commit()


def verify_audit_chain():
    logs = AuditLog.query.order_by(AuditLog.id.asc()).all()

    previous_hash = "0"
    for log in logs:
        log_string = f"{log.actor}|{log.action}|{log.po_number}|{log.details}|{log.timestamp.isoformat()}|{previous_hash}"
        recomputed = hashlib.sha256(log_string.encode("utf-8")).hexdigest()

        if log.previous_hash != previous_hash:
            return False, f"Broken chain at log ID {log.id}: previous hash mismatch."

        if log.current_hash != recomputed:
            return False, f"Broken chain at log ID {log.id}: current hash mismatch."

        previous_hash = log.current_hash

    return True, "Audit chain verified successfully."


def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "username" not in session:
                flash("Please log in first.")
                return redirect(url_for("login"))

            if role and session.get("role") != role:
                flash("Access denied.")
                return redirect(url_for("login"))

            return f(*args, **kwargs)
        return wrapped
    return decorator


def parse_iso_timestamp(timestamp_str):
    if not timestamp_str:
        return None
    try:
        return datetime.fromisoformat(timestamp_str)
    except ValueError:
        return None


def is_timestamp_fresh(timestamp_str, max_age_minutes=MAX_MESSAGE_AGE_MINUTES):
    ts = parse_iso_timestamp(timestamp_str)
    if ts is None:
        return False, "Invalid timestamp format."

    now = datetime.now(UTC)
    max_age = timedelta(minutes=max_age_minutes)

    if ts > now:
        return False, "Timestamp is in the future."

    if now - ts > max_age:
        return False, f"Timestamp expired. Older than {max_age_minutes} minutes."

    return True, "Timestamp is valid."


def detect_replay(po):
    if po.final_decision is not None:
        return True, "Purchase order has already been finalized and cannot be resubmitted."

    if po.replay_detected:
        return True, "Replay was already detected for this purchase order."

    duplicate_executed = PurchaseOrder.query.filter(
        PurchaseOrder.po_number == po.po_number,
        PurchaseOrder.id != po.id,
        PurchaseOrder.final_decision == "Executed"
    ).first()

    if duplicate_executed:
        return True, "A finalized purchase order with the same identifier already exists."

    return False, "No replay detected."


def perform_mutual_auth(sender_username, recipient_username):
    try:
        nonce_a = generate_nonce()
        recipient_signature = sign_nonce(recipient_username, nonce_a)
        recipient_valid = verify_nonce(recipient_username, nonce_a, recipient_signature)

        if not recipient_valid:
            return False, "Recipient failed challenge-response authentication."

        nonce_b = generate_nonce()
        sender_signature = sign_nonce(sender_username, nonce_b)
        sender_valid = verify_nonce(sender_username, nonce_b, sender_signature)

        if not sender_valid:
            return False, "Sender failed challenge-response authentication."

        return True, (
            f"Mutual authentication succeeded between {sender_username} and "
            f"{recipient_username} using RSA nonce challenge-response."
        )
    except Exception as e:
        return False, f"Mutual authentication error: {str(e)}"


def build_purchaser_package(po):
    return {
        "po_number": po.po_number,
        "item_description": po.item_description,
        "quantity": po.quantity,
        "cost": po.cost,
        "justification": po.justification,
        "created_by": po.created_by,
        "created_at": po.created_at_hash_string,
        "po_hash": po.po_hash,
        "purchaser_signature": po.purchaser_signature,
        "purchaser_timestamp": po.purchaser_timestamp
    }


def build_supervisor_package(po):
    return {
        "po_number": po.po_number,
        "item_description": po.item_description,
        "quantity": po.quantity,
        "cost": po.cost,
        "justification": po.justification,
        "created_by": po.created_by,
        "created_at": po.created_at_hash_string,
        "po_hash": po.po_hash,
        "purchaser_signature": po.purchaser_signature,
        "purchaser_timestamp": po.purchaser_timestamp,
        "supervisor_verified": po.supervisor_verified,
        "supervisor_verification_timestamp": po.supervisor_verification_timestamp,
        "supervisor_verification_details": po.supervisor_verification_details,
        "supervisor_signature": po.supervisor_signature,
        "supervisor_timestamp": po.supervisor_timestamp,
        "approved_by": po.approved_by
    }
LOCAL_TZ = ZoneInfo("America/Toronto")


def format_local_timestamp(value):
    if not value:
        return "N/A"

    dt = value

    # If it's a string, parse it
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return value

    # If it's naive, assume UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)

    local_dt = dt.astimezone(LOCAL_TZ)

    # Cross-platform safe formatting
    month = local_dt.strftime("%b")
    day = local_dt.day
    year = local_dt.year
    hour = local_dt.strftime("%I").lstrip("0") or "0"
    minute = local_dt.strftime("%M")
    ampm = local_dt.strftime("%p")

    return f"{month} {day}, {year} {hour}:{minute} {ampm}"


app.jinja_env.filters["localdt"] = format_local_timestamp

@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session["username"] = user.username
            session["role"] = user.role

            log_action(user.username, "Logged in")

            if user.role == "purchaser":
                return redirect(url_for("purchaser_dashboard"))
            elif user.role == "supervisor":
                return redirect(url_for("supervisor_dashboard"))
            elif user.role == "purchasing":
                return redirect(url_for("purchasing_dashboard"))
        else:
            flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username", "Unknown")
    log_action(username, "Logged out")
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


@app.route("/audit")
@login_required()
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    chain_valid, chain_message = verify_audit_chain()
    return render_template("audit.html", logs=logs, chain_valid=chain_valid, chain_message=chain_message)


@app.route("/purchaser", methods=["GET", "POST"])
@login_required(role="purchaser")
def purchaser_dashboard():
    if request.method == "POST":
        item_description = request.form["item_description"].strip()
        quantity = int(request.form["quantity"])
        cost = float(request.form["cost"])
        justification = request.form["justification"].strip()

        po_number = str(uuid.uuid4())[:8].upper()
        created_by = session["username"]
        created_at = datetime.now(UTC)
        created_at_str = created_at.isoformat()

        po_hash = generate_po_hash(
            po_number=po_number,
            item_description=item_description,
            quantity=quantity,
            cost=cost,
            justification=justification,
            created_by=created_by,
            created_at=created_at_str
        )

        po = PurchaseOrder(
            po_number=po_number,
            item_description=item_description,
            quantity=quantity,
            cost=cost,
            justification=justification,
            created_by=created_by,
            created_at=created_at,
            created_at_hash_string=created_at_str,
            status="Created and Hashed",
            po_hash=po_hash
        )

        db.session.add(po)
        db.session.commit()

        log_action(
            actor=session["username"],
            action="Created and Hashed Purchase Order",
            po_number=po_number,
            details=f"Item: {item_description}, Qty: {quantity}, Cost: {cost}, Hash: {po_hash}"
        )

        flash(f"Purchase Order {po_number} created successfully with hash.")

    orders = PurchaseOrder.query.filter_by(created_by=session["username"]).all()
    return render_template("purchaser.html", orders=orders)


@app.route("/sign_po/<int:po_id>", methods=["POST"])
@login_required(role="purchaser")
def sign_purchase_order(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)

    if po.created_by != session["username"]:
        flash("You may only sign your own purchase orders.")
        return redirect(url_for("purchaser_dashboard"))

    if po.purchaser_signature:
        flash("This purchase order has already been signed.")
        return redirect(url_for("purchaser_dashboard"))

    signature_b64 = sign_po_hash(session["username"], po.po_hash)
    timestamp = datetime.now(UTC).isoformat()

    po.purchaser_signature = signature_b64
    po.purchaser_timestamp = timestamp
    po.status = "Signed by Purchaser"

    db.session.commit()

    log_action(
        actor=session["username"],
        action="Signed Purchase Order",
        po_number=po.po_number,
        details=f"PO hash signed at {timestamp}"
    )

    flash(f"Purchase Order {po.po_number} signed successfully.")
    return redirect(url_for("purchaser_dashboard"))


@app.route("/send_to_supervisor/<int:po_id>", methods=["POST"])
@login_required(role="purchaser")
def send_to_supervisor(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)

    if po.created_by != session["username"]:
        flash("You may only send your own purchase orders.")
        return redirect(url_for("purchaser_dashboard"))

    if not po.purchaser_signature:
        flash("Purchase order must be signed before secure transmission.")
        return redirect(url_for("purchaser_dashboard"))

    auth_ok, auth_details = perform_mutual_auth(session["username"], "supervisor1")
    auth_time = datetime.now(UTC).isoformat()

    po.ps_auth_completed = auth_ok
    po.ps_auth_timestamp = auth_time
    po.ps_auth_details = auth_details

    if not auth_ok:
        po.status = "Rejected - Purchaser/Supervisor Mutual Authentication Failed"
        db.session.commit()

        log_action(
            actor=session["username"],
            action="Mutual Authentication Failed",
            po_number=po.po_number,
            details=auth_details
        )

        flash("Mutual authentication with supervisor failed.")
        return redirect(url_for("purchaser_dashboard"))

    payload = build_purchaser_package(po)
    session_key, encrypted_package_b64 = aes_encrypt_payload(payload)
    encrypted_session_key_b64 = rsa_encrypt_session_key("supervisor1", session_key)

    po.encrypted_package_b64 = encrypted_package_b64
    po.encrypted_session_key_b64 = encrypted_session_key_b64
    po.transmission_recipient = "supervisor1"
    po.transmission_stage = "to_supervisor"
    po.transmission_timestamp = datetime.now(UTC).isoformat()
    po.decrypted_by_supervisor = False
    po.status = "Authenticated, Encrypted, and Sent to Supervisor"

    db.session.commit()

    log_action(
        actor=session["username"],
        action="Securely Sent Purchase Order to Supervisor",
        po_number=po.po_number,
        details="Mutual auth passed. PO package encrypted with AES-GCM and session key encrypted with supervisor RSA public key."
    )

    flash(f"Purchase Order {po.po_number} authenticated and securely sent to supervisor.")
    return redirect(url_for("purchaser_dashboard"))


@app.route("/supervisor")
@login_required(role="supervisor")
def supervisor_dashboard():
    orders = PurchaseOrder.query.all()
    return render_template("supervisor.html", orders=orders)


@app.route("/decrypt_from_purchaser/<int:po_id>", methods=["POST"])
@login_required(role="supervisor")
def decrypt_from_purchaser(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)

    if po.transmission_stage != "to_supervisor" or po.transmission_recipient != session["username"]:
        flash("No supervisor transmission available for this purchase order.")
        return redirect(url_for("supervisor_dashboard"))

    if not po.ps_auth_completed:
        flash("Mutual authentication must succeed before supervisor decryption.")
        return redirect(url_for("supervisor_dashboard"))

    if not po.encrypted_package_b64 or not po.encrypted_session_key_b64:
        flash("Encrypted package is missing.")
        return redirect(url_for("supervisor_dashboard"))

    try:
        session_key = rsa_decrypt_session_key(session["username"], po.encrypted_session_key_b64)
        payload = aes_decrypt_payload(session_key, po.encrypted_package_b64)

        if payload["po_hash"] != po.po_hash:
            po.status = "Rejected - Decryption Payload Hash Mismatch"
            db.session.commit()
            flash("Decryption succeeded but payload hash does not match stored hash.")
            return redirect(url_for("supervisor_dashboard"))

        po.decrypted_by_supervisor = True
        po.status = "Decrypted by Supervisor"

        db.session.commit()

        log_action(
            actor=session["username"],
            action="Supervisor Decrypted Purchase Order Transmission",
            po_number=po.po_number,
            details="RSA private key decrypted AES session key and AES-GCM decrypted purchase order package."
        )

        flash(f"Purchase Order {po.po_number} decrypted successfully by supervisor.")
    except Exception as e:
        flash(f"Decryption failed: {str(e)}")

    return redirect(url_for("supervisor_dashboard"))


@app.route("/verify_po/<int:po_id>", methods=["POST"])
@login_required(role="supervisor")
def verify_purchase_order(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)

    if not po.decrypted_by_supervisor:
        flash("Purchase order must be decrypted by supervisor before verification.")
        return redirect(url_for("supervisor_dashboard"))

    if not po.purchaser_signature:
        flash("Cannot verify: purchaser signature is missing.")
        return redirect(url_for("supervisor_dashboard"))

    if po.supervisor_verified:
        flash("This purchase order has already been verified.")
        return redirect(url_for("supervisor_dashboard"))

    purchaser_ts_ok, purchaser_ts_msg = is_timestamp_fresh(po.purchaser_timestamp)
    if not purchaser_ts_ok:
        verification_time = datetime.now(UTC).isoformat()
        po.supervisor_verified = False
        po.supervisor_verification_timestamp = verification_time
        po.supervisor_verification_details = f"Purchaser timestamp invalid: {purchaser_ts_msg}"
        po.status = "Rejected - Invalid Purchaser Timestamp"

        db.session.commit()
        flash(f"Verification failed for PO {po.po_number}: invalid purchaser timestamp.")
        return redirect(url_for("supervisor_dashboard"))

    recomputed_hash = recompute_hash_for_po(po)

    if recomputed_hash != po.po_hash:
        verification_time = datetime.now(UTC).isoformat()
        po.supervisor_verified = False
        po.supervisor_verification_timestamp = verification_time
        po.supervisor_verification_details = "Hash mismatch detected. Purchase order may have been tampered with."
        po.status = "Rejected - Hash Mismatch"

        db.session.commit()
        flash(f"Verification failed for PO {po.po_number}: hash mismatch.")
        return redirect(url_for("supervisor_dashboard"))

    signature_valid = verify_po_signature(
        username=po.created_by,
        po_hash=po.po_hash,
        signature_b64=po.purchaser_signature
    )

    verification_time = datetime.now(UTC).isoformat()

    if signature_valid:
        po.supervisor_verified = True
        po.supervisor_verification_timestamp = verification_time
        po.supervisor_verification_details = "Purchaser signature verified successfully and purchaser timestamp is fresh."
        po.status = "Verified by Supervisor"

        db.session.commit()

        log_action(
            actor=session["username"],
            action="Supervisor Verified Purchase Order",
            po_number=po.po_number,
            details="Purchaser signature, purchaser timestamp, and PO hash verified successfully."
        )

        flash(f"Purchase Order {po.po_number} verified successfully.")
    else:
        po.supervisor_verified = False
        po.supervisor_verification_timestamp = verification_time
        po.supervisor_verification_details = "Invalid purchaser signature."
        po.status = "Rejected - Invalid Signature"

        db.session.commit()

        log_action(
            actor=session["username"],
            action="Supervisor Verification Failed",
            po_number=po.po_number,
            details="Purchaser signature verification failed."
        )

        flash(f"Verification failed for PO {po.po_number}: invalid signature.")

    return redirect(url_for("supervisor_dashboard"))


@app.route("/approve_po/<int:po_id>", methods=["POST"])
@login_required(role="supervisor")
def approve_purchase_order(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)

    if not po.supervisor_verified:
        flash("Purchase order must be verified before approval.")
        return redirect(url_for("supervisor_dashboard"))

    if po.supervisor_signature:
        flash("This purchase order has already been approved and signed by the supervisor.")
        return redirect(url_for("supervisor_dashboard"))

    supervisor_username = session["username"]
    signature_b64 = sign_po_hash(supervisor_username, po.po_hash)
    timestamp = datetime.now(UTC).isoformat()

    po.supervisor_signature = signature_b64
    po.supervisor_timestamp = timestamp
    po.approved_by = supervisor_username
    po.status = "Approved and Signed by Supervisor"

    db.session.commit()

    log_action(
        actor=supervisor_username,
        action="Supervisor Approved and Signed Purchase Order",
        po_number=po.po_number,
        details=f"Supervisor signed PO hash at {timestamp}"
    )

    flash(f"Purchase Order {po.po_number} approved and signed successfully.")
    return redirect(url_for("supervisor_dashboard"))


@app.route("/send_to_purchasing/<int:po_id>", methods=["POST"])
@login_required(role="supervisor")
def send_to_purchasing(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)

    if not po.supervisor_signature:
        flash("Purchase order must be approved and signed before sending to purchasing.")
        return redirect(url_for("supervisor_dashboard"))

    auth_ok, auth_details = perform_mutual_auth(session["username"], "purchasing1")
    auth_time = datetime.now(UTC).isoformat()

    po.sp_auth_completed = auth_ok
    po.sp_auth_timestamp = auth_time
    po.sp_auth_details = auth_details

    if not auth_ok:
        po.status = "Rejected - Supervisor/Purchasing Mutual Authentication Failed"
        db.session.commit()

        log_action(
            actor=session["username"],
            action="Mutual Authentication Failed",
            po_number=po.po_number,
            details=auth_details
        )

        flash("Mutual authentication with purchasing failed.")
        return redirect(url_for("supervisor_dashboard"))

    payload = build_supervisor_package(po)
    session_key, encrypted_package_b64 = aes_encrypt_payload(payload)
    encrypted_session_key_b64 = rsa_encrypt_session_key("purchasing1", session_key)

    po.encrypted_package_b64 = encrypted_package_b64
    po.encrypted_session_key_b64 = encrypted_session_key_b64
    po.transmission_recipient = "purchasing1"
    po.transmission_stage = "to_purchasing"
    po.transmission_timestamp = datetime.now(UTC).isoformat()
    po.decrypted_by_purchasing = False
    po.status = "Authenticated, Encrypted, and Sent to Purchasing"

    db.session.commit()

    log_action(
        actor=session["username"],
        action="Securely Sent Purchase Order to Purchasing",
        po_number=po.po_number,
        details="Mutual auth passed. Approved package encrypted with AES-GCM and session key encrypted with purchasing RSA public key."
    )

    flash(f"Purchase Order {po.po_number} authenticated and securely sent to purchasing.")
    return redirect(url_for("supervisor_dashboard"))


@app.route("/purchasing")
@login_required(role="purchasing")
def purchasing_dashboard():
    orders = PurchaseOrder.query.all()
    return render_template("purchasing.html", orders=orders)


@app.route("/decrypt_from_supervisor/<int:po_id>", methods=["POST"])
@login_required(role="purchasing")
def decrypt_from_supervisor(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)

    if po.transmission_stage != "to_purchasing" or po.transmission_recipient != session["username"]:
        flash("No purchasing transmission available for this purchase order.")
        return redirect(url_for("purchasing_dashboard"))

    if not po.sp_auth_completed:
        flash("Mutual authentication must succeed before purchasing decryption.")
        return redirect(url_for("purchasing_dashboard"))

    if not po.encrypted_package_b64 or not po.encrypted_session_key_b64:
        flash("Encrypted package is missing.")
        return redirect(url_for("purchasing_dashboard"))

    try:
        session_key = rsa_decrypt_session_key(session["username"], po.encrypted_session_key_b64)
        payload = aes_decrypt_payload(session_key, po.encrypted_package_b64)

        if payload["po_hash"] != po.po_hash:
            po.status = "Rejected - Decryption Payload Hash Mismatch"
            db.session.commit()
            flash("Decryption succeeded but payload hash does not match stored hash.")
            return redirect(url_for("purchasing_dashboard"))

        po.decrypted_by_purchasing = True
        po.status = "Decrypted by Purchasing"

        db.session.commit()

        log_action(
            actor=session["username"],
            action="Purchasing Decrypted Purchase Order Transmission",
            po_number=po.po_number,
            details="RSA private key decrypted AES session key and AES-GCM decrypted approved package."
        )

        flash(f"Purchase Order {po.po_number} decrypted successfully by purchasing.")
    except Exception as e:
        flash(f"Decryption failed: {str(e)}")

    return redirect(url_for("purchasing_dashboard"))


@app.route("/finalize_po/<int:po_id>", methods=["POST"])
@login_required(role="purchasing")
def finalize_purchase_order(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)

    if not po.decrypted_by_purchasing:
        flash("Purchase order must be decrypted by purchasing before final verification.")
        return redirect(url_for("purchasing_dashboard"))

    if not po.ps_auth_completed:
        flash("Purchaser-to-supervisor mutual authentication was not completed.")
        return redirect(url_for("purchasing_dashboard"))

    if not po.sp_auth_completed:
        flash("Supervisor-to-purchasing mutual authentication was not completed.")
        return redirect(url_for("purchasing_dashboard"))

    replay_found, replay_message = detect_replay(po)
    replay_check_time = datetime.now(UTC).isoformat()

    po.replay_checked = True
    po.replay_check_timestamp = replay_check_time

    if replay_found:
        po.replay_detected = True
        po.replay_details = replay_message
        po.purchasing_verified = False
        po.purchasing_verification_timestamp = replay_check_time
        po.purchasing_verification_details = replay_message
        po.final_decision = "Rejected"
        po.status = "Rejected by Purchasing - Replay Detected"

        db.session.commit()

        log_action(
            actor=session["username"],
            action="Purchasing Rejected Purchase Order",
            po_number=po.po_number,
            details=f"Replay detected: {replay_message}"
        )

        flash(f"PO {po.po_number} rejected: replay detected.")
        return redirect(url_for("purchasing_dashboard"))

    po.replay_detected = False
    po.replay_details = "No replay detected."

    purchaser_ts_ok, purchaser_ts_msg = is_timestamp_fresh(po.purchaser_timestamp)
    supervisor_ts_ok, supervisor_ts_msg = is_timestamp_fresh(po.supervisor_timestamp)

    if not purchaser_ts_ok:
        po.purchasing_verified = False
        po.purchasing_verification_timestamp = datetime.now(UTC).isoformat()
        po.purchasing_verification_details = f"Purchaser timestamp invalid: {purchaser_ts_msg}"
        po.final_decision = "Rejected"
        po.status = "Rejected by Purchasing - Invalid Purchaser Timestamp"
        db.session.commit()
        flash(f"PO {po.po_number} rejected: purchaser timestamp invalid.")
        return redirect(url_for("purchasing_dashboard"))

    if not supervisor_ts_ok:
        po.purchasing_verified = False
        po.purchasing_verification_timestamp = datetime.now(UTC).isoformat()
        po.purchasing_verification_details = f"Supervisor timestamp invalid: {supervisor_ts_msg}"
        po.final_decision = "Rejected"
        po.status = "Rejected by Purchasing - Invalid Supervisor Timestamp"
        db.session.commit()
        flash(f"PO {po.po_number} rejected: supervisor timestamp invalid.")
        return redirect(url_for("purchasing_dashboard"))

    recomputed_hash = recompute_hash_for_po(po)
    if recomputed_hash != po.po_hash:
        po.purchasing_verified = False
        po.purchasing_verification_timestamp = datetime.now(UTC).isoformat()
        po.purchasing_verification_details = "Hash mismatch detected during final verification."
        po.final_decision = "Rejected"
        po.status = "Rejected by Purchasing - Hash Mismatch"
        db.session.commit()
        flash(f"PO {po.po_number} rejected: hash mismatch.")
        return redirect(url_for("purchasing_dashboard"))

    purchaser_signature_valid = verify_po_signature(po.created_by, po.po_hash, po.purchaser_signature)
    supervisor_signature_valid = verify_po_signature(po.approved_by, po.po_hash, po.supervisor_signature)

    final_time = datetime.now(UTC).isoformat()

    if purchaser_signature_valid and supervisor_signature_valid:
        po.purchasing_verified = True
        po.purchasing_verification_timestamp = final_time
        po.purchasing_verification_details = (
            "Mutual auth passed, replay check passed, timestamps are valid, hash integrity confirmed, "
            "and both signatures verified successfully. Purchase order executed."
        )
        po.final_decision = "Executed"
        po.status = "Executed by Purchasing"

        db.session.commit()

        log_action(
            actor=session["username"],
            action="Purchasing Executed Purchase Order",
            po_number=po.po_number,
            details="Final verification passed including mutual authentication, replay protection, timestamp validation, and hybrid-encrypted transmission."
        )

        flash(f"PO {po.po_number} verified and executed successfully.")
    else:
        po.purchasing_verified = False
        po.purchasing_verification_timestamp = final_time
        po.purchasing_verification_details = "One or both signatures are invalid during final verification."
        po.final_decision = "Rejected"
        po.status = "Rejected by Purchasing - Invalid Signature"

        db.session.commit()

        log_action(
            actor=session["username"],
            action="Purchasing Rejected Purchase Order",
            po_number=po.po_number,
            details="One or both signatures invalid during final verification."
        )

        flash(f"PO {po.po_number} rejected: invalid signature detected.")

    return redirect(url_for("purchasing_dashboard"))


if __name__ == "__main__":
    app.run(debug=True)