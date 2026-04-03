from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # purchaser, supervisor, purchasing


class PurchaseOrder(db.Model):
    __tablename__ = "purchase_orders"

    id = db.Column(db.Integer, primary_key=True)
    po_number = db.Column(db.String(100), unique=True, nullable=False)
    item_description = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    cost = db.Column(db.Float, nullable=False)
    justification = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Strongest hash fix: store the exact string used during original hashing
    created_at_hash_string = db.Column(db.String(100), nullable=False)

    status = db.Column(db.String(100), default="Created")
    po_hash = db.Column(db.String(64), nullable=True)

    purchaser_signature = db.Column(db.Text, nullable=True)
    purchaser_timestamp = db.Column(db.String(100), nullable=True)

    supervisor_verified = db.Column(db.Boolean, default=False)
    supervisor_verification_timestamp = db.Column(db.String(100), nullable=True)
    supervisor_verification_details = db.Column(db.Text, nullable=True)

    supervisor_signature = db.Column(db.Text, nullable=True)
    supervisor_timestamp = db.Column(db.String(100), nullable=True)
    approved_by = db.Column(db.String(80), nullable=True)

    purchasing_verified = db.Column(db.Boolean, default=False)
    purchasing_verification_timestamp = db.Column(db.String(100), nullable=True)
    purchasing_verification_details = db.Column(db.Text, nullable=True)
    final_decision = db.Column(db.String(50), nullable=True)  # Executed or Rejected

    replay_checked = db.Column(db.Boolean, default=False)
    replay_detected = db.Column(db.Boolean, default=False)
    replay_check_timestamp = db.Column(db.String(100), nullable=True)
    replay_details = db.Column(db.Text, nullable=True)

    # Hybrid encryption transmission fields
    encrypted_package_b64 = db.Column(db.Text, nullable=True)
    encrypted_session_key_b64 = db.Column(db.Text, nullable=True)
    transmission_recipient = db.Column(db.String(80), nullable=True)
    transmission_stage = db.Column(db.String(50), nullable=True)  # to_supervisor / to_purchasing
    transmission_timestamp = db.Column(db.String(100), nullable=True)

    decrypted_by_supervisor = db.Column(db.Boolean, default=False)
    decrypted_by_purchasing = db.Column(db.Boolean, default=False)

    # Mutual authentication fields
    ps_auth_completed = db.Column(db.Boolean, default=False)
    ps_auth_timestamp = db.Column(db.String(100), nullable=True)
    ps_auth_details = db.Column(db.Text, nullable=True)

    sp_auth_completed = db.Column(db.Boolean, default=False)
    sp_auth_timestamp = db.Column(db.String(100), nullable=True)
    sp_auth_details = db.Column(db.Text, nullable=True)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    po_number = db.Column(db.String(100), nullable=True)
    actor = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    timestamp_hash_string = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)

    previous_hash = db.Column(db.String(64), nullable=True)
    current_hash = db.Column(db.String(64), nullable=True)