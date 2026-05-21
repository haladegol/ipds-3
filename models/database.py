from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from config import Config
from sqlalchemy_utils import EncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(EncryptedType(db.String(120), Config.DB_ENCRYPTION_KEY, AesEngine, 'pkcs5'), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    attack_logs = db.relationship("AttackLog", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class AttackLog(db.Model):
    __tablename__ = "attack_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

    # Stage 1 results
    total_flows = db.Column(db.Integer, default=0)
    normal_count = db.Column(db.Integer, default=0)
    anomaly_count = db.Column(db.Integer, default=0)

    # Stage 2 results
    attack_category = db.Column(db.String(50), nullable=True)
    category_confidence = db.Column(db.Float, nullable=True)
    detected_by = db.Column(db.String(20), nullable=True)

    # Stage 3 results
    specific_attack = db.Column(db.String(100), nullable=True)
    specific_confidence = db.Column(db.Float, nullable=True)

    # Summary
    severity = db.Column(db.String(20), default="low")
    mitre_info = db.Column(db.String(100), nullable=True) # e.g. T1190 - Initial Access
    results_json = db.Column(db.Text, nullable=True)
    is_ips_action = db.Column(db.Boolean, default=False)  # True if IPS mitigation was executed

    # Network metadata (for incident details)
    source_ip = db.Column(EncryptedType(db.String(45), Config.DB_ENCRYPTION_KEY, AesEngine, 'pkcs5'), nullable=True)
    dest_ip = db.Column(EncryptedType(db.String(45), Config.DB_ENCRYPTION_KEY, AesEngine, 'pkcs5'), nullable=True)
    source_port = db.Column(db.Integer, nullable=True)
    dest_port = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f"<AttackLog {self.filename} - {self.attack_category}>"


class SystemLog(db.Model):
    __tablename__ = "system_logs"
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), default="INFO")
    event = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f"<SystemLog {self.event} - {self.level}>"


class AnalysisSession(db.Model):
    __tablename__ = "analysis_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20), default="pending")
    filepath = db.Column(db.String(512), nullable=True)  # Absolute path to uploaded CSV
    total_flows = db.Column(db.Integer, default=0)
    normal_count = db.Column(db.Integer, default=0)
    anomaly_count = db.Column(db.Integer, default=0)
    results_json = db.Column(db.Text, nullable=True)

    user = db.relationship("User", backref="sessions")

    def __repr__(self):
        return f"<AnalysisSession {self.filename} - {self.status}>"


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(EncryptedType(db.String(45), Config.DB_ENCRYPTION_KEY, AesEngine, 'pkcs5'), nullable=False)
    reason = db.Column(db.String(256), nullable=True)
    blocked_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    blocked_at = db.Column(db.DateTime, default=datetime.now)
    is_active = db.Column(db.Boolean, default=True)

    user = db.relationship("User", backref="blocked_ips")

    def __repr__(self):
        return f"<BlockedIP {self.ip_address}>"



class AlertConfig(db.Model):
    __tablename__ = "alert_configs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)
    severity_threshold = db.Column(db.String(20), default="low")  # min severity to alert
    items_per_page = db.Column(db.Integer, default=20)
    auto_block_critical = db.Column(db.Boolean, default=False)
    ips_mode_enabled = db.Column(db.Boolean, default=False)  # Master toggle for Active vs Passive
    email_notifications = db.Column(db.Boolean, default=False)
    
    # Advanced IPS Features (Tier 2)
    ips_inline_filtering = db.Column(db.Boolean, default=True)
    ips_rst_injection = db.Column(db.Boolean, default=True)
    ips_dynamic_shunning = db.Column(db.Boolean, default=True)
    ips_rate_limiting = db.Column(db.Boolean, default=True)
    ips_protocol_normalization = db.Column(db.Boolean, default=True)
    ips_payload_sanitization = db.Column(db.Boolean, default=False)
    ips_signature_matching = db.Column(db.Boolean, default=True)
    ips_anomaly_detection = db.Column(db.Boolean, default=True)
    ips_virtual_patching = db.Column(db.Boolean, default=False)
    ips_vlan_steering = db.Column(db.Boolean, default=False)
    
    # Tier 3 & Operational
    ips_bypass_mode = db.Column(db.Boolean, default=False)  # Fail-Open Switch
    ips_json_logging = db.Column(db.Boolean, default=True)
    ips_reputation_check = db.Column(db.Boolean, default=True)
    ips_protocol_analysis = db.Column(db.Boolean, default=True)
    ips_stream_reassembly = db.Column(db.Boolean, default=False)
    ips_file_hashing = db.Column(db.Boolean, default=False)
    
    # New Advanced Security Functions
    ips_geoip_filtering = db.Column(db.Boolean, default=False)
    ips_honeypot_routing = db.Column(db.Boolean, default=False)
    ips_ddos_protection = db.Column(db.Boolean, default=False)

    user = db.relationship("User", backref="alert_config", uselist=False)

    def __repr__(self):
        return f"<AlertConfig user={self.user_id}>"


class SimulationResult(db.Model):
    __tablename__ = "simulation_results"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    attack_type = db.Column(db.String(50), nullable=False)
    flow_count = db.Column(db.Integer, default=100)
    detected_count = db.Column(db.Integer, default=0)
    detection_rate = db.Column(db.Float, default=0.0)
    avg_confidence = db.Column(db.Float, default=0.0)
    results_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship("User", backref="simulations")

    def __repr__(self):
        return f"<SimulationResult {self.attack_type} - {self.detection_rate}%>"


class Signature(db.Model):
    __tablename__ = "signatures"
    id = db.Column(db.Integer, primary_key=True)
    sid = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    pattern = db.Column(db.String(500), nullable=False)  # PCRE / Regex
    severity = db.Column(db.String(20), default="medium")
    mitre_id = db.Column(db.String(20), nullable=True)    # e.g. T1190
    mitre_tactic = db.Column(db.String(50), nullable=True) # e.g. Initial Access
    is_active = db.Column(db.Boolean, default=True)
    description = db.Column(db.String(256), nullable=True)
    hit_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f"<Signature {self.sid} - {self.name}>"
