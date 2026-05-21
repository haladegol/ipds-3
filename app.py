"""HADES Final 2 — Flask Application."""
import os
from flask import Flask
from flask_login import LoginManager
from config import Config
from models.database import db, User


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure directories exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["TRAINED_MODELS_FOLDER"], exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    # SQLite Concurrency Optimization
    with app.app_context():
        from sqlalchemy import event
        @event.listens_for(db.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=30000") # 30s timeout
            cursor.close()

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except Exception:
            return None

    # Register blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.analysis import analysis_bp
    from routes.api import api_bp
    from routes.admin import admin_bp
    from routes.threats import threats_bp
    from routes.network import network_bp
    from routes.reports import reports_bp
    from routes.database import database_bp
    from routes.incidents import incidents_bp
    from routes.model_insights import model_insights_bp
    from routes.live_monitor import live_monitor_bp
    from routes.response import response_bp
    from routes.timeline_route import timeline_bp
    from routes.settings import settings_bp
    from routes.simulation import simulation_bp
    from routes.chatbot import chatbot_bp
    from routes.account import account_bp
    from routes.hybrid import hybrid_bp
    from routes.forensics import forensics_bp
    from routes.vulnerability import vulnerability_bp
    from routes.hunting import hunting_bp
    from routes.signatures import signatures_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(database_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(model_insights_bp)
    app.register_blueprint(live_monitor_bp)
    app.register_blueprint(response_bp)
    app.register_blueprint(timeline_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(simulation_bp)
    app.register_blueprint(chatbot_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(hybrid_bp)
    app.register_blueprint(forensics_bp)
    app.register_blueprint(vulnerability_bp)
    app.register_blueprint(hunting_bp)
    app.register_blueprint(signatures_bp)

    # Create tables + auto-migrate
    with app.app_context():
        db.create_all()
        # Auto-add columns if missing (migrations)
        from sqlalchemy import text
        migrations = [
            ("users", "is_admin", "ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0"),
            ("attack_logs", "source_ip", "ALTER TABLE attack_logs ADD COLUMN source_ip VARCHAR(45)"),
            ("attack_logs", "dest_ip", "ALTER TABLE attack_logs ADD COLUMN dest_ip VARCHAR(45)"),
            ("attack_logs", "source_port", "ALTER TABLE attack_logs ADD COLUMN source_port INTEGER"),
            ("attack_logs", "dest_port", "ALTER TABLE attack_logs ADD COLUMN dest_port INTEGER"),
            ("attack_logs", "is_ips_action", "ALTER TABLE attack_logs ADD COLUMN is_ips_action BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_mode_enabled", "ALTER TABLE alert_configs ADD COLUMN ips_mode_enabled BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_inline_filtering", "ALTER TABLE alert_configs ADD COLUMN ips_inline_filtering BOOLEAN DEFAULT 1"),
            ("alert_configs", "ips_rst_injection", "ALTER TABLE alert_configs ADD COLUMN ips_rst_injection BOOLEAN DEFAULT 1"),
            ("alert_configs", "ips_dynamic_shunning", "ALTER TABLE alert_configs ADD COLUMN ips_dynamic_shunning BOOLEAN DEFAULT 1"),
            ("alert_configs", "ips_rate_limiting", "ALTER TABLE alert_configs ADD COLUMN ips_rate_limiting BOOLEAN DEFAULT 1"),
            ("alert_configs", "ips_protocol_normalization", "ALTER TABLE alert_configs ADD COLUMN ips_protocol_normalization BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_payload_sanitization", "ALTER TABLE alert_configs ADD COLUMN ips_payload_sanitization BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_signature_matching", "ALTER TABLE alert_configs ADD COLUMN ips_signature_matching BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_anomaly_detection", "ALTER TABLE alert_configs ADD COLUMN ips_anomaly_detection BOOLEAN DEFAULT 1"),
            ("alert_configs", "ips_virtual_patching", "ALTER TABLE alert_configs ADD COLUMN ips_virtual_patching BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_vlan_steering", "ALTER TABLE alert_configs ADD COLUMN ips_vlan_steering BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_bypass_mode", "ALTER TABLE alert_configs ADD COLUMN ips_bypass_mode BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_json_logging", "ALTER TABLE alert_configs ADD COLUMN ips_json_logging BOOLEAN DEFAULT 1"),
            ("alert_configs", "ips_reputation_check", "ALTER TABLE alert_configs ADD COLUMN ips_reputation_check BOOLEAN DEFAULT 1"),
            ("alert_configs", "ips_protocol_analysis", "ALTER TABLE alert_configs ADD COLUMN ips_protocol_analysis BOOLEAN DEFAULT 1"),
            ("alert_configs", "ips_stream_reassembly", "ALTER TABLE alert_configs ADD COLUMN ips_stream_reassembly BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_file_hashing", "ALTER TABLE alert_configs ADD COLUMN ips_file_hashing BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_geoip_filtering", "ALTER TABLE alert_configs ADD COLUMN ips_geoip_filtering BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_honeypot_routing", "ALTER TABLE alert_configs ADD COLUMN ips_honeypot_routing BOOLEAN DEFAULT 0"),
            ("alert_configs", "ips_ddos_protection", "ALTER TABLE alert_configs ADD COLUMN ips_ddos_protection BOOLEAN DEFAULT 0"),
            ("attack_logs", "mitre_info", "ALTER TABLE attack_logs ADD COLUMN mitre_info VARCHAR(100)"),
            ("signatures", "mitre_id", "ALTER TABLE signatures ADD COLUMN mitre_id VARCHAR(20)"),
            ("signatures", "mitre_tactic", "ALTER TABLE signatures ADD COLUMN mitre_tactic VARCHAR(50)"),
            ("analysis_sessions", "filepath", "ALTER TABLE analysis_sessions ADD COLUMN filepath VARCHAR(512)"),
        ]
        for table, col, sql in migrations:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text(f"SELECT {col} FROM {table} LIMIT 1"))
            except Exception:
                with db.engine.connect() as conn:
                    conn.execute(text(sql))
                    conn.commit()
                    print(f"[HADES] Migrated: added {col} to {table}")

        # Seed Signatures if empty
        from models.database import Signature
        if Signature.query.count() <= 5: # Re-seed if only initial ones present
            Signature.query.delete() # Clear old ones to update with MITRE
            seeds = [
                # Initial access / Web Exploit
                Signature(sid="HADES-SIG-001", name="Directory Traversal", pattern=r"\.\.\/|\.\.\\", severity="high", 
                          mitre_id="T1083", mitre_tactic="Discovery", description="Detects attempts to access parent directories."),
                Signature(sid="HADES-SIG-002", name="SQL Injection Pattern", pattern=r"(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*FROM", severity="critical", 
                          mitre_id="T1190", mitre_tactic="Initial Access", description="Detects standard SQL injection keywords."),
                Signature(sid="HADES-SIG-003", name="XSS Script Tag", pattern=r"<script.*?>.*?<\/script>", severity="high", 
                          mitre_id="T1190", mitre_tactic="Initial Access", description="Detects injection of script tags."),
                Signature(sid="HADES-SIG-004", name="Remote Command Execution", pattern=r"(bash|sh|cmd\.exe|powershell)\s+.*", severity="critical", 
                          mitre_id="T1059", mitre_tactic="Execution", description="Detects shell command execution attempts."),
                Signature(sid="HADES-SIG-005", name="Sensitive File Access", pattern=r"\/etc\/passwd|\/etc\/shadow|c:\\windows\\system32\\config", severity="critical", 
                          mitre_id="T1552", mitre_tactic="Credential Access", description="Detects access to critical system files."),
                
                # New Advanced Patterns
                Signature(sid="HADES-SIG-006", name="Log4Shell Exploit", pattern=r"\$\{jndi:(ldap|rmi|dns|nis|iiop|corba|nds|http):", severity="critical", 
                          mitre_id="T1190", mitre_tactic="Initial Access", description="Detects JNDI lookup patterns used in Log4j exploits."),
                Signature(sid="HADES-SIG-007", name="PHP Web Shell (eval)", pattern=r"eval\s*\(\s*base64_decode", severity="critical", 
                          mitre_id="T1505.003", mitre_tactic="Persistence", description="Detects common PHP web shell obfuscation."),
                Signature(sid="HADES-SIG-008", name="Reverse Shell Payload", pattern=r"python -c 'import socket,os,pty;s=socket\.socket", severity="critical", 
                          mitre_id="T1059.006", mitre_tactic="Execution", description="Detects common Python reverse shell one-liners."),
                Signature(sid="HADES-SIG-009", name="SSH Brute Force Attempt", pattern=r"Failed password for invalid user", severity="medium", 
                          mitre_id="T1110.001", mitre_tactic="Credential Access", description="Detects SSH authentication failure patterns."),
                Signature(sid="HADES-SIG-010", name="Data Exfiltration (ICMP)", pattern=r"I C M P .* length [5-9]\d{2}", severity="high", 
                          mitre_id="T1048", mitre_tactic="Exfiltration", description="Detects oversized ICMP packets potentially carrying data."),
                Signature(sid="HADES-SIG-011", name="Port Scan Header (Nmap)", pattern=r"User-Agent: Nmap Scripting Engine", severity="medium", 
                          mitre_id="T1595.001", mitre_tactic="Reconnaissance", description="Detects default Nmap scanning headers."),
                Signature(sid="HADES-SIG-012", name="Cobalt Strike Beacon", pattern=r"Cookie: .* __cf_bm=", severity="high", 
                          mitre_id="T1071.001", mitre_tactic="Command and Control", description="Detects common Cobalt Strike malleable C2 traffic."),
            ]
            db.session.add_all(seeds)
            db.session.commit()
            print("[HADES] Expanded and Mapped core IPS signatures to MITRE ATT&CK.")


    @app.template_filter('cvss')
    def cvss_filter(severity):
        cvss_map = {'info': '0.0', 'low': '3.9', 'medium': '6.9', 'high': '8.9', 'critical': '10.0'}
        return cvss_map.get(str(severity).lower(), '0.0')

    @app.template_filter('format_number')
    def format_number_filter(value):
        """Format a number with comma separators: 15142151 → 15,142,151"""
        try:
            return f"{int(value):,}"
        except (ValueError, TypeError):
            return str(value)

    @app.template_filter('fromjson')
    def fromjson_filter(value):
        import json
        try:
            return json.loads(value) if value else {}
        except Exception:
            return {}

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)
