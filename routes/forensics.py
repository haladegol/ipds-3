"""PCAP Forensic Lab: Reconstructs and inspects simulated traffic streams."""
import json
import random
from datetime import datetime, timedelta
from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user
from models.database import AttackLog

forensics_bp = Blueprint("forensics", __name__, url_prefix="/forensics")

@forensics_bp.route("/")
@login_required
def index():
    logs = AttackLog.query.filter_by(user_id=current_user.id).order_by(AttackLog.timestamp.desc()).all()
    return render_template("forensics/index.html", logs=logs)

@forensics_bp.route("/view/<int:log_id>")
@login_required
def view_pcap(log_id):
    log = AttackLog.query.filter_by(id=log_id, user_id=current_user.id).first_or_404()
    
    # Generate simulated packet stream based on attack category
    packets = generate_mock_packets(log)
    
    return render_template("forensics/view.html", log=log, packets=packets)

def generate_mock_packets(log):
    """Generates a sequence of high-fidelity mock packets based on the attack type."""
    src_ip = log.source_ip or "192.168.1.100"
    dst_ip = log.dest_ip or "10.0.0.50"
    src_port = log.source_port or random.randint(49152, 65535)
    dst_port = log.dest_port or (80 if "WEB" in (log.attack_category or "").upper() else 443)
    
    category = (log.attack_category or "Unknown").upper()
    packets = []
    base_time = log.timestamp - timedelta(seconds=2)
    
    # TCP Handshake Simulation
    packets.append({"time": (base_time + timedelta(milliseconds=10)).isoformat(), "src": src_ip, "dst": dst_ip, "proto": "TCP", "len": 60, "info": f"[{src_port} -> {dst_port}] [SYN] Seq=0 Win=64240"})
    packets.append({"time": (base_time + timedelta(milliseconds=25)).isoformat(), "src": dst_ip, "dst": src_ip, "proto": "TCP", "len": 60, "info": f"[{dst_port} -> {src_port}] [SYN, ACK] Seq=0 Ack=1 Win=64240"})
    packets.append({"time": (base_time + timedelta(milliseconds=35)).isoformat(), "src": src_ip, "dst": dst_ip, "proto": "TCP", "len": 54, "info": f"[{src_port} -> {dst_port}] [ACK] Seq=1 Ack=1 Win=64240"})

    # Attack Payload Simulation
    if "WEB" in category or "SQL" in category:
        payload = "GET /admin/login.php?user=' OR 1=1-- HTTP/1.1" if "SQL" in category else "GET /etc/passwd HTTP/1.1"
        packets.append({"time": (base_time + timedelta(milliseconds=150)).isoformat(), "src": src_ip, "dst": dst_ip, "proto": "HTTP", "len": 450, "info": payload, "payload": payload.encode().hex()})
        packets.append({"time": (base_time + timedelta(milliseconds=200)).isoformat(), "src": dst_ip, "dst": src_ip, "proto": "HTTP", "len": 1200, "info": "HTTP/1.1 200 OK (Exploit Potential)", "payload": "3c68746d6c3e726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f62617368" })
    elif "DOS" in category or "DDOS" in category:
        for i in range(5):
            packets.append({"time": (base_time + timedelta(milliseconds=100 + i*10)).isoformat(), "src": f"VAR_SRC_{i}", "dst": dst_ip, "proto": "TCP", "len": 64, "info": f"[ATTACK] SYN Flood Chunk {i+1}"})
    elif "BRUTE" in category:
        for i in range(3):
            packets.append({"time": (base_time + timedelta(milliseconds=200 + i*500)).isoformat(), "src": src_ip, "dst": dst_ip, "proto": "SSH", "len": 120, "info": f"Encrypted Password Attempt (Fail {i+1})"})
    else:
        packets.append({"time": (base_time + timedelta(milliseconds=300)).isoformat(), "src": src_ip, "dst": dst_ip, "proto": "DATA", "len": 800, "info": f"Suspicious Fragment: {log.specific_attack}", "payload": "00ffdeadaffe00112233445566778899aabbccddeeff" })

    return packets
