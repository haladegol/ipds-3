from datetime import datetime, timedelta
import re
import random
from flask import Blueprint, jsonify, request, session
from flask_login import login_required, current_user
from models.database import db, AttackLog, SystemLog, BlockedIP
from sqlalchemy import func, desc

chatbot_bp = Blueprint("chatbot", __name__, url_prefix="/chatbot")

# ═══════════════════════════════════════════════════════════════
# HADES PERSONA
# ═══════════════════════════════════════════════════════════════
HADES_PERSONA = {
    "name": "HADES",
    "title": "Hierarchical Anomaly Detection & Elimination System",
    "greeting": "I am HADES, your AI-powered network guardian. How can I assist you in securing your infrastructure today?",
    "personality": "vigilant, precise, protective, professional, helpful, encyclopedic",
}

# Generic noise words
STOP_WORDS = {
    "what", "is", "a", "the", "how", "do", "you", "does", "are", "it", "to", "for", 
    "of", "in", "with", "on", "at", "by", "from", "up", "about", "can", "me", "give", 
    "show", "tell", "explain", "describe", "why", "who", "where", "which"
}

NEGATION_WORDS = {"not", "except", "without", "dont", "don't", "no"}

# ═══════════════════════════════════════════════════════════════
# KNOWLEDGE BASE — DYNAMIC & COMPREHENSIVE
# ═══════════════════════════════════════════════════════════════
KNOWLEDGE_BASE = {
    # --- CORE ATTACK FAMILIES ---
    "dos ddos": {
        "answer": "**DoS (Denial of Service)** and **DDoS (Distributed Denial of Service)** are attacks aimed at making a service unavailable by overwhelming it with traffic.\n\n### The HADES Defense:\n- **Volumetric Detection:** Flagging abnormal traffic spikes (Stage 1).\n- **Protocol Analysis:** Distinguishing between valid TCP/UDP flows and malicious floods (Stage 2).\n- **Mitigation:** Recommending **Traffic Scrubbing** or **Rate Limiting** to keep legitimate users connected.",
        "tags": ["dos", "ddos", "flood", "denial", "service", "traffic", "overwhelm"],
    },
    "botnet": {
        "answer": "**Botnets** are networks of 'zombie' computers controlled by a central Command & Control (C2) server. They are often used to launch massive DDoS attacks or spread malware.\n\n### Detection in HADES:\nWe monitor for **'Heartbeat'** patterns—periodic, small packets used by the bot to check in with the C2 server. By identifying these low-volume but repetitive flows, we can neutralize the bot before it is activated.",
        "tags": ["botnet", "zombie", "c2", "command", "control", "heartbeat"],
    },
    "brute force": {
        "answer": "**Brute Force** involves automated trial-and-error to guess passwords or keys. Common targets include SSH, FTP, and web login portals.\n\n### Prevention:\n- **Rate Limiting:** Disallowing more than X attempts per minute.\n- **MFA:** Multi-Factor Authentication effectively kills brute force success.\n- **HADES flagging:** We detect the high-frequency 'Access-Denied' flow patterns associated with scanners.",
        "tags": ["brute", "force", "password", "credential", "ssh", "login"],
    },
    "infiltration": {
        "answer": "**Infiltration** occurs when an attacker gains internal access to a network, often via a vulnerable application or a compromised user device.\n\n### Lateral Movement:\nOnce inside, attackers move 'East-West' across the network. HADES is uniquely positioned to detect this internal movement by analyzing traffic behavior *inside* the perimeter, where traditional firewalls are often blind.",
        "tags": ["infiltration", "access", "internal", "lateral", "movement", "compromise"],
    },

    # --- MACHINE LEARNING & PREPROCESSING ---
    "preprocessing": {
        "answer": "**Preprocessing** is the 'cleaning' phase of our AI pipeline. Raw network flows are messy, often containing null values or infinity errors that can crash deep learning models.\n\n### The HADES Strategy:\n- **Cleaning:** Removing noise and handling missing data.\n- **Engineering:** Deriving **78 metadata features** (Inter-arrival times, distributions) from raw traffic.\n- **Scaling:** Normalizing values to a 0-1 range to ensure mathematical objectivity.",
        "tags": ["process", "cleaning", "feature", "engineering", "raw", "data", "science"],
    },
    "feature engineering": {
        "answer": "**Feature Engineering** transforms raw data into inputs that the Random Forest algorithm can understand. \n\n### Why it Matters:\nWe don't just look at 'Bytes'. We look at the **Entropy** of the payload, the **Variance** of packet sizes, and the **IAT (Inter-Arrival Time)**. These 78 features are the DNA of a flow, allowing us to spot anomalies with 98.5% precision.",
        "tags": ["features", "metrics", "78", "flows", "extraction", "science"],
    },
    "normalization": {
        "answer": "**Normalization** (or Scaling) ensures all traffic metrics are compared fairly. If one feature has a range of 0-65535 (Ports) and another has a range of 0.001-0.005 (Time), the AI might ignore the time variance. We scale everything to [0,1] to maintain pure objectivity.",
        "tags": ["scaling", "minmax", "zscore", "fairness", "math", "model"],
    },

    # --- INFRASTRUCTURE & DOMAINS ---
    "network": {
        "answer": "A **Network** is an infrastructure of connected nodes. HADES operates primarily at the **Network Layer (L3)** and **Transport Layer (L4)**, analyzing the behavior of the flow rather than the individual packets.",
        "tags": ["nodes", "osi", "link", "tcp", "ip", "infrastructure", "basic"],
    },
    "cyber security": {
        "answer": "**Cybersecurity** is the comprehensive practice of protecting digital assets. It encompasses **Network**, **Endpoint**, **Cloud**, and **Application** security domains.",
        "tags": ["security", "protection", "defense", "basic", "fundamental"],
    },
    "network security": {
        "answer": "**Network Security** is the strategy of protecting network infrastructure. It combines policy, software (like HADES), and hardware (Firewalls) into a unified defense posture.",
        "tags": ["strategy", "architecture", "policy", "infrastructure"],
    },

    # --- HADES internals ---
    "what is hades": {
        "answer": "**HADES** is a 3-stage AI guardian. It uses **Random Forest** ensembles to identify threats in real-time. Stage 1 detects anomalies, Stage 2 categorizes them, and Stage 3 identifies the specific exploit.",
        "tags": ["hades", "about", "pipeline", "system", "who"],
    },
    "hades api": {
        "answer": "HADES exposes specialized APIs for automation: `/analysis/upload` for batch processing and `/response/tactical-action` for real-time mitigation.",
        "tags": ["api", "integration", "automation", "endpoint", "rest"],
    },
}

STATUS_QUERIES = ["status", "stats", "how many", "threat count", "alerts today", "system status", "overview", "recommend", "summary", "happened"]

def _find_best_match(user_msg):
    """Dynamic Search Engine with Precision and Fuzzy Fallback."""
    msg_lower = user_msg.lower().strip()
    all_raw_words = re.findall(r'\w+', msg_lower)
    
    # 1. Negation Detection
    negated_words = set()
    for i, word in enumerate(all_raw_words):
        if word in NEGATION_WORDS and i + 1 < len(all_raw_words):
            negated_words.add(all_raw_words[i+1])

    # 2. Subject Extraction
    subject_words = [w for w in all_raw_words if w not in STOP_WORDS and w not in NEGATION_WORDS]
    subject_words_set = set(subject_words)
    msg_words_set = set(all_raw_words)

    # --- CONTEXTUAL ACTIONS ---
    if any(k in msg_words_set for k in ["yes", "do", "proceed", "go", "ok", "confirm"]):
        return _execute_pending_action()
    if any(k in msg_words_set for k in ["no", "cancel", "stop"]):
        return _clear_pending_action()

    # --- ACTIONS & GREETINGS ---
    action_reply = _parse_action(msg_lower)
    if action_reply: return action_reply
    if "help" in msg_lower:
        return "I can explain ML (Preprocessing, Metrics), Attacks (DoS, Botnet, Brute Force), summarize activity, or block IPs."
    if any(pattern in msg_lower for pattern in ["hi", "hello", "hey"]):
        return f"Hello, {current_user.username}. HADES is online. How can I assist you with your security data?"

    # --- CORE SEARCH ---
    scored_results = []
    
    for key, entry in KNOWLEDGE_BASE.items():
        key_words = set(re.findall(r'\w+', key.lower()))
        subject_key_words = key_words.difference(STOP_WORDS)
        tag_words = set(entry.get("tags", []))
        
        # Disqualify Negated
        if any(w in negated_words for w in subject_key_words) or any(w in negated_words for w in tag_words):
            continue

        # Intersection/Union (Jaccard)
        intersection = subject_key_words.intersection(subject_words_set)
        union = subject_key_words.union(subject_words_set)
        ratio = len(intersection) / len(union) if len(union) > 0 else 0
        
        score = ratio * 1000
        score += len(tag_words.intersection(subject_words_set)) * 50 # Increased tag weight
        
        # Exact title word match boost (Crucial for single word 'DoS')
        if any(w in key_words for w in subject_words_set):
            score += 300
            
        if key in msg_lower: 
            score += 500
        
        scored_results.append((score, entry["answer"], key))

    # Sort results
    scored_results.sort(key=lambda x: x[0], reverse=True)
    
    # Threshold check
    if scored_results and scored_results[0][0] >= 100: # Slightly lower threshold for utility
        return scored_results[0][1]

    # --- DYNAMIC FUZZY SUGGESTION FALLBACK ---
    suggestions = []
    for score, answer, key in scored_results:
        if key not in suggestions and score > 0:
            suggestions.append(key.title())
        if len(suggestions) >= 3: break
    
    if suggestions:
        suggestion_str = ", ".join(suggestions)
        return (f"I'm still enhancing my briefing on those specific words, admin. "
                f"However, I can provide deep intelligence on **{suggestion_str}**. "
                "Would you like to explore any of these?")
    
    return f"I am HADES, {current_user.username}. I didn't find a direct match. Try asking about **DoS, Botnets, SSH Brute Force,** or **HADES Pipeline**."


def _parse_action(msg):
    if any(k in msg for k in ["block", "ban", "stop"]) and re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', msg):
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', msg)
        ip = ip_match.group(0)
        session['pending_action'] = {'type': 'block', 'ip': ip}
        return f"Prepared **Block** for IP **{ip}**. Proceed?"
    return None

def _execute_pending_action():
    pending = session.get('pending_action')
    if not pending: return "No actions pending."
    action_type, ip = pending.get('type'), pending.get('ip')
    try:
        if action_type == 'block':
            block = BlockedIP(ip_address=ip, reason="AI Confirmed", blocked_by=current_user.id)
            db.session.add(block); db.session.add(SystemLog(level="WARNING", event="IP Blocked", details=f"Blocked {ip}.")); db.session.commit()
            session.pop('pending_action', None); return f"✅ **Confirmed.** {ip} blocked."
    except Exception as e: return f"Error: {str(e)}"
    return "Action complete."

def _clear_pending_action():
    if session.get('pending_action'):
        session.pop('pending_action', None); return "Cancelled."
    return "Nothing to cancel."

def _get_activity_summary():
    last_24h = datetime.utcnow() - timedelta(hours=24)
    logs_count = AttackLog.query.filter(AttackLog.timestamp >= last_24h).count()
    anomaly_sum = db.session.query(func.sum(AttackLog.anomaly_count)).filter(AttackLog.timestamp >= last_24h).scalar() or 0
    return f"**Summary (24h)**\n- **Sessions:** {logs_count}\n- **Anomalies:** {anomaly_sum}"

def _get_threat_intel():
    top_attacker = db.session.query(AttackLog.source_ip, func.count(AttackLog.id).label('total')).group_by(AttackLog.source_ip).order_by(desc('total')).limit(1).first()
    return f"**Top Adversary:** **{top_attacker[0]}** ({top_attacker[1]} attempts). Block?" if top_attacker else "No threats."

def _get_system_status():
    from models.database import Signature
    anomalies = db.session.query(func.sum(AttackLog.anomaly_count)).filter_by(user_id=current_user.id).scalar() or 0
    sig_count = Signature.query.count()
    return f"**HADES Status**\n- **Signatures:** {sig_count:,}\n- **Anomalies:** {anomalies}"

@chatbot_bp.route("/message", methods=["POST"])
@login_required
def message():
    data = request.get_json()
    user_msg = data.get("message", "").strip()
    if not user_msg: return jsonify({"reply": "Type something.", "status": "error"})
    reply = _find_best_match(user_msg)
    return jsonify({"reply": reply, "status": "ok", "timestamp": datetime.now().strftime("%H:%M")})
