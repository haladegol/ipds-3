"""
HADES IPS Engine — Full Implementation
Covers:
  1. Signature-Based Detection   (Misuse Detection)
  2. Protocol Anomaly Detection  (SPI — Stateful Packet Inspection)
  3. Deep Packet Inspection      (DPI — 4-step: Decode → Preprocess → Match → Verdict)
  4. IPS Actions                 (Drop / Reject / Alert / Rate-Limit + Blacklist)
"""

import re
import json
import datetime
import os
import hashlib
import urllib.parse
from collections import defaultdict

# ── Constants ────────────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW   = 60    # seconds — sliding window for scan/brute-force detection
RATE_LIMIT_THRESHOLD = 20   # packets per window before triggering dynamic blacklist
TCP_SESSION_TIMEOUT  = 300  # seconds — idle TCP sessions are purged
LOG_PATH = os.path.join("static", "logs", "ips_signals.json")

# ── Verdict constants ─────────────────────────────────────────────────────────
VERDICT_ALLOW  = "ALLOW"
VERDICT_DROP   = "DROP"      # Silent discard — attacker gets no feedback
VERDICT_REJECT = "REJECT"    # Active denial — send TCP RST / ICMP unreachable
VERDICT_ALERT  = "ALERT"     # IDS-style — log only, do not block


class ConnectionTracker:
    """
    Stateful Packet Inspection (SPI) — tracks TCP connection state per 5-tuple.
    Detects state anomalies: data before handshake, invalid flag combos, etc.
    """

    STATES = {"NONE", "SYN_SENT", "SYN_ACK", "ESTABLISHED", "FIN_WAIT", "CLOSED"}

    def __init__(self):
        # key: (src_ip, dst_ip, src_port, dst_port, proto) → {state, last_seen, pkt_count}
        self._table: dict = {}

    def _key(self, flow: dict) -> tuple:
        return (
            flow.get("src_ip", ""),
            flow.get("dst_ip", ""),
            flow.get("src_port", 0),
            flow.get("dst_port", 0),
            flow.get("proto", "TCP"),
        )

    def update(self, flow: dict) -> dict:
        """
        Update connection table and return {state, anomaly}.
        anomaly is None if clean, or a string describing the violation.
        """
        key = self._key(flow)
        flags    = flow.get("tcp_flags", "").upper()
        payload  = flow.get("payload", "")
        now      = datetime.datetime.utcnow()
        anomaly  = None

        entry = self._table.get(key)
        if entry is None:
            entry = {"state": "NONE", "last_seen": now, "pkt_count": 0}
            self._table[key] = entry

        entry["last_seen"] = now
        entry["pkt_count"] += 1

        # ── Flag-based anomalies (DPI — header analysis) ──────────────────────
        # ── Flag-based anomalies (DPI — header analysis) ──────────────────────
        if "S" in flags and "F" in flags:
            anomaly = "SYN+FIN flag combo — invalid TCP (evasion attempt)"
        elif "S" in flags and "R" in flags:
            anomaly = "SYN+RST flag combo — invalid TCP"
        
        # Disabled 'Data without handshake' for CSV flow analysis as it lacks packet-level state.
        # elif flags == "" and payload and entry["state"] not in ("ESTABLISHED",):
        #    anomaly = "Data payload without completed TCP handshake (state anomaly)"

        # ── State machine transitions ─────────────────────────────────────────
        if "S" in flags and "A" not in flags:          # SYN
            entry["state"] = "SYN_SENT"
        elif "S" in flags and "A" in flags:            # SYN-ACK
            entry["state"] = "SYN_ACK"
        elif "A" in flags and entry["state"] == "SYN_ACK":
            entry["state"] = "ESTABLISHED"             # Handshake complete
        elif "F" in flags:
            entry["state"] = "FIN_WAIT"
        elif "R" in flags:
            entry["state"] = "CLOSED"

        self._purge_stale(now)
        return {"state": entry["state"], "anomaly": anomaly}

    def _purge_stale(self, now: datetime.datetime):
        stale = [k for k, v in self._table.items()
                 if (now - v["last_seen"]).total_seconds() > TCP_SESSION_TIMEOUT]
        for k in stale:
            del self._table[k]

    def session_count(self) -> int:
        return len(self._table)


class RateLimiter:
    """
    Active Response — sliding-window rate limiter per source IP.
    Triggers dynamic blacklist when a source exceeds RATE_LIMIT_THRESHOLD
    packets within RATE_LIMIT_WINDOW seconds.
    """

    def __init__(self):
        # ip → list of timestamps
        self._windows: dict = defaultdict(list)
        self._blacklisted: set = set()

    def check(self, src_ip: str) -> bool:
        """Returns True if this IP has exceeded the rate limit (should be blocked)."""
        if src_ip in self._blacklisted:
            return True

        now = datetime.datetime.utcnow()
        cutoff = now - datetime.timedelta(seconds=RATE_LIMIT_WINDOW)
        window = self._windows[src_ip]

        # Slide the window
        self._windows[src_ip] = [t for t in window if t > cutoff]
        self._windows[src_ip].append(now)

        if len(self._windows[src_ip]) >= RATE_LIMIT_THRESHOLD:
            self._blacklisted.add(src_ip)
            return True

        return False

    def is_blacklisted(self, src_ip: str) -> bool:
        return src_ip in self._blacklisted


class IPSEngine:
    """
    HADES IPS Engine — coordinates all inspection layers and action dispatch.

    Inspection workflow (4 steps):
      1. Decode       — parse raw flow fields into structured representation
      2. Preprocess   — normalize payload (URL decode, hex unescape, case fold)
      3. Pattern Match— run Signature DB + Protocol Anomaly + Rate checks
      4. Verdict      — emit DROP / REJECT / ALERT / ALLOW + persist events
    """

    def __init__(self):
        self._sig_cache          = None
        self._last_cache_refresh = None
        self._spi                = ConnectionTracker()
        self._rate_limiter       = RateLimiter()

        # Reputation list (supplemented at runtime from BlockedIP table)
        self.reputation_list = {
            "185.220.101.10":  "Tor Exit Node",
            "45.227.253.18":   "Mirai Botnet C2",
            "103.141.137.10":  "Brute Force Source",
            "193.189.100.185": "Known XSS Aggressor",
            "213.202.242.130": "Cobalt Strike Beacon",
        }

        # Protocol anomaly rules
        self._protocol_rules = {
            "dns_max_bytes":         512,
            "http_max_uri_length":   8192,
            "smtp_max_line_length":  1000,
            "ftp_data_on_ctrl_port": True,
            "icmp_flood_pps":        200,    # packets/sec threshold
        }

    def reset_state(self):
        """Clear dynamic state (SPI sessions, Rate Limit windows) for a fresh analysis."""
        from utils.ips_engine import ConnectionTracker, RateLimiter
        self._spi = ConnectionTracker()
        self._rate_limiter = RateLimiter()
        print("[IPS] Dynamic inspection state (SPI/Rate-Limit) has been reset.")

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1: DECODE
    # ─────────────────────────────────────────────────────────────────────────
    def decode_flow(self, raw: dict) -> dict:
        """
        Map raw CIC-IDS column names → canonical internal field names.
        Produces a clean dict the rest of the engine can rely on.
        Safely handles missing columns (NaNs) from heterogeneous datasets.
        """
        def _get(keys, default=None):
            for k in keys:
                if k in raw:
                    val = raw[k]
                    # Check for float NaN or None safely
                    if val != val or val is None:
                        continue
                    return val
            return default

        def _int(val, default=0):
            try:
                return int(float(val))
            except (ValueError, TypeError):
                return default

        return {
            "src_ip":    str(_get(["Source IP", "Src IP", "src_ip"], "0.0.0.0")),
            "dst_ip":    str(_get(["Destination IP", "Dst IP", "dst_ip"], "0.0.0.0")),
            "src_port":  _int(_get(["Source Port", "Src Port", "src_port"], 0)),
            "dst_port":  _int(_get(["Destination Port", "Dst Port", "dst_port"], 0)),
            "proto":     str(_get(["Protocol", "proto"], "TCP")),
            "bytes":     _int(_get(["Total Length of Fwd Packets", "Total Fwd Packets", "bytes"], 0)),
            "packets":   _int(_get(["Total Fwd Packets", "packets"], 0)),
            "tcp_flags": str(_get(["Fwd PSH Flags", "tcp_flags"], "")),
            "payload":   str(_get(["payload", "Payload", "Info"], "")),
            "duration":  float(_int(_get(["Flow Duration", "duration"], 0))),
            # Pass-through originals for signature regex
            "_raw":      raw,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2: PREPROCESS (Normalization / DPI)
    # ─────────────────────────────────────────────────────────────────────────
    def preprocess(self, flow: dict) -> str:
        """
        Deep Packet Inspection normalization:
          - URL-decode (%20 → space)
          - Hex-unescape (\\x41 → A)
          - HTML entity decode (&lt; → <)
          - Collapse whitespace
        Returns a single normalised string representing the entire flow for
        pattern matching (payload + stringified numeric features).
        """
        payload = flow.get("payload", "")

        # URL decode
        try:
            payload = urllib.parse.unquote_plus(payload)
        except Exception:
            pass

        # Hex escape sequences: \x41
        try:
            payload = re.sub(
                r"\\x([0-9a-fA-F]{2})",
                lambda m: chr(int(m.group(1), 16)),
                payload,
            )
        except Exception:
            pass

        # Basic HTML entity decode
        for entity, char in [("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"),
                              ("&quot;", '"'), ("&#39;", "'")]:
            payload = payload.replace(entity, char)

        # Append numeric flow features as space-separated tokens so that
        # signature patterns like (?=.*\b6\b) (proto=TCP) can match
        proto_num = {"TCP": "6", "UDP": "17", "ICMP": "1", "HOPOPT": "0"}.get(
            flow.get("proto", "").upper(), str(flow.get("proto", ""))
        )
        feature_str = (
            f" {proto_num} "
            f"{flow.get('src_port', '')} "
            f"{flow.get('dst_port', '')} "
            f"{flow.get('bytes', '')} "
            f"{flow.get('packets', '')} "
        )

        return (payload + feature_str).strip()

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3A: SIGNATURE MATCHING
    # ─────────────────────────────────────────────────────────────────────────
    def get_active_signatures(self):
        from models.database import Signature
        now = datetime.datetime.utcnow()
        if (self._sig_cache is None or
                not self._last_cache_refresh or
                (now - self._last_cache_refresh).total_seconds() > 300):
            try:
                raw_sigs = Signature.query.filter_by(is_active=True).all()
                self._sig_cache = []
                for s in raw_sigs:
                    try:
                        compiled = re.compile(s.pattern, re.IGNORECASE | re.DOTALL)
                        self._sig_cache.append((s, compiled))
                    except re.error as e:
                        print(f"[IPS] Failed to compile regex for {s.sid}: {e}")
                
                self._last_cache_refresh = now
                print(f"[IPS] Signature cache refreshed: {len(self._sig_cache)} rules loaded.")
            except Exception:
                return []
        return self._sig_cache

    def clear_cache(self):
        self._sig_cache = None

    def check_signatures(self, normalised: str) -> list:
        """
        Pattern matching against all active signatures using pre-compiled regex objects.
        Returns list of matching signature dicts.
        """
        matches   = []
        sigs      = self.get_active_signatures()
        to_commit = []

        for sig, compiled_regex in sigs:
            try:
                if compiled_regex.search(normalised):
                    sig.hit_count += 1
                    to_commit.append(sig)
                    matches.append({
                        "sid":         sig.sid,
                        "name":        sig.name,
                        "severity":    sig.severity,
                        "mitre":       f"{sig.mitre_id} – {sig.mitre_tactic}" if sig.mitre_id else sig.mitre_tactic,
                        "description": sig.description,
                        "action_type": VERDICT_DROP if sig.severity in ("critical", "high") else VERDICT_ALERT,
                    })
            except Exception as e:
                pass

        # Increment hit counts in memory; the caller (analysis.py) will handle 
        # the final commit to avoid SQLite lock contention in loops.
        return matches

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3B: PROTOCOL ANOMALY DETECTION (SPI + DPI)
    # ─────────────────────────────────────────────────────────────────────────
    def check_protocol_anomaly(self, flow: dict) -> list:
        """
        Stateful + Deep inspection for protocol rule violations.
        Returns list of anomaly description strings.
        """
        anomalies = []
        dst_port  = flow.get("dst_port", 0)
        src_port  = flow.get("src_port", 0)
        proto     = str(flow.get("proto", "")).upper()
        payload   = flow.get("payload", "")
        bytes_    = flow.get("bytes", 0)
        duration  = flow.get("duration", 0)
        packets   = flow.get("packets", 0)

        # ── DNS anomalies ─────────────────────────────────────────────────────
        if dst_port == 53 or src_port == 53:
            if bytes_ > self._protocol_rules["dns_max_bytes"]:
                anomalies.append(
                    f"DNS Tunnelling: oversized DNS payload ({bytes_} bytes > "
                    f"{self._protocol_rules['dns_max_bytes']}B limit)"
                )
            if proto == "TCP" and bytes_ > 512:
                anomalies.append("DNS over TCP with large payload — possible exfiltration")

        # ── HTTP anomalies ────────────────────────────────────────────────────
        if dst_port in (80, 443, 8080, 8443):
            if len(payload) > self._protocol_rules["http_max_uri_length"]:
                anomalies.append(
                    f"HTTP URI Too Long ({len(payload)} chars) — possible buffer overflow"
                )
            if re.search(r"(GET|POST|PUT|DELETE)\s+/[^\s]{2000,}", payload, re.IGNORECASE):
                anomalies.append("HTTP Request with oversized URI path (potential exploit)")

        # ── SMTP anomalies ────────────────────────────────────────────────────
        if dst_port in (25, 587, 465):
            lines = payload.split("\n")
            for line in lines:
                if len(line) > self._protocol_rules["smtp_max_line_length"]:
                    anomalies.append(
                        f"SMTP Line Length Anomaly ({len(line)} chars) — RFC 2821 violation"
                    )
                    break

        # ── ICMP flood ───────────────────────────────────────────────────────
        if proto == "ICMP" and duration > 0:
            pps = packets / (duration / 1_000_000 + 0.001)   # duration in µs
            if pps > self._protocol_rules["icmp_flood_pps"]:
                anomalies.append(f"ICMP Flood detected ({pps:.0f} pps > {self._protocol_rules['icmp_flood_pps']} pps threshold)")

        # ── FTP data on control port ─────────────────────────────────────────
        if dst_port == 21 and bytes_ > 10_000:
            anomalies.append("FTP Data transfer on control port 21 (PORT/PASV anomaly)")

        # ── Port scan heuristic (many dsts from same src in short duration) ──
        if duration < 100_000 and packets > 50 and bytes_ / max(packets, 1) < 60:
            anomalies.append(
                f"Port Scan signature: {packets} pkts, avg {bytes_/max(packets,1):.0f} B/pkt, "
                f"duration {duration:.0f}µs"
            )

        # ── Invalid TCP header size (zero-length, oversized) ─────────────────
        if proto == "TCP" and bytes_ > 65535:
            anomalies.append(f"TCP Packet Total Length exceeds IP max ({bytes_} bytes) — header anomaly")

        # ── SPI state check ──────────────────────────────────────────────────
        spi_result = self._spi.update(flow)
        if spi_result.get("anomaly"):
            anomalies.append(f"SPI: {spi_result['anomaly']}")

        return anomalies

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3C: REPUTATION + RATE LIMIT
    # ─────────────────────────────────────────────────────────────────────────
    def check_reputation(self, src_ip: str) -> str | None:
        """Check static reputation list. Returns reason string or None."""
        return self.reputation_list.get(src_ip)

    def check_rate_limit(self, src_ip: str) -> bool:
        """Returns True if src_ip has been rate-limited / dynamically blacklisted."""
        return self._rate_limiter.check(src_ip)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4: VERDICT + ACTION DISPATCH
    # ─────────────────────────────────────────────────────────────────────────
    def inspect(self, raw_flow: dict, ips_enabled: bool = True, auto_block_critical: bool = True) -> dict:
        """
        Full 4-step inspection pipeline.  Call this for every anomalous flow.
        Returns an InspectionResult dict:
          {verdict, action, reason, sig_matches, anomalies, src_ip, dst_ip}
        """
        # ── Step 1: Decode ────────────────────────────────────────────────────
        flow = self.decode_flow(raw_flow)
        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]

        result = {
            "verdict":     VERDICT_ALLOW,
            "action":      "PERMITTED",
            "reason":      None,
            "sig_matches": [],
            "anomalies":   [],
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "spi_state":   None,
        }

        if not ips_enabled:
            result["verdict"] = VERDICT_ALERT
            result["action"]  = "LOGGED (IDS mode)"
            return result

        # ── Step 2: Preprocess (DPI normalization) ────────────────────────────
        normalised = self.preprocess(flow)

        # ── Step 3: Multi-layer threat detection ─────────────────────────────
        # 3a. Reputation — O(1), check first
        rep = self.check_reputation(src_ip)
        if rep:
            # Reputation hits are ALWAYS critical/blocked in any IPS mode
            result["verdict"]  = VERDICT_DROP
            result["action"]   = self._action_drop(src_ip, f"Reputation: {rep}", dst_ip)
            result["reason"]   = f"IP Reputation Hit: {rep}"
            return result

        # 3b. Rate limit / dynamic blacklist
        if self.check_rate_limit(src_ip):
            if auto_block_critical: # Hybrid mode - Log high anomalies
                result["verdict"] = VERDICT_ALERT
                result["action"]  = f"LOGGED — Rate limit exceeded from {src_ip}"
                result["reason"]  = "Rate limit anomaly (Hybrid mode alert)"
            else: # Active mode - Block
                result["verdict"]  = VERDICT_DROP
                result["action"]   = self._action_rate_limit(src_ip, dst_ip)
                result["reason"]   = "Dynamic Blacklist: Rate limit exceeded"
                return result

        # 3c. Protocol anomaly detection (SPI + header checks)
        anomalies = self.check_protocol_anomaly(flow)
        result["anomalies"]  = anomalies
        result["spi_state"]  = self._spi._table.get(
            (src_ip, dst_ip, flow["src_port"], flow["dst_port"], flow["proto"]), {}
        ).get("state", "NONE")

        if anomalies:
            first = anomalies[0]
            if auto_block_critical: # Hybrid mode - Log protocol anomalies
                result["verdict"] = VERDICT_ALERT
                result["action"]  = f"LOGGED — Protocol Anomaly: {first}"
                result["reason"]  = f"Protocol Anomaly (Hybrid): {first}"
            else: # Active mode - Block
                # REJECT for state anomalies (send RST), DROP for flood/scan
                if "SPI:" in first or "SYN" in first or "handshake" in first.lower():
                    result["verdict"] = VERDICT_REJECT
                    result["action"]  = self._action_reject(src_ip, dst_ip, first)
                    result["reason"]  = first
                else:
                    result["verdict"] = VERDICT_DROP
                    result["action"]  = self._action_drop(src_ip, first, dst_ip)
                    result["reason"]  = first
            # Still continue to signature match for logging completeness

        # 3d. Signature matching (DPI — payload + feature pattern)
        sig_matches = self.check_signatures(normalised)
        # Filter action_type based on tier if in Hybrid mode
        if auto_block_critical:
            for sig_m in sig_matches:
                if sig_m["severity"].lower() != "critical":
                    sig_m["action_type"] = VERDICT_ALERT
        
        result["sig_matches"] = sig_matches

        if sig_matches:
            top = sig_matches[0]
            if result["verdict"] == VERDICT_ALLOW:   # Don't downgrade a DROP
                if top["action_type"] == VERDICT_DROP:
                    result["verdict"] = VERDICT_DROP
                    result["action"]  = self._action_drop(src_ip, f"Sig: {top['name']}", dst_ip)
                    result["reason"]  = f"Signature match: [{top['sid']}] {top['name']}"
                else:
                    result["verdict"] = VERDICT_ALERT
                    result["action"]  = self._action_alert(src_ip, top, dst_ip)
                    result["reason"]  = f"Signature alert: [{top['sid']}] {top['name']}"

        # If nothing matched but it's an anomalous flow → passive alert
        if result["verdict"] == VERDICT_ALLOW:
            result["verdict"] = VERDICT_ALERT
            result["action"]  = "LOGGED (no signature match)"

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # IPS ACTION IMPLEMENTATIONS
    # ─────────────────────────────────────────────────────────────────────────
    def _action_drop(self, src_ip: str, reason: str, dst_ip: str) -> str:
        """
        Action: DROP — silent packet discard.
        Attacker receives no feedback. Logs to BlockedIP + SystemLog + SIEM file.
        """
        self._persist_block(src_ip, reason, dst_ip, "DROP")
        self.log_structured_event({
            "src_ip": src_ip, "dst_ip": dst_ip,
            "action": "DROP", "details": reason, "severity": "high",
        })
        return f"DROPPED — {reason}"

    def _action_reject(self, src_ip: str, dst_ip: str, reason: str) -> str:
        """
        Action: REJECT — active denial.
        Simulates sending TCP RST / ICMP Destination Unreachable.
        In a real inline deployment this calls the kernel netfilter REJECT target.
        """
        self._persist_block(src_ip, reason, dst_ip, "REJECT")
        self.log_structured_event({
            "src_ip": src_ip, "dst_ip": dst_ip,
            "action": "REJECT (TCP RST)", "details": reason, "severity": "high",
        })
        return f"REJECTED (TCP RST sent) — {reason}"

    def _action_alert(self, src_ip: str, sig: dict, dst_ip: str) -> str:
        """
        Action: ALERT — log without blocking (IDS-mode action inside IPS).
        Records timestamp, IPs, SID, and MITRE tactic.
        """
        self.log_structured_event({
            "src_ip": src_ip, "dst_ip": dst_ip,
            "action": "ALERT", "rule_id": sig["sid"],
            "details": sig["name"], "severity": sig["severity"],
        })
        return f"ALERTED — [{sig['sid']}] {sig['name']}"

    def _action_rate_limit(self, src_ip: str, dst_ip: str) -> str:
        """
        Action: RATE LIMIT + DYNAMIC BLACKLIST.
        After exceeding RATE_LIMIT_THRESHOLD packets/window, the source IP is
        added to the dynamic blacklist for the remainder of the session.
        """
        self._persist_block(src_ip, "Rate limit exceeded (dynamic blacklist)", dst_ip, "RATE_LIMIT")
        self.log_structured_event({
            "src_ip": src_ip, "dst_ip": dst_ip,
            "action": "RATE_LIMIT — BLACKLISTED",
            "details": f"Exceeded {RATE_LIMIT_THRESHOLD} pkts/{RATE_LIMIT_WINDOW}s",
            "severity": "high",
        })
        return f"RATE LIMITED + BLACKLISTED — {src_ip}"

    # ─────────────────────────────────────────────────────────────────────────
    # PERSISTENCE HELPERS
    # ─────────────────────────────────────────────────────────────────────────
    def _persist_block(self, src_ip: str, reason: str, dst_ip: str, action_type: str):
        """Add IP to BlockedIP table and write a SystemLog entry."""
        if not src_ip or src_ip in ("0.0.0.0", "Unknown"):
            return
        try:
            from models.database import db, BlockedIP, SystemLog
            if not BlockedIP.query.filter_by(ip_address=src_ip, is_active=True).first():
                db.session.add(BlockedIP(
                    ip_address=src_ip,
                    reason=f"[{action_type}] {reason}",
                    blocked_by=1,
                    is_active=True,
                ))
            db.session.add(SystemLog(
                level="CRITICAL",
                event=f"IPS {action_type}",
                details=f"{src_ip} → {dst_ip} | {reason}",
            ))
            db.session.commit()
        except Exception as e:
            print(f"[IPS] Persist error: {e}")

    def trigger_prevention(self, src_ip: str, event_type: str,
                            severity: str = "high", dst_ip: str = "Unknown"):
        """Legacy-compatible wrapper used by analysis.py."""
        self._action_drop(src_ip, event_type, dst_ip)

    # ─────────────────────────────────────────────────────────────────────────
    # SIEM STRUCTURED LOGGING
    # ─────────────────────────────────────────────────────────────────────────
    def log_structured_event(self, event_data: dict):
        """
        Append to static/logs/ips_signals.json using fast append-only JSONL format.
        Each record is a single line, making it O(1) to log.
        """
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        event = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "src_ip":    event_data.get("src_ip"),
            "dst_ip":    event_data.get("dst_ip"),
            "action":    event_data.get("action", "ALERT"),
            "rule_id":   event_data.get("rule_id", "HADES-IPS"),
            "details":   event_data.get("details"),
            "severity":  event_data.get("severity", "medium"),
        }
        try:
            # Use append mode for O(1) performance
            with open(LOG_PATH, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            print(f"[IPS] Log write error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # DIAGNOSTICS
    # ─────────────────────────────────────────────────────────────────────────
    def status(self) -> dict:
        """Return engine diagnostics for the dashboard."""
        return {
            "sig_cache_count":   len(self._sig_cache) if self._sig_cache else 0,
            "spi_sessions":      self._spi.session_count(),
            "blacklisted_ips":   len(self._rate_limiter._blacklisted),
            "rate_window_sec":   RATE_LIMIT_WINDOW,
            "rate_threshold":    RATE_LIMIT_THRESHOLD,
            "tcp_timeout_sec":   TCP_SESSION_TIMEOUT,
        }

    def simulate_file_hashing(self, flow: dict) -> str:
        """Compute SHA-256 fingerprint of a flow for forensic correlation."""
        seed = f"{flow.get('src_ip')}{flow.get('timestamp')}{flow.get('bytes')}"
        return hashlib.sha256(seed.encode()).hexdigest()
