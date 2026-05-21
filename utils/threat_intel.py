import urllib.request
import urllib.error
import re
from models.database import db, Signature, SystemLog

def sync_et_open(app_context=None):
    """
    Downloads Emerging Threats Open rules and parses them.
    Because our ML dataset is tabular CIC-IDS, we extract Port and Protocol 
    from the Snort rule header to create matchable Regexes instead of 
    relying on deep-packet 'content' matching.
    """
    if app_context:
        app_context.push()

    urls = [
        # Core threat intelligence
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-malware.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-botcc.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-trojan.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-exploit.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-web_client.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-phishing.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-scan.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-dshield.rules",
        # Extended coverage
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-dos.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-ftp.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-smtp.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-sql.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-telnet.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-dns.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-icmp.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-exploit_kit.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-user_agents.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-info.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-current_events.rules",
        "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-p2p.rules",
    ]
    
    rules_text = ""
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                rules_text += response.read().decode('utf-8') + "\n"
        except Exception:
            pass # Skip failed downloads, we will gather enough from successful ones
            
    added_count = 0
    total_wanted = 10000
    
    # Generic protocol mapping to CIC-IDS numericals (TCP=6, UDP=17, ICMP=1)
    proto_map = {"tcp": "6", "udp": "17", "icmp": "1"}
    
    for line in rules_text.splitlines():
        if added_count >= total_wanted:
            break

        line = line.strip()
        if not line or line.startswith("#") or not line.startswith("alert"):
            continue
            
        # Example: alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET MALWARE Win32/Onescan..."; ... classtype:trojan-activity; sid:2013444; rev:2;)
        match = re.match(r"^alert\s+(tcp|udp|icmp|ip)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s+\((.*)\)", line, re.IGNORECASE)
        if not match:
            continue
            
        protocol = match.group(1).lower()
        dst_port_raw = match.group(6)
        options = match.group(7)
        
        # Extract SID
        sid_match = re.search(r"sid:\s*(\d+);", options)
        if not sid_match:
            continue
        sid = f"ET-{sid_match.group(1)}"
        
        # Extract MSG
        msg_match = re.search(r'msg:\s*"([^"]+)";', options)
        name = msg_match.group(1) if msg_match else "ET Open Rule"
        
        # Extract Classtype for Severity
        class_match = re.search(r'classtype:\s*([^;]+);', options)
        classtype = class_match.group(1) if class_match else "unknown"
        
        severity = "medium"
        if "trojan" in classtype or "malware" in classtype.lower() or "shellcode" in classtype: severity = "critical"
        elif "policy" in classtype: severity = "low"
        elif "attempted-admin" in classtype: severity = "high"
        
        # Port Translation
        port_regex = r"\d+"
        if "$HTTP_PORTS" in dst_port_raw:
            port_regex = r"(?:80|443|8080)"
        elif "$FTP_PORTS" in dst_port_raw:
            port_regex = r"(?:21|20)"
        elif "$SSH_PORTS" in dst_port_raw:
            port_regex = r"22"
        elif dst_port_raw.isdigit():
            port_regex = dst_port_raw
        elif "[" in dst_port_raw and "]" in dst_port_raw: 
            ports = re.findall(r"\d+", dst_port_raw)
            if ports: port_regex = f"(?:{'|'.join(ports)})"
        
        numeric_proto = proto_map.get(protocol, r"\d+")
        
        # Regex Pattern Formulation to match Tabular Flow Data Space-Delimited:
        # We use lookaheads to ensure both Protocol number and Port number exist as isolated words in the tabular string.
        pattern = f"(?=.*(?:^|\\s){numeric_proto}(?:\\s|$))(?=.*(?:^|\\s){port_regex}(?:\\s|$))"

        # Check if exists
        existing = Signature.query.filter_by(sid=sid).first()
        if not existing:
            new_sig = Signature(
                sid=sid,
                name=name,
                pattern=pattern,
                severity=severity,
                mitre_tactic=classtype,
                description=f"ET Open SNORT Translation | Target Port Layer: {dst_port_raw}"
            )
            db.session.add(new_sig)
            added_count += 1
            
            if added_count % 500 == 0:
                db.session.commit()
                
    db.session.commit()
    
    if added_count > 0:
        message = f"HADES Intelligence Lab: Synchronized {added_count} New Real-World ET Open Signatures."
        db.session.add(SystemLog(level='SUCCESS', event='Intelligence Sync', details=message))
        db.session.commit()
    
    if app_context:
        app_context.pop()
        
    return True, f"Successfully parsed and injected {added_count} ET Open signatures."


def sync_talos(app_context=None):
    """
    Downloads the Snort Community Ruleset (Talos-certified, GPLv2, free — no registration).
    Source: https://www.snort.org/downloads/community/community-rules.tar.gz
    Parses standard Snort 2.9 rule syntax — same format as ET Open.
    Also fetches the Talos IP block list and seeds any new IPs into BlockedIP.
    """
    import tarfile
    import io
    from models.database import BlockedIP

    if app_context:
        app_context.push()

    # ── 1. Download & extract community-rules.tar.gz ──────────────────────────
    RULES_URL = "https://www.snort.org/downloads/community/community-rules.tar.gz"
    IP_LIST_URL = "https://www.snort.org/downloads/ip-block-list"

    rules_text = ""
    try:
        req = urllib.request.Request(RULES_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
        # Extract all *.rules files from the tarball
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".rules"):
                    f = tar.extractfile(member)
                    if f:
                        rules_text += f.read().decode("utf-8", errors="ignore") + "\n"
    except Exception as e:
        if app_context:
            app_context.pop()
        return False, f"Talos rules download failed: {e}"

    # ── 2. Parse rules (same logic as ET Open) ────────────────────────────────
    proto_map = {"tcp": "6", "udp": "17", "icmp": "1"}
    cvss_classtype = {
        "trojan-activity": ("critical", 9.8),
        "malware":         ("critical", 9.8),
        "shellcode-detect":("critical", 9.5),
        "attempted-admin": ("high",     7.5),
        "web-application-attack": ("high", 7.5),
        "attempted-user":  ("high",     7.0),
        "denial-of-service": ("high",   7.8),
        "policy-violation":  ("low",    2.1),
        "protocol-command-decode": ("medium", 5.3),
        "network-scan":    ("medium",   4.0),
        "unknown":         ("medium",   5.3),
    }

    added_count = 0
    for line in rules_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith("alert"):
            continue

        match = re.match(
            r"^alert\s+(tcp|udp|icmp|ip)\s+(\S+)\s+(\S+)\s+(-\>|\<\>)\s+(\S+)\s+(\S+)\s+\((.*)\)",
            line, re.IGNORECASE
        )
        if not match:
            continue

        protocol    = match.group(1).lower()
        dst_port_raw = match.group(6)
        options      = match.group(7)

        sid_m = re.search(r"sid:\s*(\d+);", options)
        if not sid_m:
            continue
        sid = f"TALOS-{sid_m.group(1)}"

        # Skip if already in DB
        if Signature.query.filter_by(sid=sid).first():
            continue

        msg_m   = re.search(r'msg:\s*"([^"]+)";', options)
        name    = msg_m.group(1) if msg_m else "Talos Community Rule"

        class_m  = re.search(r"classtype:\s*([^;]+);", options)
        classtype = class_m.group(1).strip() if class_m else "unknown"

        # Find best-matching classtype key
        sev, cvss = "medium", 5.3
        for key, (s, c) in cvss_classtype.items():
            if key in classtype.lower():
                sev, cvss = s, c
                break

        # MITRE mapping by classtype
        mitre_map = {
            "trojan":    "T1071 - C2",
            "malware":   "T1059 - Execution",
            "shellcode": "T1203 - Exploitation",
            "dos":       "T1498 - Impact",
            "web-application": "T1190 - Initial Access",
            "scan":      "T1046 - Reconnaissance",
        }
        mitre = next((v for k, v in mitre_map.items() if k in classtype.lower()), "TA0001")

        # Port regex
        if "$HTTP_PORTS" in dst_port_raw:
            port_regex = r"(?:80|443|8080)"
        elif "$FTP_PORTS" in dst_port_raw:
            port_regex = r"(?:21|20)"
        elif "$SSH_PORTS" in dst_port_raw:
            port_regex = r"22"
        elif "$SMTP_PORTS" in dst_port_raw:
            port_regex = r"(?:25|587|465)"
        elif "$SQL_PORTS" in dst_port_raw:
            port_regex = r"(?:1433|3306|5432)"
        elif dst_port_raw.isdigit():
            port_regex = dst_port_raw
        elif "[" in dst_port_raw:
            ports = re.findall(r"\d+", dst_port_raw)
            port_regex = f"(?:{'|'.join(ports)})" if ports else r"\d+"
        else:
            port_regex = r"\d+"

        numeric_proto = proto_map.get(protocol, r"\d+")
        pattern = (
            f"(?=.*(?:^|\\s){numeric_proto}(?:\\s|$))"
            f"(?=.*(?:^|\\s){port_regex}(?:\\s|$))"
        )

        db.session.add(Signature(
            sid=sid,
            name=name,
            pattern=pattern,
            severity=sev,
            mitre_tactic=mitre,
            description=(
                f"Talos Community Rule | classtype:{classtype} | "
                f"CVSS:{cvss} | port:{dst_port_raw}"
            ),
        ))
        added_count += 1
        if added_count % 500 == 0:
            db.session.commit()

    db.session.commit()

    # ── 3. Fetch Talos IP Block List ──────────────────────────────────────────
    ip_added = 0
    try:
        req2 = urllib.request.Request(IP_LIST_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req2, timeout=15) as resp:
            ip_text = resp.read().decode("utf-8", errors="ignore")

        for ip_line in ip_text.splitlines():
            ip_line = ip_line.strip()
            if not ip_line or ip_line.startswith("#"):
                continue
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_line):
                existing = BlockedIP.query.filter_by(ip_address=ip_line).first()
                if not existing:
                    db.session.add(BlockedIP(
                        ip_address=ip_line,
                        reason="Talos IP Block List",
                        severity="high",
                        is_active=True,
                    ))
                    ip_added += 1
        if ip_added:
            db.session.commit()
    except Exception:
        pass  # IP list is optional — rules are the main payload

    msg = (
        f"Talos Sync: {added_count} new Snort community rules added"
        + (f", {ip_added} Talos IPs imported." if ip_added else ".")
    )
    db.session.add(SystemLog(
        level="SUCCESS",
        event="Talos Intelligence Sync",
        details=msg,
    ))
    db.session.commit()

    if app_context:
        app_context.pop()

    return True, msg

