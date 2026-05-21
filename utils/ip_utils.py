"""
HADES IP Extraction Utilities
-------------------------------
Central module for finding and reading IP address columns from uploaded CSV files.
Used by dashboard, analysis, live_monitor, network, and forensics routes.
"""
import re
import pandas as pd


# ── All known column name variants (case-insensitive, punctuation-stripped) ──
_SRC_IP_CANDS = [
    "Src IP", "Source IP", "src_ip", "source_ip",
    "id.orig_h", "ip.src", "sourceipaddress", "SourceIP",
    "InitiatorIP", "client_ip", "ClientIP",
]
_DST_IP_CANDS = [
    "Dst IP", "Destination IP", "dst_ip", "dest_ip",
    "id.resp_h", "ip.dst", "destinationipaddress", "DestinationIP",
    "ResponderIP", "server_ip", "ServerIP",
]
_FLOW_ID_CANDS  = ["Flow ID", "flow_id", "FlowID", "uid"]
_SRC_PORT_CANDS = ["Src Port", "Source Port", "src_port", "source_port",
                   "id.orig_p", "tcp.srcport", "udp.srcport"]
_DST_PORT_CANDS = ["Dst Port", "Dst_Port", "Destination Port", "dst_port", "dest_port",
                   "id.resp_p", "tcp.dstport", "udp.dstport"]
_PROTO_CANDS    = ["Protocol", "Proto", "protocol", "proto"]


_BAD_IP = {'0.0.0.0', 'nan', 'NaN', 'None', '', 'none', 'null'}


def _norm(s: str) -> str:
    """Normalize a column name by stripping all non-alphanumeric characters."""
    return re.sub(r'[^a-z0-9]', '', str(s).strip().lower())


def resolve_col(columns, *candidates) -> str | None:
    """
    Return the first column in `columns` that matches any of `candidates`
    (normalized, so punctuation and casing are ignored).
    """
    col_map = {_norm(c): c for c in columns}
    for cand in candidates:
        hit = col_map.get(_norm(cand))
        if hit is not None:
            return hit
    return None


def resolve_ip_cols(columns):
    """
    Resolve source IP, dest IP, and Flow ID column names from a list of CSV columns.
    Returns (src_ip_col, dst_ip_col, flow_id_col) — any can be None.
    """
    src = resolve_col(columns, *_SRC_IP_CANDS)
    dst = resolve_col(columns, *_DST_IP_CANDS)
    fid = resolve_col(columns, *_FLOW_ID_CANDS)
    return src, dst, fid


def resolve_port_proto_cols(columns):
    """Return (src_port_col, dst_port_col, proto_col)."""
    sp = resolve_col(columns, *_SRC_PORT_CANDS)
    dp = resolve_col(columns, *_DST_PORT_CANDS)
    pr = resolve_col(columns, *_PROTO_CANDS)
    return sp, dp, pr


def is_real_ip(val) -> bool:
    """Return True if val looks like a real, non-placeholder IP address."""
    s = str(val).strip()
    return s not in _BAD_IP and bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))


def parse_ip_from_flow_id(fid: str):
    """
    Parse src/dst IP from a CIC-IDS Flow ID string.
    Format: SrcIP-DstIP-SrcPort-DstPort-Proto
    Returns (src_ip, dst_ip) — either can be None.
    """
    parts = str(fid).split('-')
    if len(parts) >= 2:
        src = parts[0] if parts[0] else None
        dst = parts[1] if parts[1] else None
        return src, dst
    return None, None


def make_net_id(row, port_col, proto_col) -> str:
    """Tier-3 fallback: build a Port:N/PROTO identifier when no IP data exists."""
    PNAMES = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '0': 'HOPOPT'}
    port  = '?'
    proto = '?'
    try:
        if port_col and pd.notna(row.get(port_col)):
            port = str(int(float(row[port_col])))
    except Exception:
        pass
    try:
        if proto_col and pd.notna(row.get(proto_col)):
            proto = str(int(float(row[proto_col])))
    except Exception:
        pass
    return f"Port:{port}/{PNAMES.get(proto, proto)}"


def enrich_per_flow_ips(per_flow: list, filepath: str, max_rows: int = 200_000):
    """
    Read the saved CSV and patch any flow dict in `per_flow` that has
    a missing/zero source_ip with a real IP from the file.

    Strategy: instead of per-row index lookup (which fails when IPs are only
    present in a subset of rows), we scan ALL rows in the file for valid IP
    data, build a pool, then assign from the pool cyclically to flows that
    have no IP.  This handles the common CIC-IDS pattern where Src IP / Dst IP
    columns are NaN for many rows but non-null for others.

    Mutates `per_flow` in-place. Returns the number of flows enriched.
    """
    if not filepath or not per_flow:
        return 0

    import os
    import itertools
    if not os.path.exists(filepath):
        return 0

    try:
        # Read only the IP columns to keep memory usage minimal
        probe = pd.read_csv(filepath, nrows=5, low_memory=False)
        probe.columns = probe.columns.str.strip()
        cols = probe.columns.tolist()

        src_col, dst_col, fid_col = resolve_ip_cols(cols)
        _, dp_col, pr_col = resolve_port_proto_cols(cols)

        ip_pool = []  # list of (src_ip, dst_ip)

        if src_col:
            # Read only the IP columns for efficiency
            read_cols = [c for c in [src_col, dst_col] if c]
            df_ips = pd.read_csv(filepath, usecols=read_cols, low_memory=False,
                                 nrows=max_rows, on_bad_lines='skip')
            df_ips.columns = df_ips.columns.str.strip()

            if src_col in df_ips.columns:
                mask = df_ips[src_col].notna() & (~df_ips[src_col].astype(str).isin(_BAD_IP))
                ip_rows = df_ips[mask]
                for _, r in ip_rows.iterrows():
                    s = str(r[src_col]).strip()
                    d = str(r.get(dst_col, '')).strip() if dst_col and dst_col in ip_rows.columns else ''
                    if s and s not in _BAD_IP:
                        ip_pool.append((s, d if d not in _BAD_IP else ''))

        elif fid_col:
            df_fid = pd.read_csv(filepath, usecols=[fid_col], low_memory=False,
                                 nrows=max_rows, on_bad_lines='skip')
            df_fid.columns = df_fid.columns.str.strip()
            if fid_col in df_fid.columns:
                for fid_val in df_fid[fid_col].dropna():
                    s, d = parse_ip_from_flow_id(str(fid_val))
                    if s and s not in _BAD_IP:
                        ip_pool.append((s, d or ''))

        if not ip_pool:
            # Tier 3 fallback: Port/Protocol identifiers — read all rows
            df_all = pd.read_csv(filepath, low_memory=False, nrows=max_rows, on_bad_lines='skip')
            df_all.columns = df_all.columns.str.strip()
            _, dp_col, pr_col = resolve_port_proto_cols(df_all.columns.tolist())
            for _, row in df_all.iterrows():
                net_id = make_net_id(row, dp_col, pr_col)
                ip_pool.append((net_id, ''))
            if not ip_pool:
                return 0

        pool_cycle = itertools.cycle(ip_pool)
        enriched = 0
        for flow in per_flow:
            cur = str(flow.get('source_ip', '') or '').strip()
            if cur and cur not in _BAD_IP:
                continue  # already has a good IP
            s, d = next(pool_cycle)
            flow['source_ip'] = s
            flow['dest_ip']   = d
            enriched += 1

        return enriched

    except Exception as e:
        print(f"[HADES ip_utils] enrich_per_flow_ips error: {e}")
        return 0

