"""
Fast CSV zone-sampler utility.

For large CSVs we read 3 zones (start/mid/end) using byte-level seeking so
we NEVER scan past what we need.  This reduces a 4 GB / 20 M-row file from
"hours of itertuples" to "a few seconds of targeted I/O".
"""
import io
import os
import pandas as pd


def _seek_to_line(fh, target_line: int):
    """
    Jump to approximately line `target_line` by seeking to a byte offset
    estimated from the file's average bytes-per-line, then scanning forward
    to the next complete newline so the next read starts cleanly.

    Parameters
    ----------
    fh          : binary file handle (opened with 'rb')
    target_line : 1-based line number to seek to (0 = header)
    """
    fsize = os.fstat(fh.fileno()).st_size

    # Sample first 32 KB to estimate average bytes-per-line
    fh.seek(0)
    sample = fh.read(32_768)
    n_nl = sample.count(b'\n')
    avg_bpl = (32_768 / n_nl) if n_nl > 1 else 300

    byte_offset = min(int(target_line * avg_bpl), max(0, fsize - 1))
    fh.seek(byte_offset)
    fh.readline()   # skip partial line → now at clean line boundary


def fast_zone_sample(filepath: str, quota: int, est_lines: int) -> pd.DataFrame | None:
    """
    Read `quota` rows from `filepath` by sampling 3 zones (start, middle, end).
    Uses byte-level seeking so we read O(quota) rows, not O(total_rows).

    Returns a DataFrame or None on failure.
    """
    zone = max(1, quota // 3)
    parts = []

    try:
        # ── Zone 1: Start — plain nrows, no seeking ──────────────────────
        z1 = pd.read_csv(filepath, nrows=zone, low_memory=False, on_bad_lines='skip')
        parts.append(z1)
        hdr = z1.columns.tolist()

        if est_lines <= zone * 2:
            # File is small enough that zone 1 covers it
            return z1

        # ── Zone 2: Middle — byte-seek to ~50% of file ───────────────────
        mid_line = max(zone + 1, est_lines // 2 - zone // 2)
        with open(filepath, 'rb') as fh:
            # Read header bytes (need them to parse)
            header_bytes = fh.readline()
            _seek_to_line(fh, mid_line)
            # Read exactly `zone` rows from this position
            buf = io.BytesIO(header_bytes + fh.read(int(zone * 400)))  # ~400 bytes/row est
        z2 = pd.read_csv(buf, nrows=zone, low_memory=False, on_bad_lines='skip')
        if list(z2.columns) != hdr and len(z2.columns) == len(hdr):
            z2.columns = hdr
        if set(z2.columns) == set(hdr):
            parts.append(z2)

        if est_lines <= zone * 3:
            return pd.concat(parts, ignore_index=True) if parts else None

        # ── Zone 3: End — byte-seek to ~90% of file ──────────────────────
        end_line = max(mid_line + zone + 1, est_lines - zone - 10)
        with open(filepath, 'rb') as fh:
            header_bytes = fh.readline()
            _seek_to_line(fh, end_line)
            buf = io.BytesIO(header_bytes + fh.read(int(zone * 400)))
        z3 = pd.read_csv(buf, nrows=zone, low_memory=False, on_bad_lines='skip')
        if list(z3.columns) != hdr and len(z3.columns) == len(hdr):
            z3.columns = hdr
        if set(z3.columns) == set(hdr):
            parts.append(z3)

    except Exception as e:
        print(f"[HADES] Zone sampler warning ({os.path.basename(filepath)}): {e}")
        # Absolute fallback: just read the first quota rows
        try:
            return pd.read_csv(filepath, nrows=quota, low_memory=False, on_bad_lines='skip')
        except Exception:
            return None

    return pd.concat(parts, ignore_index=True) if parts else None
