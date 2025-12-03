"""Background DNS capture & analysis service.

Simplified implementation: tails `dns_log.csv` (written by `capture.py`) and
creates SuspiciousQuery entries based on heuristic rules.

This avoids needing raw packet sniffing privileges inside the API process.
"""

from __future__ import annotations

import threading
import time
import os
from typing import Dict
from sqlalchemy.orm import Session
from backend.database import SessionLocal
from backend import crud

LOG_PATH = "dns_log.csv"

_capture_lock = threading.Lock()
_capture_thread: threading.Thread | None = None
_stop_event: threading.Event | None = None
_last_offset = 0


def _is_suspicious(qname: str) -> bool:
    if not qname:
        return False
    # Heuristic examples:
    # 1. Very long domain
    if len(qname) > 50:
        return True
    # 2. Many subdomains
    if qname.count('.') > 5:
        return True
    # 3. High ratio of digits
    digits = sum(c.isdigit() for c in qname)
    if digits / max(1, len(qname)) > 0.3 and len(qname) > 20:
        return True
    return False


def _process_new_lines():
    global _last_offset
    if not os.path.isfile(LOG_PATH):
        return []
    new_items = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        f.seek(_last_offset)
        for line in f:
            parts = line.strip().split(',')
            if len(parts) < 5:
                continue
            # header skip
            if parts[0] == 'timestamp' and 'qname' in parts:
                continue
            qname = parts[4]
            if _is_suspicious(qname):
                new_items.append(qname)
        _last_offset = f.tell()
    return new_items


def _capture_loop(owner_user_id: int):
    # Each loop iteration reads new log lines and adds suspicious entries.
    while _stop_event and not _stop_event.is_set():
        try:
            suspicious_qnames = _process_new_lines()
            if suspicious_qnames:
                db: Session = SessionLocal()
                try:
                    for q in suspicious_qnames:
                        crud.create_suspicious(db, owner_user_id, item=type('Tmp', (), {'qname': q, 'confidence': 0.9})())
                finally:
                    db.close()
        except Exception:
            # Suppress capture errors to avoid killing thread.
            pass
        time.sleep(2)


def start_capture(user_id: int) -> bool:
    """Start background capture if not already running."""
    global _capture_thread, _stop_event
    with _capture_lock:
        if _capture_thread and _capture_thread.is_alive():
            return False  # already running
        _stop_event = threading.Event()
        _capture_thread = threading.Thread(target=_capture_loop, args=(user_id,), daemon=True)
        _capture_thread.start()
        return True


def stop_capture() -> bool:
    """Signal background capture to stop."""
    global _stop_event, _capture_thread
    with _capture_lock:
        if not _capture_thread:
            return False
        if _stop_event:
            _stop_event.set()
        _capture_thread = None
        return True


def is_running() -> bool:
    return _capture_thread is not None and _capture_thread.is_alive()
