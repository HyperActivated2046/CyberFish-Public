#!/usr/bin/env python3

# Start/stop an ephemeral cloudflared tunnel (optional, disabled by default).
# NEVER use without explicit written authorization.

import subprocess
import time
import re
from pathlib import Path
from typing import Optional, Tuple


def start_tunnel(host: str, port: int,
                 cloudflared_path: str = "./cloudflared-linux-amd64",
                 logpath: str = ".cld.log",
                 wait_seconds: int = 6) -> Tuple[Optional[subprocess.Popen], Optional[str]]:
    cf = Path(cloudflared_path)
    if not cf.exists():
        raise FileNotFoundError(
            f"cloudflared binary not found at: {cloudflared_path}")

    log = Path(logpath)
    try:
        if log.exists():
            log.unlink()
    except Exception:
        pass

    args = [str(cf), "tunnel", "--url", f"{host}:{port}"]
    with open(logpath, "wb") as f:
        proc = subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT)

    time.sleep(wait_seconds)
    public_url = None
    try:
        txt = log.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"https://[-0-9a-z]+\.trycloudflare\.com", txt)
        if m:
            public_url = m.group(0)
    except Exception:
        pass
    return proc, public_url


def stop_tunnel(proc: subprocess.Popen):
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
