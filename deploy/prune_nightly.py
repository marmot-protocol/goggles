"""Run retention on startup, then every night at 03:00 UTC.

Run as a separate Compose service after the web service has applied migrations.
Use a child process so each prune gets fresh database connections and releases
all memory afterwards. Failures retry after five minutes, without overlapping.
"""

import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta


def seconds_until_next_run(now: datetime) -> float:
    now = now.astimezone(UTC)
    next_run = now.replace(hour=3, minute=0, second=0, microsecond=0)
    if next_run <= now:
        next_run += timedelta(days=1)
    return (next_run - now).total_seconds()


def main() -> None:
    while True:
        if os.environ.get("GOGGLES_PRUNE_ON_STARTUP", "1").lower() in {"1", "true", "yes", "on"}:
            result = subprocess.run([sys.executable, "manage.py", "prune_audit_data"])
            if result.returncode:
                print("Retention prune failed; retrying in 300 seconds.", flush=True)
                time.sleep(300)
                continue
        else:
            print("Automatic retention pruning is disabled.", flush=True)
        time.sleep(seconds_until_next_run(datetime.now(UTC)))


if __name__ == "__main__":
    main()
