"""raw.auth_lines -> stg.auth_events

Lit les lignes brutes, les découpe avec parser.py et écrit le résultat dans stg.
Relançable sans risque : une ligne déjà présente est mise à jour, pas dupliquée.
C'est ce qui permet de corriger le parser puis de tout rejouer.

Usage :
    python src/sentinel/load_stg.py                 # année déduite, fuseau UTC
    python src/sentinel/load_stg.py --year 2017     # année forcée
    python src/sentinel/load_stg.py --tz Europe/Paris
"""

import argparse
import ipaddress
import sys
from collections import Counter
from datetime import timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg

# Permet de lancer le script directement (python src/sentinel/load_stg.py)
# tout en important le parser comme un module du paquet "sentinel".
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.parser import parse_line, resolve_timestamp  # noqa: E402

DSN = "postgresql://sentinel:sentinel@localhost:5433/sentinel"

UPSERT = """
INSERT INTO stg.auth_events (
  source_file, line_no, event_ts, host, process, pid, event_type, username,
  src_ip, src_port, src_host, auth_method, invalid_user, preauth,
  repeat_count, detail, message, parsed_at
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
ON CONFLICT (source_file, line_no) DO UPDATE SET
  event_ts = EXCLUDED.event_ts, host = EXCLUDED.host, process = EXCLUDED.process,
  pid = EXCLUDED.pid, event_type = EXCLUDED.event_type, username = EXCLUDED.username,
  src_ip = EXCLUDED.src_ip, src_port = EXCLUDED.src_port, src_host = EXCLUDED.src_host,
  auth_method = EXCLUDED.auth_method, invalid_user = EXCLUDED.invalid_user,
  preauth = EXCLUDED.preauth, repeat_count = EXCLUDED.repeat_count,
  detail = EXCLUDED.detail, message = EXCLUDED.message, parsed_at = now()
"""


def get_timezone(name: str):
    # Sous Windows, ZoneInfo a besoin du paquet "tzdata" (voir requirements.txt).
    return timezone.utc if name.upper() == "UTC" else ZoneInfo(name)


def load(year: int | None, tz_name: str) -> Counter:
    tz = get_timezone(tz_name)
    stats: Counter = Counter()
    rows = []

    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source_file, line_no, line, ingested_at "
                "FROM raw.auth_lines ORDER BY source_file, line_no"
            )
            for source_file, line_no, line, ingested_at in cur:
                ev = parse_line(line)
                if ev is None:
                    stats["(en-tête non reconnu)"] += 1
                    continue
                stats[ev.event_type] += 1
                rows.append((
                    source_file, line_no,
                    resolve_timestamp(ev, reference=ingested_at, tz=tz, year=year),
                    ev.host, ev.process, ev.pid, ev.event_type, ev.username,
                    ipaddress.ip_address(ev.src_ip) if ev.src_ip else None,
                    ev.src_port, ev.src_host, ev.auth_method, ev.invalid_user,
                    ev.preauth, ev.repeat_count, ev.detail, ev.message,
                ))

            cur.executemany(UPSERT, rows)
    return stats


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Parse raw.auth_lines vers stg.auth_events")
    ap.add_argument("--year", type=int, help="année des logs (sinon déduite de la date d'ingestion)")
    ap.add_argument("--tz", default="UTC", help="fuseau horaire des logs (défaut : UTC)")
    args = ap.parse_args()

    stats = load(args.year, args.tz)
    total = sum(stats.values())
    print(f"{total} lignes traitées\n")
    for event_type, n in stats.most_common():
        print(f"  {event_type:<24} {n:>5}")
    unknown = stats.get("unknown", 0) + stats.get("(en-tête non reconnu)", 0)
    print(f"\nNon reconnues : {unknown}")
