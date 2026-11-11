"""Recrée les vues de détection (sql/004_detections.sql) et affiche les alertes.

Le schéma detect n'a que des vues, donc je le recrée à chaque fois sans rien perdre.

Usage :
    python src/sentinel/detect.py
"""

import sys
from pathlib import Path

import psycopg

# pour lancer le script directement
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.load_mart import DSN  # noqa: E402

DDL_FILE = Path(__file__).resolve().parents[2] / "sql" / "004_detections.sql"

SEVERITY_ORDER = "array_position(ARRAY['critical','high','medium','low'], severity)"

ALERTS = f"""
SELECT detection, name, attack_technique, severity, host(src_ip), username,
       window_start, window_end, score, detail
FROM detect.alerts
ORDER BY {SEVERITY_ORDER}, detection, score DESC, src_ip
"""


def create_views(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(DDL_FILE.read_text(encoding="utf-8"))


def fetch_alerts(conn: psycopg.Connection) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute(ALERTS)
        return cur.fetchall()


def main() -> None:
    with psycopg.connect(DSN) as conn:
        conn.add_notice_handler(lambda _: None)  # sinon PostgreSQL affiche tous les "drop cascades"
        create_views(conn)
        alerts = fetch_alerts(conn)

    if not alerts:
        print("Aucune alerte.")
        return

    for det, name, technique, severity, ip, user, start, end, score, detail in alerts:
        who = f"{ip} -> {user}" if user else ip
        print(f"[{severity:<8}] {det} {name:<24} {technique:<10} {who:<24} "
              f"{start:%H:%M:%S}-{end:%H:%M:%S}  {detail}")

    print(f"\n{len(alerts)} alertes")


if __name__ == "__main__":
    main()
