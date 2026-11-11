"""detect -> reports/report.md

Recrée les vues de détection puis écrit le rapport en Markdown.
Tout ce qui est dans le rapport vient de la base, rien n'est écrit à la main.

Usage :
    python src/sentinel/report.py
    python src/sentinel/report.py -o reports/autre.md
"""

import argparse
import sys
from datetime import date
from pathlib import Path

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.detect import create_views  # noqa: E402
from sentinel.load_mart import DSN  # noqa: E402

DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "reports" / "report.md"

SEVERITY_RANK = "array_position(ARRAY['critical','high','medium','low'], severity)"

OVERVIEW = """
SELECT
  (SELECT string_agg(DISTINCT source_file, ', ') FROM raw.auth_lines),
  (SELECT count(*) FROM raw.auth_lines),
  (SELECT min(event_ts) FROM mart.fact_auth_event),
  (SELECT max(event_ts) FROM mart.fact_auth_event),
  (SELECT count(*) FROM mart.fact_auth_event),
  (SELECT sum(attempts) FROM mart.fact_auth_event
    WHERE event_type = 'auth_failure' AND auth_method = 'password'),
  (SELECT count(DISTINCT ip_key) FROM mart.fact_auth_event
    WHERE event_type = 'auth_failure' AND auth_method = 'password'),
  (SELECT count(*) FROM detect.alerts),
  (SELECT count(DISTINCT src_ip) FROM detect.alerts)
"""

BY_DETECTION = """
SELECT d.detection, d.name, d.technique, count(a.detection), count(DISTINCT a.src_ip)
FROM (VALUES ('D1', 'Brute force', 'T1110.001'),
             ('D2', 'Password spraying', 'T1110.003'),
             ('D3', 'Succès après échecs', 'T1078'),
             ('D4', 'Énumération de comptes', 'T1110'),
             ('D5', 'Ciblage de root', 'T1110')) AS d(detection, name, technique)
LEFT JOIN detect.alerts a ON a.detection = d.detection
GROUP BY d.detection, d.name, d.technique
ORDER BY d.detection
"""

# Une ligne par IP qui a au moins une alerte, de la plus grave à la moins grave.
BY_IP = f"""
WITH alerted AS (
  SELECT src_ip,
         min({SEVERITY_RANK}) AS rank,
         string_agg(DISTINCT detection, ', ' ORDER BY detection) AS detections
  FROM detect.alerts
  GROUP BY src_ip
),
activity AS (
  SELECT e.src_ip,
         coalesce(sum(e.attempts) FILTER (WHERE e.event_type = 'auth_failure'
                                           AND e.auth_method = 'password'), 0) AS failures,
         count(DISTINCT e.user_key)                                   AS users,
         count(DISTINCT e.user_key) FILTER (WHERE e.account_exists = false) AS unknown_users,
         min(e.event_ts) AS first_ts,
         max(e.event_ts) AS last_ts
  FROM detect.auth_events e
  GROUP BY e.src_ip
)
SELECT host(a.src_ip),
       (ARRAY['critical','high','medium','low'])[a.rank],
       a.detections,
       act.failures, act.users, act.unknown_users,
       r.root_ratio,
       act.first_ts, act.last_ts,
       i.reverse_dns_mismatch, i.ptr_host
FROM alerted a
JOIN activity act ON act.src_ip = a.src_ip
JOIN mart.dim_ip i ON i.src_ip = a.src_ip
LEFT JOIN detect.d5_root_targeting r ON r.src_ip = a.src_ip
ORDER BY a.rank, act.failures DESC
"""

ALERTS = f"""
SELECT detection, severity, host(src_ip), window_start, window_end, detail
FROM detect.alerts
ORDER BY detection, score DESC, src_ip
"""

SUCCESSES = """
SELECT e.username, host(e.src_ip), e.event_ts,
       (SELECT coalesce(sum(f.attempts), 0) FROM detect.auth_events f
         WHERE f.ip_key = e.ip_key AND f.event_type = 'auth_failure' AND f.event_ts < e.event_ts),
       EXISTS (SELECT 1 FROM detect.d3_success_after_failures d
                WHERE d.src_ip = e.src_ip AND d.success_ts = e.event_ts)
FROM detect.auth_events e
WHERE e.event_type = 'auth_success'
ORDER BY e.event_ts
"""


def fetch(cur, sql):
    cur.execute(sql)
    return cur.fetchall()


def hm(ts):
    return f"{ts:%H:%M}"


def plage(start, end):
    return hm(start) if hm(start) == hm(end) else f"{hm(start)} - {hm(end)}"


def build(cur) -> str:
    (files, n_lines, start, end, n_events, n_failures, n_failing_ips,
     n_alerts, n_alert_ips) = fetch(cur, OVERVIEW)[0]
    by_detection = fetch(cur, BY_DETECTION)
    by_ip = fetch(cur, BY_IP)
    alerts = fetch(cur, ALERTS)
    successes = fetch(cur, SUCCESSES)

    out = []
    w = out.append

    w("# Rapport de détection SSH\n")
    w(f"Fichier analysé : `{files}`, {n_lines} lignes, "
      f"du {start:%d/%m/%Y} {hm(start)} au {end:%d/%m/%Y} {hm(end)} (UTC).  ")
    w(f"Généré le {date.today():%d/%m/%Y} avec `report.py`.\n")

    w("## Résumé\n")
    w(f"{n_events} événements d'authentification, dont {n_failures} mots de passe ratés "
      f"venant de {n_failing_ips} adresses IP. "
      f"Les détections sortent {n_alerts} alertes sur {n_alert_ips} IP.\n")
    if not successes:
        w("Aucune connexion réussie dans le fichier.\n")
    else:
        compromised = sum(1 for s in successes if s[4])
        if compromised:
            w(f"**{compromised} connexion{'s' * (compromised > 1)} réussie{'s' * (compromised > 1)} "
              "après une série d'échecs (D3), à traiter en premier.**\n")
        elif len(successes) == 1:
            w("Une seule connexion réussie, sans échec avant depuis la même IP.\n")
        else:
            w(f"{len(successes)} connexions réussies, aucune précédée d'échecs depuis la même IP.\n")

    w("| Détection | ATT&CK | Alertes | IP |")
    w("| --- | --- | --- | --- |")
    for det, name, technique, n, ips in by_detection:
        w(f"| {det} {name} | {technique} | {n} | {ips} |")
    w("")

    w("## IP concernées\n")
    w("| IP | Gravité max | Détections | Mots de passe ratés | Comptes essayés "
      "| dont inexistants | Part root | Activité |")
    w("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for ip, sev, dets, fails, users, unknown, ratio, first, last, _, _ in by_ip:
        root = f"{round(ratio * 100)} %" if ratio is not None else "-"
        w(f"| {ip} | {sev} | {dets} | {fails} | {users} | {unknown} | {root} "
          f"| {plage(first, last)} |")
    w("")

    mismatch = [(ip, ptr) for ip, *_, flag, ptr in by_ip if flag]
    if mismatch:
        w("DNS inverse incohérent (`POSSIBLE BREAK-IN ATTEMPT!`) : "
          + ", ".join(f"{ip} (`{ptr}`)" for ip, ptr in mismatch) + ".\n")

    w("## Connexions réussies\n")
    if successes:
        w("| Compte | IP | Heure | Échecs avant depuis cette IP | D3 |")
        w("| --- | --- | --- | --- | --- |")
        for user, ip, ts, before, d3 in successes:
            w(f"| {user} | {ip} | {ts:%H:%M:%S} | {before} | {'oui' if d3 else 'non'} |")
        w("")
    else:
        w("Aucune.\n")

    w("## Détail des alertes\n")
    w("| | Gravité | IP | Fenêtre | Détail |")
    w("| --- | --- | --- | --- | --- |")
    for det, sev, ip, ws, we, detail in alerts:
        w(f"| {det} | {sev} | {ip} | {plage(ws, we)} | {detail} |")
    w("")

    w("Les règles et leurs seuils sont décrits dans le README (section `detect`).")
    return "\n".join(out) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Écrit le rapport Markdown des alertes.")
    ap.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT)
    args = ap.parse_args()

    with psycopg.connect(DSN) as conn:
        conn.add_notice_handler(lambda _: None)
        create_views(conn)
        with conn.cursor() as cur:
            cur.execute("SET TIME ZONE 'UTC'")
            text = build(cur)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    print(f"Rapport écrit : {args.output}")


if __name__ == "__main__":
    main()
