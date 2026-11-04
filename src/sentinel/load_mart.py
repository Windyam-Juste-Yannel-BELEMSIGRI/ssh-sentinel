"""stg.auth_events -> mart (dim_ip, dim_user, fact_auth_event)

Tout se fait en SQL dans la base : Python ne fait qu'envoyer les requêtes, dans
une seule transaction. Soit tout passe, soit rien n'est modifié.

Relançable sans risque :
- les dimensions et les faits sont en upsert (ON CONFLICT DO UPDATE) ;
- les faits dont la ligne stg n'est plus un événement d'authentification
  (par exemple après une correction du parser) sont supprimés.

Usage :
    python src/sentinel/load_mart.py
"""

from pathlib import Path

import psycopg

DSN = "postgresql://sentinel:sentinel@localhost:5433/sentinel"
DDL_FILE = Path(__file__).resolve().parents[2] / "sql" / "003_mart.sql"

# Les seuls types d'événements qui vont dans la table de faits.
# Les lignes PAM (pam_auth_failure, pam_more_failures...) sont volontairement
# exclues : elles répètent les échecs déjà écrits par sshd.
FACT_EVENT_TYPES = ("auth_failure", "auth_success", "invalid_user")

DELETE_STALE_FACTS = """
DELETE FROM mart.fact_auth_event f
WHERE NOT EXISTS (
  SELECT 1 FROM stg.auth_events e
  WHERE e.source_file = f.source_file
    AND e.line_no = f.line_no
    AND e.event_type = ANY(%(types)s)
    AND e.src_ip IS NOT NULL
    AND e.event_ts IS NOT NULL
)
"""

# dim_ip : on prend TOUTES les lignes stg qui ont une IP, pas seulement les faits,
# pour avoir la vraie première / dernière apparition et le DNS inverse.
UPSERT_DIM_IP = """
INSERT INTO mart.dim_ip (src_ip, first_seen, last_seen, ptr_host, reverse_dns_mismatch, is_private)
SELECT
  src_ip,
  min(event_ts),
  max(event_ts),
  max(src_host) FILTER (WHERE event_type = 'reverse_mapping_failed'),
  bool_or(event_type = 'reverse_mapping_failed'),
  src_ip << inet '10.0.0.0/8' OR src_ip << inet '172.16.0.0/12' OR src_ip << inet '192.168.0.0/16'
FROM stg.auth_events
WHERE src_ip IS NOT NULL
GROUP BY src_ip
ON CONFLICT (src_ip) DO UPDATE SET
  first_seen = EXCLUDED.first_seen,
  last_seen = EXCLUDED.last_seen,
  ptr_host = EXCLUDED.ptr_host,
  reverse_dns_mismatch = EXCLUDED.reverse_dns_mismatch,
  is_private = EXCLUDED.is_private
"""

# dim_user : est-ce que le compte existe sur le serveur ?
# - oui si on le voit dans une connexion réussie, une session, un échec PAM
#   (PAM ne parle que des comptes qu'il connaît) ou un "Failed password for X"
#   sans "invalid user" ;
# - non s'il n'apparaît que comme "invalid user" ;
# - NULL sinon (on ne sait pas).
UPSERT_DIM_USER = """
INSERT INTO mart.dim_user (username, is_root, account_exists, first_seen, last_seen)
SELECT
  username,
  username = 'root',
  CASE
    WHEN bool_or(
           event_type IN ('auth_success', 'session_opened', 'session_closed',
                          'pam_auth_failure', 'pam_more_failures')
           OR (event_type = 'auth_failure' AND NOT invalid_user)
         ) THEN true
    WHEN bool_or(invalid_user) THEN false
  END,
  min(event_ts),
  max(event_ts)
FROM stg.auth_events
WHERE username IS NOT NULL
GROUP BY username
ON CONFLICT (username) DO UPDATE SET
  is_root = EXCLUDED.is_root,
  account_exists = EXCLUDED.account_exists,
  first_seen = EXCLUDED.first_seen,
  last_seen = EXCLUDED.last_seen
"""

UPSERT_FACT = """
INSERT INTO mart.fact_auth_event (
  source_file, line_no, event_ts, ip_key, user_key, event_type,
  auth_method, src_port, session_pid, attempts
)
SELECT
  e.source_file, e.line_no, e.event_ts, i.ip_key, u.user_key, e.event_type,
  e.auth_method, e.src_port, e.pid, e.repeat_count
FROM stg.auth_events e
JOIN mart.dim_ip i ON i.src_ip = e.src_ip
LEFT JOIN mart.dim_user u ON u.username = e.username
WHERE e.event_type = ANY(%(types)s)
  AND e.event_ts IS NOT NULL
ON CONFLICT (source_file, line_no) DO UPDATE SET
  event_ts = EXCLUDED.event_ts,
  ip_key = EXCLUDED.ip_key,
  user_key = EXCLUDED.user_key,
  event_type = EXCLUDED.event_type,
  auth_method = EXCLUDED.auth_method,
  src_port = EXCLUDED.src_port,
  session_pid = EXCLUDED.session_pid,
  attempts = EXCLUDED.attempts
"""

SUMMARY = """
SELECT
  (SELECT count(*) FROM mart.dim_ip),
  (SELECT count(*) FROM mart.dim_user),
  (SELECT count(*) FROM mart.fact_auth_event),
  (SELECT coalesce(sum(attempts), 0) FROM mart.fact_auth_event WHERE event_type = 'auth_failure')
"""


def load() -> tuple[int, int, int, int]:
    params = {"types": list(FACT_EVENT_TYPES)}
    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            # Crée les tables si besoin (la base peut exister d'avant 003_mart.sql).
            cur.execute(DDL_FILE.read_text(encoding="utf-8"))
            # Ordre important : on nettoie, puis les dimensions, puis les faits
            # (les faits ont besoin des clés des dimensions).
            cur.execute(DELETE_STALE_FACTS, params)
            cur.execute(UPSERT_DIM_IP)
            cur.execute(UPSERT_DIM_USER)
            cur.execute(UPSERT_FACT, params)
            cur.execute(SUMMARY)
            return cur.fetchone()


if __name__ == "__main__":
    n_ip, n_user, n_fact, failures = load()
    print(f"dim_ip           {n_ip:>5} IP")
    print(f"dim_user         {n_user:>5} utilisateurs")
    print(f"fact_auth_event  {n_fact:>5} événements")
    print(f"\nTentatives ratées (sum(attempts) des auth_failure) : {failures}")
