"""Tests du modèle en étoile. Contrairement à test_parser.py, ils ont besoin de la
base (docker compose up -d) avec raw et stg déjà chargés. Sinon ils sont ignorés."""

import psycopg
import pytest

from sentinel.load_mart import DSN, FACT_EVENT_TYPES, load


def _connect():
    try:
        return psycopg.connect(DSN, connect_timeout=3, autocommit=True)
    except psycopg.OperationalError:
        pytest.skip("base PostgreSQL injoignable (docker compose up -d ?)")


@pytest.fixture(scope="module")
def cur():
    conn = _connect()
    with conn.cursor() as c:
        c.execute("SELECT to_regclass('stg.auth_events') IS NOT NULL")
        if not c.fetchone()[0]:
            pytest.skip("stg.auth_events n'existe pas (lancer load_stg.py)")
        c.execute("SELECT count(*) FROM stg.auth_events")
        if c.fetchone()[0] == 0:
            pytest.skip("stg.auth_events est vide (lancer load_stg.py)")
    load()
    with conn.cursor() as c:
        yield c
    conn.close()


def scalar(cur, sql, params=None):
    cur.execute(sql, params)
    return cur.fetchone()[0]


def test_fact_a_une_ligne_par_evenement_stg_retenu(cur):
    attendu = scalar(cur,
        "SELECT count(*) FROM stg.auth_events "
        "WHERE event_type = ANY(%s) AND src_ip IS NOT NULL AND event_ts IS NOT NULL",
        [list(FACT_EVENT_TYPES)])
    assert scalar(cur, "SELECT count(*) FROM mart.fact_auth_event") == attendu


def test_pas_de_lignes_pam_dans_les_faits(cur):
    # Sinon chaque tentative compterait double (ligne sshd + ligne PAM).
    assert scalar(cur, "SELECT count(*) FROM mart.fact_auth_event WHERE event_type LIKE 'pam%'") == 0


def test_les_tentatives_repetees_sont_comptees(cur):
    # "message repeated 5 times" doit valoir 5 dans attempts.
    stg = scalar(cur, "SELECT sum(repeat_count) FROM stg.auth_events WHERE event_type = 'auth_failure'")
    mart = scalar(cur, "SELECT sum(attempts) FROM mart.fact_auth_event WHERE event_type = 'auth_failure'")
    assert mart == stg
    assert mart > scalar(cur, "SELECT count(*) FROM mart.fact_auth_event WHERE event_type = 'auth_failure'")


def test_une_ligne_par_ip_dans_dim_ip(cur):
    assert scalar(cur, "SELECT count(*) FROM mart.dim_ip") == \
        scalar(cur, "SELECT count(DISTINCT src_ip) FROM stg.auth_events WHERE src_ip IS NOT NULL")


def test_chaque_fait_a_une_ip(cur):
    assert scalar(cur, "SELECT count(*) FROM mart.fact_auth_event WHERE ip_key IS NULL") == 0


def test_root_existe_et_est_marque_root(cur):
    cur.execute("SELECT is_root, account_exists FROM mart.dim_user WHERE username = 'root'")
    row = cur.fetchone()
    if row is None:
        pytest.skip("pas de root dans ce jeu de données")
    assert row == (True, True)


def test_un_compte_vu_seulement_en_invalid_user_n_existe_pas(cur):
    n = scalar(cur, """
        SELECT count(*) FROM mart.dim_user u
        WHERE u.account_exists IS DISTINCT FROM false
          AND NOT EXISTS (SELECT 1 FROM stg.auth_events e
                          WHERE e.username = u.username AND e.invalid_user IS NOT TRUE
                            AND e.event_type NOT IN ('invalid_user', 'invalid_user_request'))
          AND EXISTS (SELECT 1 FROM stg.auth_events e
                      WHERE e.username = u.username AND e.invalid_user)
    """)
    assert n == 0


def test_relancer_ne_change_rien(cur):
    avant = (
        scalar(cur, "SELECT count(*) FROM mart.fact_auth_event"),
        scalar(cur, "SELECT count(*) FROM mart.dim_ip"),
        scalar(cur, "SELECT count(*) FROM mart.dim_user"),
    )
    load()
    apres = (
        scalar(cur, "SELECT count(*) FROM mart.fact_auth_event"),
        scalar(cur, "SELECT count(*) FROM mart.dim_ip"),
        scalar(cur, "SELECT count(*) FROM mart.dim_user"),
    )
    assert avant == apres
