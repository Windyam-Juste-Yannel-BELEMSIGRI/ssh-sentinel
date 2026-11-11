"""Tests des vues de détection. Il faut la base avec mart chargé.

Certains tests vérifient les chiffres sur le vrai fichier (ceux de mon analyse
à la main). Les autres insèrent de faux événements dans une transaction que
j'annule à la fin, la base n'est jamais modifiée. C'est le seul moyen de tester
D3, qui ne sonne pas sur le fichier, et de voir les seuils (9 échecs rien, 10 alerte).
"""

from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from sentinel.detect import create_views
from sentinel.load_mart import DSN

# 198.51.100.0/24 est réservée à la doc (RFC 5737), elle n'apparaîtra jamais dans de vrais logs
TEST_IP = "198.51.100.7"
T0 = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def conn():
    try:
        c = psycopg.connect(DSN, connect_timeout=3)
    except psycopg.OperationalError:
        pytest.skip("base PostgreSQL injoignable (docker compose up -d ?)")
    c.add_notice_handler(lambda _: None)
    with c.cursor() as cur:
        cur.execute("SELECT to_regclass('mart.fact_auth_event') IS NOT NULL")
        if not cur.fetchone()[0]:
            pytest.skip("mart n'existe pas (lancer load_mart.py)")
        cur.execute("SELECT count(*) FROM mart.fact_auth_event")
        if cur.fetchone()[0] == 0:
            pytest.skip("mart.fact_auth_event est vide (lancer load_mart.py)")
    create_views(c)
    c.commit()
    yield c
    c.close()


@pytest.fixture
def cur(conn):
    # tout ce que fait le test est annulé à la fin
    with conn.cursor() as c:
        yield c
    conn.rollback()


def rows(cur, sql, params=None):
    cur.execute(sql, params)
    return cur.fetchall()


class Fake:
    """Petit helper pour insérer de faux faits depuis TEST_IP."""

    def __init__(self, cur):
        self.cur = cur
        self.line = 0
        cur.execute(
            "INSERT INTO mart.dim_ip (src_ip, first_seen, last_seen) VALUES (%s, %s, %s) "
            "RETURNING ip_key", [TEST_IP, T0, T0])
        self.ip_key = cur.fetchone()[0]

    def user(self, name, exists=True):
        self.cur.execute(
            "INSERT INTO mart.dim_user (username, is_root, account_exists) VALUES (%s, %s, %s) "
            "ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username RETURNING user_key",
            [name, name == "root", exists])
        return self.cur.fetchone()[0]

    def event(self, minutes, event_type, username, attempts=1, method="password"):
        self.line += 1
        self.cur.execute(
            "INSERT INTO mart.fact_auth_event (source_file, line_no, event_ts, ip_key, user_key, "
            "event_type, auth_method, attempts) VALUES ('__test__', %s, %s, %s, %s, %s, %s, %s)",
            [self.line, T0 + timedelta(minutes=minutes), self.ip_key, self.user(username),
             event_type, method if event_type != "invalid_user" else None, attempts])

    def fail(self, minutes, username="alice", attempts=1, method="password"):
        self.event(minutes, "auth_failure", username, attempts, method)

    def success(self, minutes, username="alice"):
        self.event(minutes, "auth_success", username)


def alerts_for_test_ip(cur, view):
    return rows(cur, f"SELECT * FROM detect.{view} WHERE src_ip = %s", [TEST_IP])


# sur le vrai fichier

def test_d1_les_ip_du_readme(cur):
    ips = {r[0] for r in rows(cur, "SELECT host(src_ip) FROM detect.d1_brute_force")}
    assert {"183.62.140.253", "187.141.143.180", "103.99.0.122", "112.95.230.3"} <= ips


def test_d1_pic_de_183_62_140_253(cur):
    assert rows(cur, "SELECT max(peak_attempts_5min) FROM detect.d1_brute_force "
                     "WHERE src_ip = '183.62.140.253'") == [(147,)]


def test_d3_aucune_alerte_sur_le_fichier(cur):
    # la seule connexion réussie (fztu) n'a aucun échec avant, je l'avais vu à la main
    assert rows(cur, "SELECT count(*) FROM detect.d3_success_after_failures") == [(0,)]


def test_d4_seule_187_141_143_180_depasse_20(cur):
    assert rows(cur, "SELECT host(src_ip), unknown_users FROM detect.d4_user_enumeration") == \
        [("187.141.143.180", 24)]


def test_d5_root_de_183_62_140_253(cur):
    assert rows(cur, "SELECT root_failures FROM detect.d5_root_targeting "
                     "WHERE src_ip = '183.62.140.253'") == [(276,)]


def test_alerts_reprend_toutes_les_vues(cur):
    total = sum(rows(cur, f"SELECT count(*) FROM detect.{v}")[0][0] for v in (
        "d1_brute_force", "d2_password_spraying", "d3_success_after_failures",
        "d4_user_enumeration", "d5_root_targeting"))
    assert rows(cur, "SELECT count(*) FROM detect.alerts") == [(total,)]


# avec de faux événements

def test_d1_9_echecs_ne_sonnent_pas(cur):
    f = Fake(cur)
    for i in range(9):
        f.fail(i * 0.5)
    assert alerts_for_test_ip(cur, "d1_brute_force") == []


def test_d1_10_echecs_en_5_min_sonnent(cur):
    f = Fake(cur)
    for i in range(10):
        f.fail(i * 0.5)
    assert len(alerts_for_test_ip(cur, "d1_brute_force")) == 1


def test_d1_compte_les_messages_repetes(cur):
    # 2 lignes "repeated 5 times" = 10 tentatives, ça doit sonner
    f = Fake(cur)
    f.fail(0, attempts=5)
    f.fail(1, attempts=5)
    assert len(alerts_for_test_ip(cur, "d1_brute_force")) == 1


def test_d1_ignore_les_sondes_none(cur):
    f = Fake(cur)
    for i in range(10):
        f.fail(i * 0.5, method="none")
    assert alerts_for_test_ip(cur, "d1_brute_force") == []


def test_d1_echecs_trop_espaces_ne_sonnent_pas(cur):
    # 10 échecs mais un par minute, jamais 10 dans la même fenêtre de 5 min
    f = Fake(cur)
    for i in range(10):
        f.fail(i)
    assert alerts_for_test_ip(cur, "d1_brute_force") == []


def test_d1_deux_rafales_donnent_deux_alertes(cur):
    f = Fake(cur)
    for i in range(10):
        f.fail(i * 0.1)
        f.fail(60 + i * 0.1)
    assert len(alerts_for_test_ip(cur, "d1_brute_force")) == 2


def test_d2_5_comptes_en_10_min_sonnent(cur):
    f = Fake(cur)
    for i in range(5):
        f.fail(i, username=f"user{i}")
    assert len(alerts_for_test_ip(cur, "d2_password_spraying")) == 1


def test_d2_meme_compte_repete_ne_sonne_pas(cur):
    f = Fake(cur)
    for i in range(20):
        f.fail(i * 0.1, username="alice")
    assert alerts_for_test_ip(cur, "d2_password_spraying") == []


def test_d3_succes_apres_5_echecs_sonne(cur):
    f = Fake(cur)
    for i in range(5):
        f.fail(i)
    f.success(20)
    (alert,) = alerts_for_test_ip(cur, "d3_success_after_failures")
    assert alert[1] == "alice"
    assert alert[4] == 5                # failed_attempts
    assert alert[7] is True             # same_user_failed


def test_d3_4_echecs_ne_sonnent_pas(cur):
    f = Fake(cur)
    for i in range(4):
        f.fail(i)
    f.success(10)
    assert alerts_for_test_ip(cur, "d3_success_after_failures") == []


def test_d3_echecs_plus_de_30_min_avant_ne_sonnent_pas(cur):
    f = Fake(cur)
    for i in range(5):
        f.fail(i)
    f.success(40)
    assert alerts_for_test_ip(cur, "d3_success_after_failures") == []


def test_d3_est_critique_dans_alerts(cur):
    f = Fake(cur)
    for i in range(5):
        f.fail(i)
    f.success(20)
    assert rows(cur, "SELECT detection, severity FROM detect.alerts "
                     "WHERE src_ip = %s AND detection = 'D3'", [TEST_IP]) == [("D3", "critical")]


def test_d4_20_comptes_inexistants_sonnent(cur):
    f = Fake(cur)
    for i in range(20):
        f.user(f"__ghost{i}", exists=False)
        f.event(i * 30, "invalid_user", f"__ghost{i}")  # étalé sur 10 h, D4 n'a pas de fenêtre
    assert alerts_for_test_ip(cur, "d4_user_enumeration")[0][3] == 20


def test_d5_succes_root_est_critique(cur):
    f = Fake(cur)
    f.fail(0, username="root")
    f.success(1, username="root")
    assert rows(cur, "SELECT severity FROM detect.alerts "
                     "WHERE src_ip = %s AND detection = 'D5'", [TEST_IP]) == [("critical",)]
