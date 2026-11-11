"""Tests du chargement brut. Ont besoin de la base, sinon ils sont ignorés.
Le fichier de test a un nom unique et ses lignes sont supprimées à la fin."""

import psycopg
import pytest

from sentinel.load_raw import DSN, load

LIGNES = [
    "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
    "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2",
    "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2",
]


@pytest.fixture
def fichier(tmp_path):
    try:
        conn = psycopg.connect(DSN, connect_timeout=3, autocommit=True)
    except psycopg.OperationalError:
        pytest.skip("base PostgreSQL injoignable (docker compose up -d ?)")
    path = tmp_path / "__test_load_raw__.log"
    path.write_text("\n".join(LIGNES) + "\n", encoding="utf-8")
    yield path, conn
    conn.execute("DELETE FROM raw.auth_lines WHERE source_file = %s", [path.name])
    conn.close()


def lignes_en_base(conn, name):
    return conn.execute(
        "SELECT line_no, line FROM raw.auth_lines WHERE source_file = %s ORDER BY line_no",
        [name]).fetchall()


@pytest.mark.parametrize("method", ["copy", "insert"])
def test_chargement_puis_relance(fichier, method):
    path, conn = fichier
    assert load(path, method) == 3
    assert load(path, method) == 0
    assert lignes_en_base(conn, path.name) == list(enumerate(LIGNES, start=1))


def test_copy_et_insert_se_completent(fichier):
    # Une ligne déjà chargée par une méthode est ignorée par l'autre.
    path, conn = fichier
    assert load(path, "insert") == 3
    assert load(path, "copy") == 0
