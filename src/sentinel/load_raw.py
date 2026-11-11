"""fichier de logs -> raw.auth_lines

Chaque ligne est copiée telle quelle. Relançable : une ligne déjà chargée
(même fichier, même numéro de ligne) est ignorée.

Deux méthodes :
- copy (défaut) : COPY dans une table temporaire, puis INSERT ... ON CONFLICT
  vers raw.auth_lines. COPY seul ne sait pas ignorer les doublons, d'où le détour ;
- insert : un INSERT par ligne (executemany), l'ancienne version.

Usage :
    python src/sentinel/load_raw.py data/raw/OpenSSH_2k.log
    python src/sentinel/load_raw.py data/raw/OpenSSH_2k.log --method insert
"""

import argparse
import time
from pathlib import Path

import psycopg

DSN = "postgresql://sentinel:sentinel@localhost:5433/sentinel"

INSERT = (
    "INSERT INTO raw.auth_lines (line_no, line, source_file) "
    "VALUES (%s, %s, %s) "
    "ON CONFLICT (source_file, line_no) DO NOTHING"
)


def read_lines(path: Path) -> list[tuple[int, str, str]]:
    resultat = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for numero, ligne in enumerate(f, start=1):
            resultat.append((numero, ligne.rstrip("\n"), path.name))
    return resultat


def load_insert(cur: psycopg.Cursor, rows: list) -> int:
    cur.executemany(INSERT, rows)
    return cur.rowcount


def load_copy(cur: psycopg.Cursor, rows: list) -> int:
    cur.execute(
        "CREATE TEMP TABLE tmp_auth_lines (line_no int, line text, source_file text) "
        "ON COMMIT DROP"
    )
    with cur.copy("COPY tmp_auth_lines (line_no, line, source_file) FROM STDIN") as copy:
        for row in rows:
            copy.write_row(row)
    cur.execute(
        "INSERT INTO raw.auth_lines (line_no, line, source_file) "
        "SELECT line_no, line, source_file FROM tmp_auth_lines "
        "ON CONFLICT (source_file, line_no) DO NOTHING"
    )
    return cur.rowcount


METHODS = {"copy": load_copy, "insert": load_insert}


def load(path: Path, method: str = "copy") -> int:
    rows = read_lines(path)
    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            return METHODS[method](cur, rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Charge un fichier de logs dans raw.auth_lines")
    ap.add_argument("path", type=Path)
    ap.add_argument("--method", choices=METHODS, default="copy")
    args = ap.parse_args()

    debut = time.perf_counter()
    n = load(args.path, args.method)
    print(f"{n} lignes chargées en {time.perf_counter() - debut:.2f} s ({args.method})")
