import sys
from pathlib import Path

import psycopg

DSN = "postgresql://sentinel:sentinel@localhost:5433/sentinel"


def read_lines(path: Path) -> list[tuple[int, str, str]]:
    resultat = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for numero, ligne in enumerate(f, start=1):
            resultat.append((numero, ligne.rstrip("\n"), path.name))
    return resultat


def load(path: Path) -> int:
    rows = read_lines(path)
    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO raw.auth_lines (line_no, line, source_file) "
                "VALUES (%s, %s, %s) "
                "ON CONFLICT (source_file, line_no) DO NOTHING",
                rows,
            )
            inserted = cur.rowcount
    return inserted


if __name__ == "__main__":
    n = load(Path(sys.argv[1]))
    print(f"{n} lignes chargées")