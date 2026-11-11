"""Tests du parser. Une vraie ligne du fichier par type d'événement, et les
pièges que j'ai trouvés en regardant les logs à la main."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.parser import parse_line, resolve_timestamp

DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "raw" / "OpenSSH_2k.log"


# l'en-tête syslog

def test_header():
    ev = parse_line("Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186")
    assert (ev.month, ev.day, ev.time) == (12, 10, "06:55:46")
    assert (ev.host, ev.process, ev.pid) == ("LabSZ", "sshd", 24200)


def test_header_jour_sur_un_chiffre():
    # syslog écrit "Dec  1" avec deux espaces
    ev = parse_line("Dec  1 06:55:46 LabSZ sshd[1]: Connection closed by 1.2.3.4 [preauth]")
    assert ev.day == 1


def test_fin_de_ligne_windows():
    ev = parse_line("Dec 10 06:55:46 LabSZ sshd[1]: Invalid user bob from 1.2.3.4\r\n")
    assert ev.src_ip == "1.2.3.4"


def test_ligne_hors_format():
    assert parse_line("ceci n'est pas un log") is None


# un test par type d'événement

@pytest.mark.parametrize("message, attendu", [
    ("Accepted password for fztu from 119.137.62.142 port 49116 ssh2",
     dict(event_type="auth_success", username="fztu", src_ip="119.137.62.142",
          src_port=49116, auth_method="password")),
    ("Failed password for root from 183.62.140.253 port 39408 ssh2",
     dict(event_type="auth_failure", username="root", src_ip="183.62.140.253",
          src_port=39408, auth_method="password", invalid_user=False)),
    ("Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2",
     dict(event_type="auth_failure", username="webmaster", invalid_user=True)),
    ("Failed none for invalid user 0 from 5.188.10.180 port 49841 ssh2",
     dict(event_type="auth_failure", auth_method="none", username="0", invalid_user=True)),
    ("Invalid user webmaster from 173.234.31.186",
     dict(event_type="invalid_user", username="webmaster", src_ip="173.234.31.186",
          invalid_user=True)),
    ("input_userauth_request: invalid user webmaster [preauth]",
     dict(event_type="invalid_user_request", username="webmaster", preauth=True)),
    ("Received disconnect from 183.62.140.253: 11: Bye Bye [preauth]",
     dict(event_type="disconnect", src_ip="183.62.140.253", detail="11: Bye Bye", preauth=True)),
    ("error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]",
     dict(event_type="disconnect", src_ip="103.99.0.122")),
    ("Connection closed by 212.47.254.145 [preauth]",
     dict(event_type="connection_closed", src_ip="212.47.254.145")),
    ("Did not receive identification string from 52.80.34.196",
     dict(event_type="no_identification", src_ip="52.80.34.196")),
    ("reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!",
     dict(event_type="reverse_mapping_failed", src_ip="173.234.31.186",
          src_host="ns.marryaldkfaczcz.com")),
    ("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=183.62.140.253  user=root",
     dict(event_type="pam_auth_failure", src_ip="183.62.140.253", username="root")),
    ("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=ns.marryaldkfaczcz.com ",
     dict(event_type="pam_auth_failure", src_ip=None, src_host="ns.marryaldkfaczcz.com",
          username=None)),
    ("pam_unix(sshd:auth): check pass; user unknown",
     dict(event_type="pam_unknown_user")),
    ("PAM 5 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=183.62.140.253  user=root",
     dict(event_type="pam_more_failures", detail="5", username="root")),
    ("PAM service(sshd) ignoring max retries; 6 > 3",
     dict(event_type="pam_max_retries", detail="6 > 3")),
    ("Disconnecting: Too many authentication failures for root [preauth]",
     dict(event_type="too_many_failures", username="root", preauth=True)),
    ("pam_unix(sshd:session): session opened for user fztu by (uid=0)",
     dict(event_type="session_opened", username="fztu")),
    ("pam_unix(sshd:session): session closed for user fztu",
     dict(event_type="session_closed", username="fztu")),
    ("fatal: Write failed: Connection reset by peer [preauth]",
     dict(event_type="fatal", detail="Write failed: Connection reset by peer")),
])
def test_types_evenements(message, attendu):
    ev = parse_line(f"Dec 10 06:55:46 LabSZ sshd[24200]: {message}")
    for champ, valeur in attendu.items():
        assert getattr(ev, champ) == valeur, champ


# les pièges

def test_message_repete_compte_plusieurs_echecs():
    ev = parse_line(
        "Dec 10 07:27:55 LabSZ sshd[24237]: message repeated 5 times: "
        "[ Failed password for root from 112.95.230.3 port 41782 ssh2]"
    )
    assert ev.event_type == "auth_failure"
    assert ev.repeat_count == 5
    assert ev.src_ip == "112.95.230.3"


def test_nom_utilisateur_avec_espace():
    # c'est l'attaquant qui choisit le nom, espaces compris
    ev = parse_line("Dec 10 06:55:46 LabSZ sshd[1]: Invalid user  0101 from 1.2.3.4")
    assert ev.username == " 0101"
    assert ev.src_ip == "1.2.3.4"


def test_message_inconnu():
    ev = parse_line("Dec 10 06:55:46 LabSZ sshd[1]: Server listening on 0.0.0.0 port 22.")
    assert ev.event_type == "unknown"


# l'année et le fuseau

def _ev(month_day_time="Dec 10 06:55:46"):
    return parse_line(f"{month_day_time} LabSZ sshd[1]: Connection closed by 1.2.3.4")


def test_annee_forcee():
    ts = resolve_timestamp(_ev(), reference=datetime(2026, 11, 2, tzinfo=timezone.utc), year=2017)
    assert ts == datetime(2017, 12, 10, 6, 55, 46, tzinfo=timezone.utc)


def test_annee_deduite_meme_annee():
    ref = datetime(2026, 12, 15, tzinfo=timezone.utc)
    assert resolve_timestamp(_ev(), reference=ref).year == 2026


def test_annee_deduite_date_future_recule_d_un_an():
    # lu le 2 novembre 2026, "Dec 10" ne peut être que décembre 2025
    ref = datetime(2026, 11, 2, tzinfo=timezone.utc)
    assert resolve_timestamp(_ev(), reference=ref).year == 2025


def test_29_fevrier_annee_non_bissextile():
    ref = datetime(2026, 3, 1, tzinfo=timezone.utc)
    assert resolve_timestamp(_ev("Feb 29 10:00:00"), reference=ref, year=2026) is None


# sur le vrai fichier, si je l'ai téléchargé

@pytest.mark.skipif(not DATA_FILE.exists(), reason="data/raw/OpenSSH_2k.log absent")
def test_toutes_les_lignes_du_jeu_de_donnees_sont_reconnues():
    with DATA_FILE.open(encoding="utf-8", errors="replace") as f:
        events = [parse_line(line) for line in f]
    assert len(events) == 2000
    assert all(ev is not None for ev in events)
    inconnus = [ev.message for ev in events if ev.event_type == "unknown"]
    assert inconnus == []
