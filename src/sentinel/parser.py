"""Découpe une ligne de log SSH (format syslog) en champs structurés.

Ce module ne touche pas à la base de données : il reçoit du texte et renvoie
un objet Python. C'est ce qui le rend simple à tester avec pytest.

Exemple de ligne :
    Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2
   └───── date ────┘└hôte┘└proc┘└pid┘ └───────────────────────── message ─────────────────────────────┘
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo

# Les mois sont convertis avec un dictionnaire plutôt qu'avec strptime("%b") :
# strptime dépend de la langue du système (sur un Windows en français, "Dec"
# ne serait pas reconnu, il attendrait "déc.").
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# En-tête syslog : "Dec 10 06:55:46 LabSZ sshd[24200]: <message>"
# \s+ entre le mois et le jour car syslog écrit "Dec  1" (deux espaces) pour les jours < 10.
HEADER_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$"
)

# "message repeated 5 times: [ Failed password for root from ... ]"
# syslog regroupe des messages identiques consécutifs : une ligne = N événements.
REPEATED_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<inner>.*?)\s*\]$")

PREAUTH_SUFFIX = " [preauth]"

# Liste ordonnée (type d'événement, regex). La première qui correspond gagne.
# Les noms d'utilisateur utilisent (?P<user>.*?) et non \S+ : ils sont choisis
# par l'attaquant et peuvent contenir des espaces (ex : "invalid user  0101").
MESSAGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("auth_success", re.compile(
        r"^Accepted (?P<method>\S+) for (?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)")),
    ("auth_failure", re.compile(
        r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) "
        r"from (?P<ip>\S+) port (?P<port>\d+)")),
    ("invalid_user", re.compile(
        r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?$")),
    ("invalid_user_request", re.compile(
        r"^input_userauth_request: invalid user (?P<user>.*)$")),
    ("disconnect", re.compile(
        r"^(?:error: )?Received disconnect from (?P<ip>[^\s:]+)(?: port (?P<port>\d+))?: "
        r"(?P<detail>.*)$")),
    ("connection_closed", re.compile(
        r"^Connection closed by (?P<ip>\S+)(?: port (?P<port>\d+))?$")),
    ("no_identification", re.compile(
        r"^Did not receive identification string from (?P<ip>\S+)")),
    ("reverse_mapping_failed", re.compile(
        r"^reverse mapping checking getaddrinfo for (?P<host>\S+) \[(?P<ip>[^\]]+)\] failed")),
    ("pam_auth_failure", re.compile(
        r"^pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<rhost>\S*)"
        r"(?:\s+user=(?P<user>\S+))?")),
    ("pam_unknown_user", re.compile(
        r"^pam_unix\(sshd:auth\): check pass; user unknown$")),
    ("pam_more_failures", re.compile(
        r"^PAM (?P<detail>\d+) more authentication failures?;.*?rhost=(?P<rhost>\S*)"
        r"(?:\s+user=(?P<user>\S+))?")),
    ("pam_max_retries", re.compile(
        r"^PAM service\(sshd\) ignoring max retries; (?P<detail>.*)$")),
    ("too_many_failures", re.compile(
        r"^Disconnecting: Too many authentication failures for (?P<user>.*)$")),
    ("session_opened", re.compile(
        r"^pam_unix\(sshd:session\): session opened for user (?P<user>\S+)")),
    ("session_closed", re.compile(
        r"^pam_unix\(sshd:session\): session closed for user (?P<user>\S+)")),
    ("fatal", re.compile(r"^fatal: (?P<detail>.*)$")),
]


@dataclass
class ParsedEvent:
    """Une ligne de log découpée. Les champs absents de la ligne valent None."""

    month: int
    day: int
    time: str                       # "HH:MM:SS" ; l'année est ajoutée plus tard
    host: str
    process: str
    pid: int | None
    event_type: str                 # "unknown" si aucun motif ne correspond
    message: str
    username: str | None = None
    src_ip: str | None = None       # adresse IP valide uniquement
    src_port: int | None = None
    src_host: str | None = None     # nom d'hôte quand la source n'est pas une IP
    auth_method: str | None = None  # password, publickey, none...
    invalid_user: bool | None = None
    preauth: bool = False           # message émis avant la fin de l'authentification
    repeat_count: int = 1           # > 1 pour "message repeated N times"
    detail: str | None = None       # info complémentaire (raison, compteur PAM...)


def _split_ip_or_host(value: str | None) -> tuple[str | None, str | None]:
    """Renvoie (ip, None) si value est une adresse IP, sinon (None, hostname)."""
    if not value:
        return None, None
    try:
        return str(ipaddress.ip_address(value)), None
    except ValueError:
        return None, value


def _parse_message(message: str) -> dict:
    """Identifie le type d'un message et extrait ses champs."""
    fields: dict = {"repeat_count": 1, "preauth": False}

    repeated = REPEATED_RE.match(message)
    if repeated:
        fields["repeat_count"] = int(repeated["n"])
        message = repeated["inner"]

    if message.endswith(PREAUTH_SUFFIX):
        fields["preauth"] = True
        message = message[: -len(PREAUTH_SUFFIX)]
    message = message.rstrip()

    for event_type, pattern in MESSAGE_PATTERNS:
        m = pattern.match(message)
        if not m:
            continue
        g = m.groupdict()
        fields["event_type"] = event_type
        fields["username"] = g.get("user")
        fields["auth_method"] = g.get("method")
        fields["detail"] = g.get("detail")
        if g.get("port"):
            fields["src_port"] = int(g["port"])
        if "invalid" in g:
            fields["invalid_user"] = g["invalid"] is not None
        elif event_type in ("invalid_user", "invalid_user_request"):
            fields["invalid_user"] = True

        ip, host = _split_ip_or_host(g.get("ip") or g.get("rhost"))
        fields["src_ip"] = ip
        fields["src_host"] = g.get("host") or host
        return fields

    fields["event_type"] = "unknown"
    return fields


def parse_line(line: str) -> ParsedEvent | None:
    """Découpe une ligne. Renvoie None si l'en-tête syslog n'est pas reconnu."""
    header = HEADER_RE.match(line.rstrip("\r\n"))
    if not header:
        return None

    message = header["message"]
    return ParsedEvent(
        month=MONTHS[header["month"]] if header["month"] in MONTHS else 0,
        day=int(header["day"]),
        time=header["time"],
        host=header["host"],
        process=header["process"],
        pid=int(header["pid"]) if header["pid"] else None,
        message=message.rstrip(),
        **_parse_message(message),
    )


def resolve_timestamp(
    event: ParsedEvent,
    reference: datetime,
    tz: tzinfo = timezone.utc,
    year: int | None = None,
) -> datetime | None:
    """Reconstitue la date complète d'un événement.

    syslog n'écrit ni l'année ni le fuseau horaire. Deux règles :
    - si `year` est donné, on l'utilise tel quel ;
    - sinon, on prend l'année de `reference` (la date d'ingestion), et si la
      date obtenue tombe dans le futur, on recule d'un an. C'est la règle
      utilisée par rsyslog ou Logstash : un log lu en janvier qui dit "Dec 31"
      date forcément de l'année précédente.
    """
    if not 1 <= event.month <= 12:
        return None
    hh, mm, ss = (int(x) for x in event.time.split(":"))
    y = year if year is not None else reference.year
    try:
        ts = datetime(y, event.month, event.day, hh, mm, ss, tzinfo=tz)
    except ValueError:  # ex : 29 février d'une année non bissextile
        return None
    if year is None and ts > reference + timedelta(days=1):
        ts = ts.replace(year=y - 1)
    return ts
