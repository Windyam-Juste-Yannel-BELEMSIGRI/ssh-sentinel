# ssh-sentinel

Pipeline qui charge des logs d'authentification SSH dans PostgreSQL et qui doit y détecter les attaques (brute force, password spraying, compte compromis) avec des requêtes SQL.
Avant de détecter quoi que ce soit, il faut que les logs soient chargés proprement, découpés et fiables. Donc il y a deux étapes importantes:
- Etape 1 qui regroupe les données, leurs traitements, leur stockage structurée (ingestion, couches, idempotence)
- Etape 2 qui regroupe les analyses SOC (lire les logs, écrire les règles, les relier à MITRE ATT&CK).

---

## Comment c'est organisé

```
OpenSSH_2k.log ──> load_raw.py ──> raw.auth_lines
                                          │
                                     load_stg.py ──> stg.auth_events
                                                           │
                                                     load_mart.py ──> mart (dim_ip, dim_user, fact_auth_event)
                                                                                 │
                                                                            detect.py ──> detect (vues D1 à D5 + detect.alerts)
                                                                                                     │
                                                                                                report.py ──> reports/report.md
```

Tout tourne dans PostgreSQL 16 sous Docker, sur le port **5433**.

| Couche | Ce qu'il y a dedans | État |
| --- | --- | --- |
| `raw` | Chaque ligne du fichier telle quelle, jamais modifiée | fait |
| `stg` | La ligne découpée : date, hôte, PID, type d'événement, user, IP, port... | fait |
| `mart` | Modèle en étoile : `fact_auth_event`, `dim_ip`, `dim_user` | fait |
| `detect` | Des vues SQL qui sortent les alertes (D1 à D5) | fait |

Pourquoi garder `raw` : si mon parser a un bug, je le corrige et je relance `load_stg.py`, pas besoin de recharger le fichier.

---

## Relancer le projet

Il faut Docker Desktop (lancé, sinon erreur `dockerDesktopLinuxEngine`), Python 3.13 et Git Bash.

```bash
docker compose up -d

python -m venv .venv
source .venv/Scripts/activate        # sous Linux : source .venv/bin/activate
pip install -r requirements.txt

# les logs (pas dans git)
mkdir -p data/raw
curl -L -o data/raw/OpenSSH_2k.log https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log

python src/sentinel/load_raw.py data/raw/OpenSSH_2k.log   # -> 2000 lignes chargées
python src/sentinel/load_stg.py                           # -> 2000 lignes traitées, 0 non reconnue
python src/sentinel/load_mart.py                          # -> 30 IP, 64 users, 638 événements
python src/sentinel/detect.py                             # -> 23 alertes
python src/sentinel/report.py                             # -> reports/report.md
pytest                                                    # 60 tests (test_mart.py et test_detections.py ont besoin de la base)
```

Vérifier dans la base :

```bash
docker compose exec db psql -U sentinel -c "SELECT count(*) FROM raw.auth_lines;"
docker compose exec db psql -U sentinel -c "SELECT event_type, count(*) FROM stg.auth_events GROUP BY 1 ORDER BY 2 DESC;"
docker compose exec db psql -U sentinel -c "SELECT event_type, count(*), sum(attempts) FROM mart.fact_auth_event GROUP BY 1;"
docker compose exec db psql -U sentinel -c "SELECT detection, severity, host(src_ip), detail FROM detect.alerts;"
```

**Attention :** les scripts de `sql/` ne s'exécutent qu'au tout premier démarrage de la base. Si j'ajoute un fichier SQL et que la base existe déjà, il faut le lancer à la main :

```bash
docker compose exec -T db psql -U sentinel < sql/002_stg.sql
```

Ou repartir de zéro avec `docker compose down -v` (ça efface les données).

Pour `003_mart.sql` et `004_detections.sql` je n'ai plus ce problème : `load_mart.py` et `detect.py` lancent eux-mêmes leur fichier (tables en `IF NOT EXISTS`, vues recréées à chaque fois).

---

## Les données

Fichier OpenSSH de [Loghub](https://github.com/logpai/loghub) : 2000 lignes de vrais logs d'un serveur SSH exposé sur Internet, toutes du 10 décembre. Le dossier `data/` est dans le `.gitignore`.

```
Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2
```

---

## Ce que j'ai vu en analysant les logs à la main

Avant de coder j'ai regardé le fichier avec `grep`, `cut`, `sort`, `uniq` (à lancer dans Git Bash, pas PowerShell).

**Une seule connexion réussie** sur 2000 lignes :

```bash
grep -c "Accepted password" data/raw/OpenSSH_2k.log   # 1
```

C'est `fztu` depuis `119.137.62.142` à 09:32:20, déconnexion normale à 09:45:06. Cette IP n'a aucun échec avant, donc rien de suspect dans ces données. Mais pas d'échec ne veut pas dire légitime : quelqu'un avec un mot de passe volé passe du premier coup. La détection D3 cherche l'inverse (succès après plein d'échecs).

**Les IP qui attaquent le plus :**

```bash
grep "Failed password" data/raw/OpenSSH_2k.log | grep -oE "from [0-9.]+" | cut -d' ' -f2 | sort | uniq -c | sort -rn | head -5
```

| IP | Échecs |
| --- | --- |
| 183.62.140.253 | 286 |
| 187.141.143.180 | 80 |
| 103.99.0.122 | 46 |
| 112.95.230.3 | 26 |
| 5.188.10.180 | 18 |

23 IP en tout, la première fait 55 % des échecs à elle seule. Peu de sources qui concentrent tout = brute force (T1110).

**Une tentative = plusieurs lignes.** SSH écrit `Failed password`, PAM écrit `authentication failure`. Compter les lignes ne revient pas à compter les attaques. Et couper le texte à longueur fixe (`cut -c1-40`) tronque les IP. D'où le parser avec une regex par champ.

---

## Le parser

`parser.py` ne touche pas à la base : il prend une ligne, il renvoie un objet. Comme ça je le teste avec pytest sans PostgreSQL. Une regex pour l'en-tête syslog (date, hôte, processus, PID), puis une liste de regex pour le message : la première qui matche donne le type.

Résultat sur le fichier : 2000 lignes reconnues, 16 types.

| Type | Lignes | Message |
| --- | --- | --- |
| `auth_failure` | 524 | `Failed password for root from ... port ... ssh2` |
| `pam_auth_failure` | 494 | `pam_unix(sshd:auth): authentication failure; ... rhost=...` |
| `disconnect` | 468 | `Received disconnect from ...: 11: Bye Bye` |
| `pam_unknown_user` | 135 | `check pass; user unknown` |
| `invalid_user` | 113 | `Invalid user webmaster from ...` |
| `invalid_user_request` | 113 | `input_userauth_request: invalid user webmaster` |
| `reverse_mapping_failed` | 85 | `reverse mapping checking getaddrinfo ... POSSIBLE BREAK-IN ATTEMPT!` |
| `connection_closed` | 34 | `Connection closed by ...` |
| les 8 autres | 34 | succès, sessions, `Too many authentication failures`, `fatal`... |

Les pièges que j'ai dû gérer :

- **`message repeated 5 times: [ Failed password ... ]`** : syslog regroupe les messages identiques, une ligne = 5 échecs. Je garde le nombre dans `repeat_count`. Au final **528 vraies tentatives** pour 520 lignes, mon `grep` sous-estimait.
- **Les noms d'utilisateur viennent de l'attaquant**, il peut y avoir des espaces (`invalid user  0101`). La regex prend tout jusqu'à ` from ` au lieu de `\S+`.
- **Pas d'année ni de fuseau dans syslog** (`Dec 10 06:55:46`). Par défaut je prends l'année de la date d'ingestion, et si ça tombe dans le futur je recule d'un an (même règle que rsyslog / Logstash). Lu en novembre 2026, ça donne décembre 2025. `--year 2017` force l'année, `--tz Europe/Paris` change le fuseau (UTC par défaut).
- **Les mois** : je passe par un dictionnaire et pas `strptime("%b")`, qui dépend de la langue du système. Sur mon Windows en français, `Dec` ne serait pas reconnu.

---

## Le modèle en étoile (`mart`)

```
        dim_ip                         dim_user
  (une ligne par IP)          (une ligne par nom tenté)
          \                             /
           \---- fact_auth_event ------/
             (une ligne par événement d'authentification sshd)
```

**Le grain**, c'est la décision la plus importante : une ligne de `fact_auth_event` = un événement d'authentification écrit par **sshd**. Je garde seulement 3 types :

| Type | Lignes | Tentatives (`sum(attempts)`) |
| --- | --- | --- |
| `auth_failure` (password) | 520 | 528 |
| `auth_failure` (none) | 4 | 4 |
| `invalid_user` | 113 | 113 |
| `auth_success` | 1 | 1 |

Total : 638 lignes.

Ce que je laisse de côté, et pourquoi :
- **Les lignes PAM** (`pam_auth_failure`, `pam_more_failures`...) : elles répètent les échecs déjà écrits par sshd. Si je les gardais, chaque tentative compterait double dans D1. Un test vérifie qu'il n'y en a aucune dans les faits.
- **`invalid_user_request`** : même info que `invalid_user` (113 de chaque), une seule suffit.
- **Les déconnexions, `reverse_mapping_failed`...** : pas des tentatives, mais je m'en sers pour remplir les dimensions.

`attempts` reprend `repeat_count` : la ligne `message repeated 5 times` vaut 5. **Pour compter les tentatives, toujours `sum(attempts)`, jamais `count(*)`.** Et pour D1 filtrer sur `auth_method = 'password'` : les 4 `Failed none` sont des sondes du client SSH, pas des mots de passe essayés.

**`dim_ip`** (30 IP) : première et dernière apparition, et deux infos que je récupère des autres lignes de `stg` :
- `ptr_host` + `reverse_dns_mismatch` : le DNS inverse de l'IP ne correspond pas (`POSSIBLE BREAK-IN ATTEMPT!`). 4 IP, dont `187.141.143.180`, la 2e plus agressive ;
- `is_private` : IP en 10/8, 172.16/12 ou 192.168/16. Aucune ici, mais ça servira pour l'attaque Hydra entre mes VM.

**`dim_user`** (64 noms) : `is_root`, et `account_exists`, est-ce que le compte existe vraiment sur le serveur :
- **oui** si je le vois dans une connexion réussie, une session, un échec PAM (PAM ne parle que des comptes qu'il connaît) ou un `Failed password for X` sans `invalid user` ;
- **non** s'il n'apparaît qu'en `invalid user` ;
- **NULL** si je ne peux pas savoir.

Résultat : 7 comptes qui existent (`root`, `fztu`, `ftp`, `git`, `mysql`, `sshd`, `uucp`), 57 qui n'existent pas. C'est ça qui rend D4 (énumération) possible.

`session_pid` dans les faits garde le PID sshd : toutes les lignes d'une même connexion ont le même, ça permettra de reconstituer une session.

**Comment c'est chargé.** `load_mart.py` n'envoie que du SQL, dans une seule transaction (soit tout passe, soit rien) :
1. créer les tables si besoin (`003_mart.sql`) ;
2. supprimer les faits dont la ligne `stg` n'est plus un événement retenu (si je corrige le parser et qu'un type change) ;
3. upsert de `dim_ip`, puis de `dim_user` ;
4. upsert de `fact_auth_event`, en joignant `stg` aux dimensions pour récupérer les clés.

L'ordre compte : les faits ont besoin des clés des dimensions. Relancé deux fois, rien ne bouge (testé).

**Premiers essais des détections**, pour vérifier que le modèle tient (les vues sont dans la section suivante) :
- D1 : 6 IP dépassent 10 échecs en 5 min. `183.62.140.253` monte à **147 en 5 min**.
- D4 : `187.141.143.180` a essayé **24 comptes inexistants**, `103.99.0.122` en a essayé 15.
- D5 : `183.62.140.253` a fait 276 tentatives sur root. Elle ne vise presque que root, alors que `187.141.143.180` essaie plein de noms : deux façons d'attaquer différentes.
- D3 : la seule connexion réussie (`fztu`) n'a eu aucun échec dans les 30 min avant. Ça confirme ce que j'avais vu à la main.

---

## Les détections (`detect`)

`sql/004_detections.sql` crée un schéma `detect` qui ne contient **que des vues** : aucune donnée n'y est stockée, donc le fichier commence par `DROP SCHEMA detect CASCADE` et recrée tout. Comme ça je peux changer les colonnes d'une vue sans me battre avec `CREATE OR REPLACE VIEW` (qui refuse). `detect.py` lance le fichier puis affiche les alertes.

| # | Vue | Règle | ATT&CK | Gravité | Alertes |
| --- | --- | --- | --- | --- | --- |
| D1 | `d1_brute_force` | 10 mots de passe ratés ou plus depuis une IP en 5 min | T1110.001 | high | 7 (6 IP) |
| D2 | `d2_password_spraying` | 5 comptes distincts ou plus depuis une IP en 10 min | T1110.003 | medium | 5 (4 IP) |
| D3 | `d3_success_after_failures` | Connexion réussie après 5 échecs de la même IP en 30 min | T1078 | critical | 0 |
| D4 | `d4_user_enumeration` | 20 comptes inexistants ou plus depuis une IP | T1110 | medium | 1 |
| D5 | `d5_root_targeting` | Toute tentative sur root, par IP | T1110 | low → critical | 10 |

`detect.alerts` met les 5 vues au même format (détection, technique, gravité, IP, user, début, fin, score, détail en français). C'est elle que lit le rapport.

Le rapport (`reports/report.md`) est écrit par `report.py`, uniquement à partir de la base : résumé, alertes par détection, une ligne par IP avec toutes ses détections (pour ne pas lire trois fois la même attaque), les connexions réussies et le détail des alertes. [Le rapport sur OpenSSH_2k.log](reports/report.md).

**Comment ça marche :**

- **D1** : `sum(attempts) OVER (PARTITION BY ip ORDER BY event_ts RANGE BETWEEN '5 minutes' PRECEDING AND CURRENT ROW)`. `RANGE` et pas `ROWS` : la fenêtre est en temps, pas en nombre de lignes. Seulement `auth_method = 'password'` (pas les sondes `none`).
- **Épisodes** : sans ça, une IP qui fait 286 échecs donnerait des centaines d'alertes (une par ligne au-dessus du seuil). Je regroupe les déclenchements : nouvel épisode si plus de 5 min séparent deux déclenchements (technique *gaps and islands* : `lag()` puis somme cumulée). `103.99.0.122` attaque deux fois à 2 h d'écart → 2 alertes.
- **D2** : PostgreSQL ne sait pas faire `count(DISTINCT ...)` en fonction de fenêtre. Je passe par un `LATERAL` qui compte, pour chaque événement, les comptes distincts de la même IP dans les 10 min d'avant. Je prends les `auth_failure` et les `invalid_user` (distincts, donc pas de double compte).
- **D3** : pour chaque `auth_success`, un `LATERAL` additionne les échecs de la même IP dans les 30 min d'avant. `same_user_failed` dit si le compte qui a réussi faisait partie des comptes ratés (mot de passe deviné) ou pas (l'attaquant a peut-être un autre accès).
- **D4** : pas de fenêtre, toute la période. Repose sur `dim_user.account_exists = false`.
- **D5** : seuil à 1. `root_ratio` = part des échecs de l'IP qui visent root. Gravité `critical` s'il y a un succès sur root, `medium` à partir de 10 échecs, `low` sinon.

**Ce que ça donne sur le fichier :** 23 alertes. Les 4 grosses IP de mon analyse à la main sont toutes là. `187.141.143.180` sonne sur D1, D2, D4 et D5 : c'est l'IP la plus complète (et celle qui a un DNS inverse faux). D3 ne sonne pas, comme prévu (`fztu` n'a aucun échec avant).

**Limites que j'ai vues :**

- **D1 et D2 se recoupent** : un brute force sur une liste de noms coche les deux. Normal, c'est le même attaquant vu sous deux angles. Le rapport devra regrouper par IP.
- **`183.62.140.253` sort en D2** (10 comptes en 10 min) alors que 97 % de ses essais visent root : c'est du brute force, pas du spraying. Sans les mots de passe dans les logs, je ne peux pas voir le vrai spraying (« un mot de passe, plein de comptes »). On pourrait exiger un `root_ratio` faible pour D2, à voir avec plus de données.
- Les seuils sont en dur dans une CTE `params` au début de chaque vue. Pour les régler il faut modifier le SQL.

**Les tests** (`test_detections.py`, 20 tests) : 6 sur les vraies données (les chiffres du README) et 14 sur des événements **fictifs**. Ceux-là insèrent une IP de documentation (`198.51.100.7`, RFC 5737) et des faits, lisent la vue, puis font un `rollback` : la base n'est jamais modifiée. C'est comme ça que je teste D3 (qui ne sonne pas sur le fichier) et les effets de seuil : 9 échecs ne sonnent pas, 10 oui ; 2 lignes `repeated 5 times` sonnent ; 10 échecs étalés sur 10 min ne sonnent pas ; 4 échecs avant un succès non, 5 oui ; échecs 40 min avant le succès non.

---

## Pourquoi j'ai fait ces choix

- **PostgreSQL** : les fonctions de fenêtrage (`OVER ... RANGE INTERVAL`) sont parfaites pour « N échecs en 5 minutes ».
- **Docker Compose** : la base se lance en une commande, pareil sur n'importe quelle machine.
- **Chargement et parsing séparés** : `load_raw.py` copie, `parser.py` interprète. Un fichier = une responsabilité, plus simple à tester.
- **Requêtes paramétrées (`%s`)** : jamais de valeur collée dans le SQL, pas d'injection.
- **`raw` en `DO NOTHING`, `stg` en `DO UPDATE`** : dans `raw` une ligne déjà là est ignorée. Dans `stg` elle est mise à jour, comme ça si je corrige le parser je relance et `stg` est corrigé.
- **Type `inet` pour les IP** : PostgreSQL valide l'adresse, et je peux chercher par sous-réseau (`src_ip << '183.62.0.0/16'`).
- **La transformation `stg` -> `mart` en SQL, pas en Python** : les données restent dans la base, PostgreSQL fait les `GROUP BY` et les jointures bien mieux qu'une boucle Python.
- **Clés de substitution (`ip_key`, `user_key`)** dans les dimensions : un entier est plus léger à joindre qu'un texte, et les faits ne dépendent pas du format de l'IP ou du nom.
- **Pas de `dim_date`** : tout le fichier est sur une seule journée, et les détections travaillent sur des fenêtres de quelques minutes directement sur `event_ts`. À ajouter si je charge plusieurs mois de logs.
- **`event_type` reste en texte dans les faits** (dimension dégénérée) : 3 valeurs, une table à part n'apporterait rien. Un `CHECK` empêche d'y mettre autre chose.

---

## Galères et solutions

| Problème | Cause | Ce que j'ai fait |
| --- | --- | --- |
| `services.ports must be a mapping` | Mauvaise indentation YAML | `ports` et `volumes` au même niveau que `image` |
| `address already in use` sur 5432 | Un PostgreSQL local tournait déjà (Fedora) | Conteneur exposé sur **5433** |
| Conteneur qui s'arrête, `Permission denied` sur `/docker-entrypoint-initdb.d/` | SELinux sur Fedora bloque le dossier monté | `:Z` à la fin du volume. Sous Windows Docker l'ignore |
| 4000 lignes au 2e chargement au lieu de 2000 | Rien n'empêchait les doublons | `UNIQUE (source_file, line_no)` + `ON CONFLICT DO NOTHING` |
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop pas lancé | Ouvrir Docker Desktop et attendre « Engine running » |
| `py -3.13` : `No suitable Python runtime found` | Python 3.13 pas installé, j'avais que la 3.15 | `winget install Python.Python.3.13` puis recréer le venv |
| Fichier téléchargé nommé `datarawOpenSSH_2k.log` | J'ai tapé `data\raw\...` dans Git Bash, les `\` sont des échappements en bash | Toujours `/` dans Git Bash |
| `relation "stg.auth_events" does not exist` | La base existait avant `002_stg.sql`, il n'a pas été lancé | `docker compose exec -T db psql -U sentinel < sql/002_stg.sql` |

**L'idempotence**, pour m'en souvenir : un script idempotent peut être relancé autant de fois que je veux, le résultat est le même qu'après une seule fois. Sans ça chaque ligne compte double et toutes les détections sont faussées. 1re exécution : 2000 insérées. 2e : 0. La table reste à 2000.

---

## Fichiers

```
ssh-sentinel/
├── docker-compose.yml        # PostgreSQL 16, port 5433
├── requirements.txt          # psycopg, tzdata, pytest
├── pyproject.toml            # config pytest (src/ dans le path)
├── sql/
│   ├── 001_schemas.sql       # schémas raw, stg, mart + raw.auth_lines
│   ├── 002_stg.sql           # stg.auth_events
│   ├── 003_mart.sql          # dim_ip, dim_user, fact_auth_event
│   └── 004_detections.sql    # vues D1 à D5 + detect.alerts
├── src/sentinel/
│   ├── load_raw.py           # fichier -> raw.auth_lines
│   ├── parser.py             # ligne -> champs (regex, sans base)
│   ├── load_stg.py           # raw -> stg.auth_events
│   ├── load_mart.py          # stg -> mart (SQL, une transaction)
│   ├── detect.py             # crée les vues et affiche les alertes
│   └── report.py             # écrit reports/report.md
├── reports/
│   └── report.md             # rapport sur OpenSSH_2k.log
├── tests/
│   ├── test_parser.py        # 32 tests, sans base
│   ├── test_mart.py          # 8 tests, avec la base (ignorés si elle est éteinte)
│   └── test_detections.py    # 20 tests, avec la base (faux événements annulés par rollback)
└── data/raw/                 # logs, pas dans git
```

---

## Ce qu'il reste à faire

- [x] Docker + PostgreSQL, schémas `raw`, `stg`, `mart`
- [x] Analyse à la main avec les outils Unix
- [x] Chargement brut idempotent
- [x] Parser regex + tests pytest
- [x] Année et fuseau horaire
- [x] Modèle en étoile dans `mart` + tests
- [ ] Comparer `INSERT` et `COPY` sur le jeu complet (~655 000 lignes)
- [x] Les 5 détections (voir la section `detect`) :

| # | Détection | Règle de départ | ATT&CK |
| --- | --- | --- | --- |
| D1 | Brute force | 10 échecs ou plus depuis une IP en 5 min | T1110.001 |
| D2 | Password spraying | 5 comptes distincts ou plus depuis une IP en 10 min | T1110.003 |
| D3 | Succès après échecs | Connexion réussie après 5 échecs de la même IP en 30 min | T1078 |
| D4 | Énumération de comptes | 20 users inexistants ou plus depuis une IP | T1110 |
| D5 | Ciblage de root | Toute tentative sur root, groupée par IP | T1110 |

Écrites en vues SQL dans `sql/004_detections.sql`, testées avec des faux événements.

- [ ] Attaque simulée avec Hydra entre mes propres VM, vérifier que D1 et D3 sonnent
- [x] Rapport généré automatiquement (`reports/report.md`)
