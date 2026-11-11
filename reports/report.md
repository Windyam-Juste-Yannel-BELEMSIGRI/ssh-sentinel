# Rapport de détection SSH

Fichier analysé : `OpenSSH_2k.log`, 2000 lignes, du 10/12/2025 06:55 au 10/12/2025 11:04 (UTC).  
Généré le 11/11/2026 avec `report.py`.

## Résumé

638 événements d'authentification, dont 528 mots de passe ratés venant de 23 adresses IP. Les détections sortent 23 alertes sur 12 IP.

Une seule connexion réussie, sans échec avant depuis la même IP.

| Détection | ATT&CK | Alertes | IP |
| --- | --- | --- | --- |
| D1 Brute force | T1110.001 | 7 | 6 |
| D2 Password spraying | T1110.003 | 5 | 4 |
| D3 Succès après échecs | T1078 | 0 | 0 |
| D4 Énumération de comptes | T1110 | 1 | 1 |
| D5 Ciblage de root | T1110 | 10 | 10 |

## IP concernées

| IP | Gravité max | Détections | Mots de passe ratés | Comptes essayés | dont inexistants | Part root | Activité |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 183.62.140.253 | high | D1, D2, D5 | 286 | 10 | 8 | 97 % | 10:54 - 11:04 |
| 187.141.143.180 | high | D1, D2, D4, D5 | 80 | 28 | 24 | 58 % | 09:12 - 09:20 |
| 103.99.0.122 | high | D1, D2, D5 | 46 | 19 | 15 | 13 % | 09:11 - 11:04 |
| 112.95.230.3 | high | D1, D5 | 26 | 3 | 2 | 92 % | 07:27 - 07:28 |
| 5.188.10.180 | high | D1, D2 | 18 | 7 | 6 | - | 08:24 - 08:26 |
| 185.190.58.151 | high | D1 | 17 | 4 | 4 | - | 09:07 - 09:12 |
| 123.235.32.19 | low | D5 | 7 | 1 | 0 | 100 % | 07:32 - 07:34 |
| 5.36.59.76 | low | D5 | 6 | 1 | 0 | 100 % | 07:13 |
| 106.5.5.195 | low | D5 | 6 | 1 | 0 | 100 % | 08:39 |
| 60.2.12.12 | low | D5 | 5 | 1 | 0 | 100 % | 10:04 - 10:05 |
| 104.192.3.34 | low | D5 | 2 | 2 | 1 | 50 % | 09:31 |
| 191.210.223.172 | low | D5 | 1 | 1 | 0 | 100 % | 07:48 |

DNS inverse incohérent (`POSSIBLE BREAK-IN ATTEMPT!`) : 187.141.143.180 (`customer-187-141-143-180-sta.uninet-ide.com.mx`), 191.210.223.172 (`191-210-223-172.user.vivozap.com.br`).

## Connexions réussies

| Compte | IP | Heure | Échecs avant depuis cette IP | D3 |
| --- | --- | --- | --- | --- |
| fztu | 119.137.62.142 | 09:32:20 | 0 | non |

## Détail des alertes

| | Gravité | IP | Fenêtre | Détail |
| --- | --- | --- | --- | --- |
| D1 | high | 183.62.140.253 | 10:54 - 11:04 | 147 mots de passe ratés au pic sur 5 min, 286 sur l'épisode |
| D1 | high | 187.141.143.180 | 09:12 - 09:20 | 57 mots de passe ratés au pic sur 5 min, 80 sur l'épisode |
| D1 | high | 103.99.0.122 | 09:11 - 09:12 | 30 mots de passe ratés au pic sur 5 min, 30 sur l'épisode |
| D1 | high | 112.95.230.3 | 07:27 - 07:28 | 26 mots de passe ratés au pic sur 5 min, 26 sur l'épisode |
| D1 | high | 5.188.10.180 | 08:24 - 08:26 | 18 mots de passe ratés au pic sur 5 min, 18 sur l'épisode |
| D1 | high | 185.190.58.151 | 09:07 - 09:12 | 16 mots de passe ratés au pic sur 5 min, 17 sur l'épisode |
| D1 | high | 103.99.0.122 | 11:03 - 11:04 | 16 mots de passe ratés au pic sur 5 min, 16 sur l'épisode |
| D2 | medium | 187.141.143.180 | 09:12 - 09:20 | 28 comptes distincts au pic sur 10 min, 28 sur l'épisode |
| D2 | medium | 103.99.0.122 | 09:11 - 09:12 | 19 comptes distincts au pic sur 10 min, 19 sur l'épisode |
| D2 | medium | 103.99.0.122 | 11:03 - 11:04 | 12 comptes distincts au pic sur 10 min, 12 sur l'épisode |
| D2 | medium | 183.62.140.253 | 10:54 - 11:04 | 10 comptes distincts au pic sur 10 min, 10 sur l'épisode |
| D2 | medium | 5.188.10.180 | 08:24 - 08:26 | 7 comptes distincts au pic sur 10 min, 7 sur l'épisode |
| D4 | medium | 187.141.143.180 | 09:16 - 09:20 | 24 comptes inexistants essayés (ex. : abc, bssh, butter, cyrus, deploy, eoor, ghost, ingrid, jay, magnos) |
| D5 | medium | 183.62.140.253 | 10:54 - 11:04 | 276 échecs sur root, 97 % de ses échecs visent root |
| D5 | medium | 187.141.143.180 | 09:12 - 09:16 | 46 échecs sur root, 58 % de ses échecs visent root |
| D5 | medium | 112.95.230.3 | 07:27 - 07:28 | 24 échecs sur root, 92 % de ses échecs visent root |
| D5 | low | 123.235.32.19 | 07:32 - 07:34 | 7 échecs sur root, 100 % de ses échecs visent root |
| D5 | low | 5.36.59.76 | 07:13 | 6 échecs sur root, 100 % de ses échecs visent root |
| D5 | low | 103.99.0.122 | 09:11 - 11:04 | 6 échecs sur root, 13 % de ses échecs visent root |
| D5 | low | 106.5.5.195 | 08:39 | 6 échecs sur root, 100 % de ses échecs visent root |
| D5 | low | 60.2.12.12 | 10:04 - 10:05 | 5 échecs sur root, 100 % de ses échecs visent root |
| D5 | low | 104.192.3.34 | 09:31 | 1 échec sur root, 50 % de ses échecs visent root |
| D5 | low | 191.210.223.172 | 07:48 | 1 échec sur root, 100 % de ses échecs visent root |

Les règles et leurs seuils sont décrits dans le README (section `detect`).
