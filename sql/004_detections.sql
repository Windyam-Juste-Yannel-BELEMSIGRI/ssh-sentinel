-- Détections SOC sur le modèle en étoile (mart).
--
-- Le schéma detect ne contient QUE des vues : aucune donnée n'y est stockée.
-- On peut donc le supprimer et le recréer à chaque fois, ce qui rend le fichier
-- rejouable même si une vue change de colonnes (CREATE OR REPLACE VIEW refuse ça).
-- Ne jamais mettre de table dans ce schéma.
--
-- Règles communes :
-- - compter les tentatives avec sum(attempts), jamais count(*) :
--   une ligne "message repeated 5 times" vaut 5 ;
-- - les échecs "Failed none" sont des sondes du client SSH, pas des mots de
--   passe essayés : D1 et D3 ne gardent que auth_method = 'password'.
--
-- Les seuils sont écrits en dur au début de chaque vue (CTE params).

DROP SCHEMA IF EXISTS detect CASCADE;
CREATE SCHEMA detect;

-- Tous les faits avec l'IP et le nom en clair : évite de refaire les jointures
-- dans chaque détection.
CREATE VIEW detect.auth_events AS
SELECT
  f.source_file, f.line_no, f.event_ts, f.event_type, f.auth_method, f.attempts,
  f.session_pid, f.ip_key, i.src_ip, f.user_key, u.username, u.is_root, u.account_exists
FROM mart.fact_auth_event f
JOIN mart.dim_ip i ON i.ip_key = f.ip_key
LEFT JOIN mart.dim_user u ON u.user_key = f.user_key;


-- D1 - Brute force (T1110.001)
-- 10 mots de passe ratés ou plus depuis une IP en 5 minutes.
--
-- Pour chaque échec on calcule la somme des tentatives de la même IP sur les
-- 5 minutes qui précèdent (fenêtre RANGE sur le temps, pas sur les lignes).
-- Les échecs qui dépassent le seuil sont ensuite regroupés en épisodes : un
-- nouvel épisode commence quand plus de 5 minutes séparent deux déclenchements.
-- Une IP qui attaque en continu donne donc une seule alerte, pas une par ligne.
CREATE VIEW detect.d1_brute_force AS
WITH params AS (SELECT 10 AS threshold, interval '5 minutes' AS win),
failures AS (
  SELECT e.ip_key, e.src_ip, e.event_ts, e.attempts,
         sum(e.attempts) OVER (
           PARTITION BY e.ip_key ORDER BY e.event_ts
           RANGE BETWEEN interval '5 minutes' PRECEDING AND CURRENT ROW
         ) AS attempts_5min
  FROM detect.auth_events e
  WHERE e.event_type = 'auth_failure' AND e.auth_method = 'password'
),
triggers AS (
  SELECT f.*,
         CASE WHEN f.event_ts - lag(f.event_ts) OVER (PARTITION BY f.ip_key ORDER BY f.event_ts)
                   <= (SELECT win FROM params)
              THEN 0 ELSE 1 END AS new_episode
  FROM failures f
  WHERE f.attempts_5min >= (SELECT threshold FROM params)
),
episodes AS (
  SELECT t.*, sum(t.new_episode) OVER (PARTITION BY t.ip_key ORDER BY t.event_ts) AS episode
  FROM triggers t
),
-- Un épisode couvre les échecs entre (1er déclenchement - 5 min) et le dernier
-- déclenchement : on y relit les vrais échecs pour avoir la vraie heure de début.
grouped AS (
  SELECT ep.ip_key, ep.src_ip,
         min(ep.event_ts) - (SELECT win FROM params) AS span_start,
         max(ep.event_ts)                            AS span_end,
         max(ep.attempts_5min)                       AS peak_attempts_5min
  FROM episodes ep
  GROUP BY ep.ip_key, ep.src_ip, ep.episode
)
SELECT
  g.src_ip,
  s.window_start,
  g.span_end                                  AS window_end,
  g.peak_attempts_5min,
  s.attempts
FROM grouped g
CROSS JOIN LATERAL (
  SELECT min(f.event_ts) AS window_start, sum(f.attempts) AS attempts
  FROM failures f
  WHERE f.ip_key = g.ip_key AND f.event_ts > g.span_start AND f.event_ts <= g.span_end
) s;


-- D2 - Password spraying (T1110.003)
-- 5 comptes distincts ou plus essayés depuis une IP en 10 minutes.
--
-- Les logs ne contiennent pas les mots de passe : on ne peut pas voir "un même
-- mot de passe sur plein de comptes". On approche ça par "beaucoup de comptes
-- différents en peu de temps". Recoupe forcément un peu D4.
-- count(DISTINCT) n'existe pas en fonction de fenêtre dans PostgreSQL, d'où la
-- sous-requête LATERAL sur les 10 minutes qui précèdent chaque événement.
CREATE VIEW detect.d2_password_spraying AS
WITH params AS (SELECT 5 AS threshold, interval '10 minutes' AS win),
attempts AS (
  SELECT e.ip_key, e.src_ip, e.event_ts, e.user_key, e.username
  FROM detect.auth_events e
  WHERE e.event_type IN ('auth_failure', 'invalid_user') AND e.user_key IS NOT NULL
),
scored AS (
  SELECT a.ip_key, a.src_ip, a.event_ts, w.distinct_users
  FROM attempts a
  CROSS JOIN LATERAL (
    SELECT count(DISTINCT b.user_key) AS distinct_users
    FROM attempts b
    WHERE b.ip_key = a.ip_key
      AND b.event_ts >  a.event_ts - (SELECT win FROM params)
      AND b.event_ts <= a.event_ts
  ) w
),
triggers AS (
  SELECT s.*,
         CASE WHEN s.event_ts - lag(s.event_ts) OVER (PARTITION BY s.ip_key ORDER BY s.event_ts)
                   <= (SELECT win FROM params)
              THEN 0 ELSE 1 END AS new_episode
  FROM scored s
  WHERE s.distinct_users >= (SELECT threshold FROM params)
),
episodes AS (
  SELECT t.*, sum(t.new_episode) OVER (PARTITION BY t.ip_key ORDER BY t.event_ts) AS episode
  FROM triggers t
),
grouped AS (
  SELECT ep.ip_key, ep.src_ip,
         min(ep.event_ts) - (SELECT win FROM params) AS span_start,
         max(ep.event_ts)                            AS span_end,
         max(ep.distinct_users)                      AS peak_users_10min
  FROM episodes ep
  GROUP BY ep.ip_key, ep.src_ip, ep.episode
)
SELECT
  g.src_ip,
  s.window_start,
  g.span_end                                  AS window_end,
  g.peak_users_10min,
  s.distinct_users
FROM grouped g
CROSS JOIN LATERAL (
  SELECT min(a.event_ts) AS window_start, count(DISTINCT a.user_key) AS distinct_users
  FROM attempts a
  WHERE a.ip_key = g.ip_key AND a.event_ts > g.span_start AND a.event_ts <= g.span_end
) s;


-- D3 - Succès après échecs (T1078)
-- Une connexion réussie alors que la même IP a raté 5 mots de passe ou plus
-- dans les 30 minutes avant : le mot de passe a peut-être été trouvé.
-- C'est la détection la plus grave : D1 dit "on essaie", D3 dit "ça a marché".
CREATE VIEW detect.d3_success_after_failures AS
WITH params AS (SELECT 5 AS threshold, interval '30 minutes' AS win)
SELECT
  s.src_ip,
  s.username,
  s.event_ts                                  AS success_ts,
  s.session_pid,
  p.failed_attempts,
  p.failed_users,
  p.first_failure_ts,
  p.failed_users @> ARRAY[s.username]         AS same_user_failed
FROM detect.auth_events s
CROSS JOIN LATERAL (
  SELECT sum(f.attempts)                      AS failed_attempts,
         array_agg(DISTINCT f.username)       AS failed_users,
         min(f.event_ts)                      AS first_failure_ts
  FROM detect.auth_events f
  WHERE f.ip_key = s.ip_key
    AND f.event_type = 'auth_failure' AND f.auth_method = 'password'
    AND f.event_ts >= s.event_ts - (SELECT win FROM params)
    AND f.event_ts <  s.event_ts
) p
WHERE s.event_type = 'auth_success'
  AND p.failed_attempts >= (SELECT threshold FROM params);


-- D4 - Énumération de comptes (T1110)
-- 20 noms d'utilisateur inexistants ou plus essayés depuis une IP, sur toute
-- la période. L'attaquant teste une liste de noms (admin, test, oracle...)
-- pour trouver ceux qui existent. Repose sur dim_user.account_exists.
CREATE VIEW detect.d4_user_enumeration AS
WITH params AS (SELECT 20 AS threshold)
SELECT
  e.src_ip,
  min(e.event_ts)                             AS window_start,
  max(e.event_ts)                             AS window_end,
  count(DISTINCT e.user_key)                  AS unknown_users,
  (array_agg(DISTINCT e.username))[1:10]      AS sample_users
FROM detect.auth_events e
WHERE e.account_exists = false
GROUP BY e.ip_key, e.src_ip
HAVING count(DISTINCT e.user_key) >= (SELECT threshold FROM params);


-- D5 - Ciblage de root (T1110)
-- Toute tentative sur root, groupée par IP. Seuil à 1 : sur un serveur bien
-- configuré (PermitRootLogin no) personne de légitime ne tente root par mot de
-- passe. root_ratio distingue une IP qui ne vise que root (outil de brute
-- force) d'une IP qui essaie une liste de noms et root parmi d'autres.
CREATE VIEW detect.d5_root_targeting AS
WITH by_ip AS (
  SELECT
    e.ip_key, e.src_ip,
    sum(e.attempts) FILTER (WHERE e.is_root AND e.event_type = 'auth_failure') AS root_failures,
    count(*)        FILTER (WHERE e.is_root AND e.event_type = 'auth_success') AS root_successes,
    sum(e.attempts) FILTER (WHERE e.event_type = 'auth_failure')               AS all_failures,
    min(e.event_ts) FILTER (WHERE e.is_root)                                   AS window_start,
    max(e.event_ts) FILTER (WHERE e.is_root)                                   AS window_end
  FROM detect.auth_events e
  WHERE e.event_type IN ('auth_failure', 'auth_success')
  GROUP BY e.ip_key, e.src_ip
)
SELECT
  src_ip, window_start, window_end,
  coalesce(root_failures, 0)                  AS root_failures,
  root_successes,
  round(coalesce(root_failures, 0)::numeric / nullif(all_failures, 0), 2) AS root_ratio
FROM by_ip
WHERE coalesce(root_failures, 0) + root_successes > 0;


-- Toutes les alertes dans un format commun, pour le rapport.
-- severity : critical > high > medium > low.
CREATE VIEW detect.alerts AS
SELECT 'D1' AS detection, 'Brute force' AS name, 'T1110.001' AS attack_technique,
       'high' AS severity, src_ip, NULL::text AS username,
       window_start, window_end, attempts::bigint AS score,
       format('%s mots de passe ratés au pic sur 5 min, %s sur l''épisode',
              peak_attempts_5min, attempts) AS detail
FROM detect.d1_brute_force
UNION ALL
SELECT 'D2', 'Password spraying', 'T1110.003', 'medium', src_ip, NULL,
       window_start, window_end, distinct_users,
       format('%s comptes distincts au pic sur 10 min, %s sur l''épisode',
              peak_users_10min, distinct_users)
FROM detect.d2_password_spraying
UNION ALL
SELECT 'D3', 'Succès après échecs', 'T1078', 'critical', src_ip, username,
       first_failure_ts, success_ts, failed_attempts,
       format('connexion réussie de %s après %s échecs en 30 min (comptes : %s)',
              username, failed_attempts, array_to_string(failed_users, ', '))
FROM detect.d3_success_after_failures
UNION ALL
SELECT 'D4', 'Énumération de comptes', 'T1110', 'medium', src_ip, NULL,
       window_start, window_end, unknown_users,
       format('%s comptes inexistants essayés (ex. : %s)',
              unknown_users, array_to_string(sample_users, ', '))
FROM detect.d4_user_enumeration
UNION ALL
SELECT 'D5', 'Ciblage de root', 'T1110',
       CASE WHEN root_successes > 0 THEN 'critical'
            WHEN root_failures >= 10 THEN 'medium' ELSE 'low' END,
       src_ip, 'root', window_start, window_end, root_failures + root_successes,
       format('%s échecs et %s succès sur root, %s %% de ses échecs visent root',
              root_failures, root_successes, round(coalesce(root_ratio, 0) * 100))
FROM detect.d5_root_targeting;
