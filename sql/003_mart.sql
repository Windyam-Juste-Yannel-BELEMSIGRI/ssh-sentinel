-- Grain de la table de faits : 1 ligne = 1 événement d'authentification écrit par sshd
-- (auth_failure, auth_success, invalid_user). Les lignes PAM sont exclues : elles
-- doublent les échecs SSH et feraient compter chaque tentative deux fois.
--
-- Rejouable : tout est en IF NOT EXISTS. load_mart.py lance aussi ce fichier,
-- donc pas besoin de le passer à la main sur une base qui existe déjà.

-- Une ligne par adresse IP source vue dans les logs.
CREATE TABLE IF NOT EXISTS mart.dim_ip (
  ip_key          serial      PRIMARY KEY,
  src_ip          inet        NOT NULL UNIQUE,
  first_seen      timestamptz,
  last_seen       timestamptz,
  ptr_host        text,                  -- nom renvoyé par le DNS inverse, s'il y en a un
  reverse_dns_mismatch boolean NOT NULL DEFAULT false,  -- "POSSIBLE BREAK-IN ATTEMPT!"
  is_private      boolean     NOT NULL DEFAULT false    -- 10/8, 172.16/12, 192.168/16
);

-- Une ligne par nom d'utilisateur tenté.
CREATE TABLE IF NOT EXISTS mart.dim_user (
  user_key        serial      PRIMARY KEY,
  username        text        NOT NULL UNIQUE,
  is_root         boolean     NOT NULL DEFAULT false,
  account_exists  boolean,               -- true / false / NULL si on ne peut pas savoir
  first_seen      timestamptz,
  last_seen       timestamptz
);

CREATE TABLE IF NOT EXISTS mart.fact_auth_event (
  source_file     text        NOT NULL,
  line_no         int         NOT NULL,
  event_ts        timestamptz NOT NULL,
  ip_key          int         NOT NULL REFERENCES mart.dim_ip (ip_key),
  user_key        int         REFERENCES mart.dim_user (user_key),
  event_type      text        NOT NULL,  -- auth_failure | auth_success | invalid_user
  auth_method     text,                  -- password, publickey, none
  src_port        int,
  session_pid     int,                   -- PID sshd : relie les lignes d'une même connexion
  attempts        int         NOT NULL DEFAULT 1,  -- = repeat_count de stg
  CONSTRAINT fact_auth_event_pk PRIMARY KEY (source_file, line_no),
  CONSTRAINT fact_auth_event_type_ck
    CHECK (event_type IN ('auth_failure', 'auth_success', 'invalid_user'))
);

-- Les détections regardent "une IP sur une fenêtre de temps" et "un type d'événement".
CREATE INDEX IF NOT EXISTS fact_auth_event_ip_ts   ON mart.fact_auth_event (ip_key, event_ts);
CREATE INDEX IF NOT EXISTS fact_auth_event_type_ts ON mart.fact_auth_event (event_type, event_ts);
