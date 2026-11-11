-- Une ligne de fait = un événement d'authentification écrit par sshd
-- (auth_failure, auth_success, invalid_user). Pas les lignes PAM, elles
-- répètent les échecs de sshd et tout compterait double.
--
-- Tout est en IF NOT EXISTS et load_mart.py lance ce fichier lui-même,
-- pas besoin de le passer à la main.

-- une ligne par IP vue dans les logs
CREATE TABLE IF NOT EXISTS mart.dim_ip (
  ip_key          serial      PRIMARY KEY,
  src_ip          inet        NOT NULL UNIQUE,
  first_seen      timestamptz,
  last_seen       timestamptz,
  ptr_host        text,                  -- nom renvoyé par le DNS inverse, s'il y en a un
  reverse_dns_mismatch boolean NOT NULL DEFAULT false,  -- "POSSIBLE BREAK-IN ATTEMPT!"
  is_private      boolean     NOT NULL DEFAULT false    -- 10/8, 172.16/12, 192.168/16
);

-- une ligne par nom essayé
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

-- les détections cherchent par IP et par type, sur des fenêtres de temps
CREATE INDEX IF NOT EXISTS fact_auth_event_ip_ts   ON mart.fact_auth_event (ip_key, event_ts);
CREATE INDEX IF NOT EXISTS fact_auth_event_type_ts ON mart.fact_auth_event (event_type, event_ts);
