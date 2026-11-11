-- stg : chaque ligne de raw découpée en champs. Même clé que raw (source_file, line_no),
-- une ligne brute = une ligne ici.

CREATE TABLE IF NOT EXISTS stg.auth_events (
  source_file   text        NOT NULL,
  line_no       int         NOT NULL,
  event_ts      timestamptz,            -- date reconstituée (année + fuseau ajoutés)
  host          text,
  process       text,
  pid           int,                    -- même PID = même connexion sshd
  event_type    text        NOT NULL,   -- auth_failure, auth_success, invalid_user...
  username      text,
  src_ip        inet,                   -- inet pour pouvoir chercher par sous-réseau
  src_port      int,
  src_host      text,                   -- nom d'hôte quand la source n'est pas une IP
  auth_method   text,                   -- password, publickey, none
  invalid_user  boolean,                -- compte inexistant sur le serveur
  preauth       boolean     NOT NULL DEFAULT false,
  repeat_count  int         NOT NULL DEFAULT 1,  -- "message repeated N times" => N
  detail        text,
  message       text,                   -- gardé pour vérifier le parser
  parsed_at     timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT auth_events_pk PRIMARY KEY (source_file, line_no),
  CONSTRAINT auth_events_raw_fk FOREIGN KEY (source_file, line_no)
    REFERENCES raw.auth_lines (source_file, line_no)
);

-- pour les recherches par type et par IP dans le temps
CREATE INDEX IF NOT EXISTS auth_events_type_ts ON stg.auth_events (event_type, event_ts);
CREATE INDEX IF NOT EXISTS auth_events_ip_ts   ON stg.auth_events (src_ip, event_ts);
