CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS stg;
CREATE SCHEMA IF NOT EXISTS mart;

CREATE TABLE IF NOT EXISTS raw.auth_lines (
  line_no     int,
  line        text,
  source_file text,
  ingested_at timestamptz DEFAULT now(),
  CONSTRAINT auth_lines_uniq UNIQUE (source_file, line_no)
);
