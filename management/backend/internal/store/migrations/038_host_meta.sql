-- P-03: host criticality and free-form tags. Critical hosts raise alert severity by one.
CREATE TABLE IF NOT EXISTS host_meta (
    host        TEXT PRIMARY KEY,
    criticality TEXT NOT NULL DEFAULT 'normal' CHECK (criticality IN ('low','normal','high','critical')),
    tags        TEXT NOT NULL DEFAULT '',
    updated_by  TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
