-- 016_network_probes.sql
-- Network probe registration and device inventory

-- Network probes register here (same as agents but different type)
-- Agents table already handles this via os='network-probe'
-- We store probe-specific data separately

CREATE TABLE IF NOT EXISTS network_probe_devices (
    id           BIGSERIAL PRIMARY KEY,
    probe_id     TEXT NOT NULL,          -- agent_id of the network probe
    mac          TEXT NOT NULL DEFAULT '',
    ip           TEXT NOT NULL DEFAULT '',
    hostname     TEXT NOT NULL DEFAULT '',
    vendor       TEXT NOT NULL DEFAULT '',
    device_type  TEXT NOT NULL DEFAULT 'unknown',
    os_guess     TEXT NOT NULL DEFAULT '',
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_known     BOOLEAN NOT NULL DEFAULT FALSE,
    location     TEXT NOT NULL DEFAULT '',
    extra        JSONB NOT NULL DEFAULT '{}',
    UNIQUE (probe_id, mac)
);

CREATE INDEX IF NOT EXISTS idx_probe_devices_probe  ON network_probe_devices (probe_id);
CREATE INDEX IF NOT EXISTS idx_probe_devices_ip     ON network_probe_devices (ip);
CREATE INDEX IF NOT EXISTS idx_probe_devices_vendor ON network_probe_devices (vendor);

-- Bandwidth history — sent by probe analysis engine every 5 minutes
CREATE TABLE IF NOT EXISTS network_bandwidth (
    probe_id    TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    hour        TIMESTAMPTZ NOT NULL,
    bytes_out   BIGINT NOT NULL DEFAULT 0,
    bytes_in    BIGINT NOT NULL DEFAULT 0,
    flow_count  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (probe_id, src_ip, hour)
);

CREATE INDEX IF NOT EXISTS idx_network_bw_probe ON network_bandwidth (probe_id, hour DESC);

-- Network topology — CDP/LLDP neighbors
CREATE TABLE IF NOT EXISTS network_topology (
    probe_id    TEXT NOT NULL,
    local_host  TEXT NOT NULL,
    local_iface TEXT NOT NULL DEFAULT '',
    neighbor    TEXT NOT NULL,
    neighbor_ip TEXT NOT NULL DEFAULT '',
    proto       TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (probe_id, local_host, local_iface, neighbor)
);
