-- Canonical schema. Run manage.py init-db; do not run against an active service.
-- Deliberately no CREATE DATABASE, USE, DROP or embedded credentials.
CREATE TABLE transport_replay (
    key_id VARCHAR(64) NOT NULL,
    request_id CHAR(36) NOT NULL,
    nonce CHAR(24) NOT NULL,
    expires_at_utc DATETIME(6) NOT NULL,
    PRIMARY KEY (key_id, request_id),
    UNIQUE KEY transport_nonce (key_id, nonce),
    KEY transport_expiry (expires_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE schema_migrations (
    version INT NOT NULL PRIMARY KEY,
    checksum CHAR(64) NOT NULL,
    applied_at_utc DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE control_policy (
    singleton_id TINYINT NOT NULL PRIMARY KEY,
    policy_version BIGINT NOT NULL,
    policy_json JSON NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE device_credentials (
    device_id CHAR(36) NOT NULL PRIMARY KEY,
    token_hash CHAR(64) NOT NULL,
    enrolled_at_utc DATETIME(6) NOT NULL,
    last_authenticated_at_utc DATETIME(6) NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE device_heartbeats (
    device_id CHAR(36) NOT NULL PRIMARY KEY,
    received_at_utc DATETIME(6) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os_version TEXT NOT NULL,
    applied_policy_version BIGINT NOT NULL,
    proxy_state VARCHAR(32) NOT NULL,
    heartbeat_json JSON NOT NULL,
    INDEX ix_heartbeat_received (received_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE agent_inventory (
    device_id CHAR(36) NOT NULL,
    instance_id CHAR(36) NOT NULL,
    agent_type VARCHAR(32) NOT NULL,
    inventory_json JSON NOT NULL,
    PRIMARY KEY (device_id, instance_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE device_runtime (
    device_id CHAR(36) NOT NULL PRIMARY KEY,
    schema_version INT NOT NULL,
    service_version VARCHAR(64) NOT NULL,
    heartbeat_interval_seconds INT NOT NULL,
    operation_state VARCHAR(32) NOT NULL,
    source_ip VARCHAR(64) NULL,
    runtime_json JSON NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE agent_endpoint_assets (
    device_id CHAR(36) NOT NULL,
    asset_id CHAR(36) NOT NULL,
    agent_family VARCHAR(32) NOT NULL,
    asset_json JSON NOT NULL,
    PRIMARY KEY (device_id, asset_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE proxy_activity (
    device_id CHAR(36) NOT NULL,
    asset_id CHAR(36) NOT NULL,
    activity_json JSON NOT NULL,
    PRIMARY KEY (device_id, asset_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE endpoint_events (
    event_id CHAR(36) NOT NULL PRIMARY KEY,
    device_id CHAR(36) NOT NULL,
    occurred_at_utc DATETIME(6) NOT NULL,
    received_at_utc DATETIME(6) NOT NULL,
    event_json JSON NOT NULL,
    INDEX ix_events_device_time (device_id, occurred_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE remote_commands (
    command_id CHAR(36) NOT NULL PRIMARY KEY,
    device_id CHAR(36) NOT NULL,
    command_type VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at_utc DATETIME(6) NOT NULL,
    expires_at_utc DATETIME(6) NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    reason VARCHAR(256) NOT NULL,
    delivered_at_utc DATETIME(6) NULL,
    started_at_utc DATETIME(6) NULL,
    completed_at_utc DATETIME(6) NULL,
    result_code VARCHAR(128) NULL,
    result_summary VARCHAR(512) NULL,
    delivery_count BIGINT NOT NULL DEFAULT 0,
    INDEX ix_command_device_state (device_id, status, created_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE admin_audit_log (
    audit_id CHAR(36) NOT NULL PRIMARY KEY,
    occurred_at_utc DATETIME(6) NOT NULL,
    actor VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    device_id CHAR(36) NULL,
    command_id CHAR(36) NULL,
    summary TEXT NOT NULL,
    INDEX ix_audit_time (occurred_at_utc),
    INDEX ix_audit_device_time (device_id, occurred_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
