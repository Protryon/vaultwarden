CREATE TABLE users (
    uuid UUID NOT NULL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    password_hash bytea NOT NULL,
    salt bytea NOT NULL,
    password_iterations INT4 NOT NULL,
    password_hint TEXT,
    akey TEXT NOT NULL,
    private_key TEXT,
    public_key TEXT,
    totp_secret TEXT,
    totp_recover TEXT,
    security_stamp UUID NOT NULL,
    equivalent_domains TEXT NOT NULL,
    excluded_globals TEXT NOT NULL,
    client_kdf_type INT4 DEFAULT 0 NOT NULL,
    client_kdf_iter INT4 DEFAULT 100000 NOT NULL,
    verified_at TIMESTAMPTZ,
    last_verifying_at TIMESTAMPTZ,
    login_verify_count INT4 DEFAULT 0 NOT NULL,
    email_new TEXT DEFAULT NULL::VARCHAR,
    email_new_token TEXT DEFAULT NULL::VARCHAR,
    enabled BOOLEAN DEFAULT true NOT NULL,
    stamp_exception TEXT,
    api_key TEXT,
    avatar_color TEXT,
    client_kdf_memory INT4,
    client_kdf_parallelism INT4,
    external_id TEXT
);

CREATE TABLE user_revisions (
    uuid UUID NOT NULL PRIMARY KEY REFERENCES users(uuid) ON DELETE CASCADE,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX user_email ON users(email);
CREATE UNIQUE INDEX user_ext ON users(external_id);

CREATE TABLE organizations (
    uuid UUID NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    billing_email TEXT NOT NULL,
    private_key TEXT,
    public_key TEXT
);

CREATE TABLE user_organizations (
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    organization_uuid UUID NOT NULL REFERENCES organizations(uuid) ON DELETE CASCADE,
    access_all BOOLEAN NOT NULL,
    akey TEXT NOT NULL,
    status INT4 NOT NULL,
    atype INT4 NOT NULL,
    reset_password_key TEXT,
    revoked BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (user_uuid, organization_uuid)
);

CREATE TABLE ciphers (
    uuid UUID NOT NULL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    user_uuid UUID REFERENCES users(uuid) ON DELETE CASCADE,
    organization_uuid UUID REFERENCES organizations(uuid) ON DELETE CASCADE,
    atype INT4 NOT NULL,
    name TEXT NOT NULL,
    notes TEXT,
    fields JSONB,
    data JSONB NOT NULL,
    password_history JSONB,
    deleted_at TIMESTAMPTZ,
    reprompt INT4
);

CREATE INDEX cipher_user ON ciphers(user_uuid);
CREATE INDEX cipher_org ON ciphers(organization_uuid);

CREATE TABLE attachments (
    uuid UUID NOT NULL PRIMARY KEY,
    cipher_uuid UUID NOT NULL REFERENCES ciphers(uuid) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    file_size INT4 NOT NULL,
    akey TEXT
);

CREATE TABLE collections (
    uuid UUID NOT NULL PRIMARY KEY,
    organization_uuid UUID NOT NULL REFERENCES organizations(uuid) ON DELETE CASCADE,
    name TEXT NOT NULL
);

CREATE TABLE collection_ciphers (
    cipher_uuid UUID NOT NULL REFERENCES ciphers(uuid) ON DELETE CASCADE,
    collection_uuid UUID NOT NULL REFERENCES collections(uuid) ON DELETE CASCADE,
    PRIMARY KEY(collection_uuid, cipher_uuid)
);

CREATE TABLE groups (
    uuid UUID NOT NULL PRIMARY KEY,
    organization_uuid UUID NOT NULL REFERENCES organizations(uuid) ON DELETE CASCADE,
    name TEXT NOT NULL,
    access_all BOOLEAN NOT NULL,
    external_id TEXT,
    creation_date TIMESTAMPTZ NOT NULL,
    revision_date TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX group_external ON groups(external_id);

CREATE TABLE collection_groups (
    collection_uuid UUID NOT NULL REFERENCES collections(uuid) ON DELETE CASCADE,
    group_uuid UUID NOT NULL REFERENCES groups(uuid) ON DELETE CASCADE,
    read_only BOOLEAN NOT NULL,
    hide_passwords BOOLEAN NOT NULL,
    PRIMARY KEY(collection_uuid, group_uuid)
);

CREATE TABLE devices (
    uuid UUID NOT NULL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    name TEXT NOT NULL,
    atype INT4 NOT NULL,
    push_token TEXT,
    refresh_token TEXT NOT NULL,
    twofactor_remember TEXT,
    push_uuid UUID
);

CREATE INDEX device_users ON devices(user_uuid);
CREATE UNIQUE INDEX device_refresh ON devices(refresh_token);

CREATE TABLE emergency_access (
    uuid UUID NOT NULL PRIMARY KEY,
    grantor_uuid UUID REFERENCES users(uuid) ON DELETE CASCADE,
    grantee_uuid UUID REFERENCES users(uuid) ON DELETE CASCADE,
    email TEXT,
    key_encrypted TEXT,
    atype INT4 NOT NULL,
    status INT4 NOT NULL,
    wait_time_days INT4 NOT NULL,
    recovery_initiated_at TIMESTAMPTZ,
    last_notification_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE organization_policies (
    uuid UUID NOT NULL PRIMARY KEY,
    organization_uuid UUID NOT NULL REFERENCES organizations(uuid) ON DELETE CASCADE,
    atype INT4 NOT NULL,
    enabled BOOLEAN NOT NULL,
    data JSONB NOT NULL
);

CREATE INDEX organization_policies_org ON organization_policies(organization_uuid);

CREATE TABLE events (
    uuid UUID NOT NULL PRIMARY KEY,
    event_type INT4 NOT NULL,
    user_uuid UUID REFERENCES users(uuid) ON DELETE CASCADE,
    organization_uuid UUID REFERENCES organizations(uuid) ON DELETE CASCADE,
    cipher_uuid UUID REFERENCES ciphers(uuid) ON DELETE CASCADE,
    collection_uuid UUID REFERENCES collections(uuid) ON DELETE CASCADE,
    group_uuid UUID REFERENCES groups(uuid) ON DELETE CASCADE,
    act_user_uuid UUID REFERENCES users(uuid) ON DELETE CASCADE,
    device_type INT4,
    ip_address TEXT,
    event_date TIMESTAMPTZ NOT NULL,
    policy_uuid UUID REFERENCES organization_policies(uuid) ON DELETE CASCADE,
    provider_uuid UUID, --?
    provider_user_uuid UUID REFERENCES users(uuid) ON DELETE CASCADE,
    provider_organization_uuid UUID REFERENCES organizations(uuid) ON DELETE CASCADE
);

CREATE TABLE favorites (
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    cipher_uuid UUID NOT NULL REFERENCES ciphers(uuid) ON DELETE CASCADE,
    PRIMARY KEY (user_uuid, cipher_uuid)
);

CREATE TABLE folders (
    uuid UUID NOT NULL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    name TEXT NOT NULL
);

CREATE INDEX folder_users ON folders(user_uuid);

CREATE TABLE folder_ciphers (
    cipher_uuid UUID NOT NULL REFERENCES ciphers(uuid) ON DELETE CASCADE,
    folder_uuid UUID NOT NULL REFERENCES folders(uuid) ON DELETE CASCADE,
    PRIMARY KEY (folder_uuid, cipher_uuid)
);

CREATE TABLE group_users (
    group_uuid UUID NOT NULL REFERENCES groups(uuid) ON DELETE CASCADE,
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    PRIMARY KEY (group_uuid, user_uuid)
);

CREATE TABLE invitations (
    email TEXT NOT NULL
);

CREATE TABLE organization_api_key (
    uuid UUID NOT NULL PRIMARY KEY,
    organization_uuid UUID NOT NULL REFERENCES organizations(uuid) ON DELETE CASCADE,
    atype INT4 NOT NULL,
    api_key TEXT,
    revision_date TIMESTAMPTZ NOT NULL
);

CREATE INDEX organization_api_key_org ON organization_api_key(organization_uuid);

CREATE TABLE sends (
    uuid UUID NOT NULL PRIMARY KEY,
    user_uuid UUID REFERENCES users(uuid) ON DELETE CASCADE,
    organization_uuid UUID REFERENCES organizations(uuid) ON DELETE CASCADE,
    name TEXT NOT NULL,
    notes TEXT,
    atype INT4 NOT NULL,
    data JSONB NOT NULL,
    akey TEXT NOT NULL,
    password_hash bytea,
    password_salt bytea,
    password_iter INT4,
    max_access_count INT4,
    access_count INT4 NOT NULL,
    creation_date TIMESTAMPTZ NOT NULL,
    revision_date TIMESTAMPTZ NOT NULL,
    expiration_date TIMESTAMPTZ,
    deletion_date TIMESTAMPTZ NOT NULL,
    disabled BOOLEAN NOT NULL,
    hide_email BOOLEAN,
    filename TEXT
);

CREATE TABLE twofactor (
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    atype INT4 NOT NULL,
    enabled BOOLEAN NOT NULL,
    data TEXT NOT NULL,
    last_used TIMESTAMPTZ,
    PRIMARY KEY (user_uuid, atype)
);

CREATE TABLE twofactor_incomplete (
    uuid UUID NOT NULL PRIMARY KEY,
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    device_uuid UUID NOT NULL, -- REFERENCES devices(uuid) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    login_time TIMESTAMPTZ NOT NULL,
    ip_address TEXT NOT NULL
);

CREATE INDEX twofactor_incomplete_idx ON twofactor_incomplete(user_uuid, device_uuid);

CREATE TABLE collection_users (
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    collection_uuid UUID NOT NULL REFERENCES collections(uuid) ON DELETE CASCADE,
    read_only BOOLEAN DEFAULT false NOT NULL,
    hide_passwords BOOLEAN DEFAULT false NOT NULL,
    PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE VIEW user_collection_auth AS 
    SELECT co.uuid AS collection_uuid, sub.user_uuid, bool_and(sub.read_only) AS read_only, bool_and(sub.hide_passwords) AS hide_passwords
    FROM collections co
    INNER JOIN LATERAL (
        SELECT uc.user_uuid, uc.read_only, uc.hide_passwords FROM collection_users uc WHERE co.uuid = uc.collection_uuid
        UNION
        -- is this use of group access all correct?
        SELECT gu.user_uuid, gc.read_only AND NOT g.access_all, gc.hide_passwords AND NOT g.access_all FROM collection_groups gc
        INNER JOIN group_users gu ON gu.group_uuid = gc.group_uuid
        INNER JOIN groups g ON g.uuid = gu.group_uuid
        WHERE co.uuid = gc.collection_uuid
        UNION
        SELECT uo.user_uuid, false, false
        FROM user_organizations uo
        WHERE uo.organization_uuid = co.organization_uuid
        AND (uo.access_all OR uo.atype < 2)
        AND uo.status = 2 AND NOT uo.revoked
    ) sub ON 1=1
    GROUP BY co.uuid, sub.user_uuid;

CREATE VIEW user_cipher_auth AS 
    SELECT sub.cipher_uuid, sub.user_uuid, bool_and(sub.read_only) AS read_only, bool_and(sub.hide_passwords) AS hide_passwords
    FROM (
        SELECT c.uuid AS cipher_uuid, c.user_uuid, false AS read_only, false AS hide_passwords FROM ciphers c WHERE c.user_uuid IS NOT NULL AND c.organization_uuid IS NULL
        UNION
        SELECT cc.cipher_uuid, uca.user_uuid, uca.read_only, uca.hide_passwords
        FROM ciphers c
        INNER JOIN collection_ciphers cc ON cc.cipher_uuid = c.uuid
        INNER JOIN user_collection_auth uca ON uca.collection_uuid = cc.collection_uuid
        WHERE c.user_uuid IS NULL AND c.organization_uuid IS NOT NULL
    ) sub
    GROUP BY sub.cipher_uuid, sub.user_uuid;

CREATE TABLE sso_nonces (
  nonce CHAR(36) NOT NULL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sso_nonce_creation ON sso_nonces(created_at);
