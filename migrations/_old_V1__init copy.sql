--- This file serves as a reference for what is possible for just Postgres support. But I want to run CockroachDB, so it's been binned.
--- I may have had a drink or two and had way too much fun with triggers.

CREATE TABLE users (
    uuid UUID NOT NULL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    password_hash bytea NOT NULL,
    salt bytea NOT NULL,
    password_iterations INTEGER NOT NULL,
    password_hint TEXT,
    akey TEXT NOT NULL,
    private_key TEXT,
    public_key TEXT,
    totp_secret TEXT,
    totp_recover TEXT,
    security_stamp UUID NOT NULL,
    equivalent_domains TEXT NOT NULL,
    excluded_globals TEXT NOT NULL,
    client_kdf_type INTEGER DEFAULT 0 NOT NULL,
    client_kdf_iter INTEGER DEFAULT 100000 NOT NULL,
    verified_at TIMESTAMPTZ,
    last_verifying_at TIMESTAMPTZ,
    login_verify_count INTEGER DEFAULT 0 NOT NULL,
    email_new TEXT DEFAULT NULL::VARCHAR,
    email_new_token TEXT DEFAULT NULL::VARCHAR,
    enabled BOOLEAN DEFAULT true NOT NULL,
    stamp_exception TEXT,
    api_key TEXT,
    avatar_color TEXT,
    client_kdf_memory INTEGER,
    client_kdf_parallelism INTEGER,
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
    status INTEGER NOT NULL,
    atype INTEGER NOT NULL,
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
    atype INTEGER NOT NULL,
    name TEXT NOT NULL,
    notes TEXT,
    fields JSONB,
    data JSONB NOT NULL,
    password_history JSONB,
    deleted_at TIMESTAMPTZ,
    reprompt INTEGER
);

CREATE INDEX cipher_user ON ciphers(user_uuid);
CREATE INDEX cipher_org ON ciphers(organization_uuid);

CREATE TABLE attachments (
    uuid UUID NOT NULL PRIMARY KEY,
    cipher_uuid UUID NOT NULL REFERENCES ciphers(uuid) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
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
    atype INTEGER NOT NULL,
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
    atype INTEGER NOT NULL,
    status INTEGER NOT NULL,
    wait_time_days INTEGER NOT NULL,
    recovery_initiated_at TIMESTAMPTZ,
    last_notification_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE organization_policies (
    uuid UUID NOT NULL PRIMARY KEY,
    organization_uuid UUID NOT NULL REFERENCES organizations(uuid) ON DELETE CASCADE,
    atype INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL,
    data JSONB NOT NULL
);

CREATE INDEX organization_policies_org ON organization_policies(organization_uuid);

CREATE TABLE events (
    uuid UUID NOT NULL PRIMARY KEY,
    event_type INTEGER NOT NULL,
    user_uuid UUID REFERENCES users(uuid) ON DELETE CASCADE,
    organization_uuid UUID REFERENCES organizations(uuid) ON DELETE CASCADE,
    cipher_uuid UUID REFERENCES ciphers(uuid) ON DELETE CASCADE,
    collection_uuid UUID REFERENCES collections(uuid) ON DELETE CASCADE,
    group_uuid UUID REFERENCES groups(uuid) ON DELETE CASCADE,
    act_user_uuid UUID REFERENCES users(uuid) ON DELETE CASCADE,
    device_type INTEGER,
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
    atype INTEGER NOT NULL,
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
    atype INTEGER NOT NULL,
    data JSONB NOT NULL,
    akey TEXT NOT NULL,
    password_hash bytea,
    password_salt bytea,
    password_iter INTEGER,
    max_access_count INTEGER,
    access_count INTEGER NOT NULL,
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
    atype INTEGER NOT NULL,
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
    user_uuid UUID NOT NULL REFERENCES collections(uuid) ON DELETE CASCADE,
    collection_uuid UUID NOT NULL REFERENCES collections(uuid) ON DELETE CASCADE,
    read_only BOOLEAN DEFAULT false NOT NULL,
    hide_passwords BOOLEAN DEFAULT false NOT NULL,
    PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE MATERIALIZED VIEW user_collection_auth AS 
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

-- TODO: this index is propably counterproductive
CREATE UNIQUE INDEX user_collection_auth_idx ON user_collection_auth(user_uuid, collection_uuid);

CREATE MATERIALIZED VIEW user_cipher_auth AS 
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

-- TODO: this index is propably counterproductive
CREATE UNIQUE INDEX user_cipher_auth_idx ON user_cipher_auth(user_uuid, cipher_uuid);

CREATE TABLE sso_nonces (
  nonce CHAR(36) NOT NULL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sso_nonce_creation ON sso_nonces(created_at);

-- this extremely aggressive rematerialization is not going to scale
-- will need a debounce, but UI doesnt handle lagged perf updates well
-- might end up being a non-materialized view?

CREATE FUNCTION resync_views() RETURNS trigger AS $trgr$
    BEGIN
        REFRESH MATERIALIZED VIEW user_collection_auth;
        REFRESH MATERIALIZED VIEW user_cipher_auth;
        RETURN NULL;
    END;
$trgr$ LANGUAGE plpgsql;

-- requires a total rematerialization
CREATE TRIGGER collection_users_update AFTER INSERT OR UPDATE OR DELETE ON collection_users FOR EACH STATEMENT EXECUTE FUNCTION resync_views();
CREATE TRIGGER collection_groups_update AFTER INSERT OR UPDATE OR DELETE ON collection_groups FOR EACH STATEMENT EXECUTE FUNCTION resync_views();
CREATE TRIGGER group_users_update AFTER INSERT OR UPDATE OR DELETE ON group_users FOR EACH STATEMENT EXECUTE FUNCTION resync_views();
CREATE TRIGGER groups_update AFTER INSERT OR UPDATE OR DELETE ON groups FOR EACH STATEMENT EXECUTE FUNCTION resync_views();
CREATE TRIGGER user_organizations_update AFTER INSERT OR UPDATE OR DELETE ON user_organizations FOR EACH STATEMENT EXECUTE FUNCTION resync_views();

-- requires a partial rematerialization
CREATE TRIGGER ciphers_owned_update AFTER INSERT OR UPDATE OF user_uuid, organization_uuid OR DELETE ON ciphers FOR EACH STATEMENT EXECUTE FUNCTION resync_views();
CREATE TRIGGER collection_ciphers_update AFTER INSERT OR UPDATE OR DELETE ON collection_ciphers FOR EACH STATEMENT EXECUTE FUNCTION resync_views();

--- trigger to create user_revisions table entries

--- so we dont have to do upserts everywhere
CREATE FUNCTION user_created() RETURNS trigger AS $trgr$
    BEGIN
        INSERT INTO user_revisions (uuid, updated_at) VALUES (NEW.uuid, now());
        RETURN NEW;
    END;
$trgr$ LANGUAGE plpgsql;

CREATE TRIGGER user_created AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION user_created();

-- triggers for user revision updates

CREATE FUNCTION user_uuid_changed() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() WHERE u.uuid = OLD.user_uuid;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            UPDATE user_revisions u SET updated_at = now() WHERE u.uuid = OLD.user_uuid OR u.uuid = NEW.user_uuid;
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            UPDATE user_revisions u SET updated_at = now() WHERE u.uuid = NEW.user_uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;

CREATE TRIGGER send_changed BEFORE INSERT OR UPDATE OR DELETE ON sends FOR EACH ROW EXECUTE FUNCTION user_uuid_changed();
CREATE TRIGGER user_organization_changed BEFORE INSERT OR UPDATE OR DELETE ON user_organizations FOR EACH ROW EXECUTE FUNCTION user_uuid_changed();
CREATE TRIGGER favorite_changed BEFORE INSERT OR UPDATE OR DELETE ON favorites FOR EACH ROW EXECUTE FUNCTION user_uuid_changed();
CREATE TRIGGER folder_changed BEFORE INSERT OR UPDATE OR DELETE ON folders FOR EACH ROW EXECUTE FUNCTION user_uuid_changed();
CREATE TRIGGER group_user_changed BEFORE INSERT OR UPDATE OR DELETE ON group_users FOR EACH ROW EXECUTE FUNCTION user_uuid_changed();
CREATE TRIGGER collection_user_changed BEFORE INSERT OR UPDATE OR DELETE ON collection_users FOR EACH ROW EXECUTE FUNCTION user_uuid_changed();

CREATE FUNCTION user_changed() RETURNS trigger AS $trgr$
    BEGIN
        UPDATE user_revisions u SET updated_at = now() WHERE u.uuid = NEW.uuid;
        RETURN NEW;
    END;
$trgr$ LANGUAGE plpgsql;
CREATE TRIGGER user_changed BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION user_changed();

CREATE FUNCTION org_updated() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_organizations uo WHERE uo.organization_uuid = OLD.uuid AND u.uuid = uo.user_uuid;
            return OLD;
        ELSE
            UPDATE user_revisions u SET updated_at = now() FROM user_organizations uo WHERE uo.organization_uuid = NEW.uuid AND u.uuid = uo.user_uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;

CREATE TRIGGER org_changed BEFORE INSERT OR UPDATE OR DELETE ON organizations FOR EACH ROW EXECUTE FUNCTION org_updated();

CREATE FUNCTION cipher_changed() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_cipher_auth uca WHERE uca.user_uuid = u.uuid AND uca.cipher_uuid = OLD.uuid;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_cipher_auth uca WHERE uca.user_uuid = u.uuid AND (uca.cipher_uuid = OLD.uuid OR uca.cipher_uuid = NEW.uuid);
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_cipher_auth uca WHERE uca.user_uuid = u.uuid AND uca.cipher_uuid = NEW.uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;
CREATE TRIGGER cipher_changed BEFORE UPDATE OR DELETE ON ciphers FOR EACH ROW EXECUTE FUNCTION cipher_changed();
-- because of conflict with user_cipher_auth rematerialization (TODO: make sure this runs after the view changes)
-- or just dont join on user_cipher_auth here
CREATE TRIGGER cipher_changed_post AFTER INSERT OR UPDATE ON ciphers FOR EACH ROW EXECUTE FUNCTION cipher_changed();

CREATE FUNCTION folder_cipher_changed() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM folders f WHERE f.uuid = OLD.folder_uuid AND u.uuid = f.user_uuid;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM folders f WHERE (f.uuid = OLD.folder_uuid OR f.uuid = NEW.folder_uuid) AND u.uuid = f.user_uuid;
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            UPDATE user_revisions u SET updated_at = now() FROM folders f WHERE f.uuid = NEW.folder_uuid AND u.uuid = f.user_uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;
CREATE TRIGGER folder_ciphers_changed BEFORE INSERT OR UPDATE OR DELETE ON folder_ciphers FOR EACH ROW EXECUTE FUNCTION folder_cipher_changed();

CREATE FUNCTION emergency_access_changed() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() WHERE u.uuid = OLD.grantee_uuid OR u.uuid = OLD.grantor_uuid;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            UPDATE user_revisions u SET updated_at = now() WHERE u.uuid = OLD.grantee_uuid OR u.uuid = OLD.grantor_uuid OR NEW.grantee_uuid OR u.uuid = NEW.grantor_uuid;
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            UPDATE user_revisions u SET updated_at = now() WHERE u.uuid = NEW.grantee_uuid OR u.uuid = NEW.grantor_uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;

CREATE TRIGGER emergency_access_changed BEFORE INSERT OR UPDATE OR DELETE ON emergency_access FOR EACH ROW EXECUTE FUNCTION emergency_access_changed();



CREATE FUNCTION group_changed() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM group_users gu WHERE gu.group_uuid = OLD.uuid AND gu.user_uuid = u.uuid;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE' OR TG_OP = 'INSERT') THEN
            UPDATE user_revisions u SET updated_at = now() FROM group_users gu WHERE gu.group_uuid = NEW.uuid AND gu.user_uuid = u.uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;

CREATE TRIGGER group_changed BEFORE INSERT OR UPDATE OR DELETE ON groups FOR EACH ROW EXECUTE FUNCTION group_changed();

CREATE FUNCTION collection_group_changed() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM group_users gu WHERE gu.group_uuid = OLD.group_uuid AND gu.user_uuid = u.uuid;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM group_users gu WHERE (gu.group_uuid = NEW.group_uuid OR gu.group_uuid = OLD.group_uuid) AND gu.user_uuid = u.uuid;
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            UPDATE user_revisions u SET updated_at = now() FROM group_users gu WHERE gu.group_uuid = NEW.group_uuid AND gu.user_uuid = u.uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;
CREATE TRIGGER collection_group_changed BEFORE INSERT OR UPDATE OR DELETE ON collection_groups FOR EACH ROW EXECUTE FUNCTION collection_group_changed();



CREATE FUNCTION attachment_changed() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_cipher_auth uca WHERE uca.user_uuid = u.uuid AND uca.cipher_uuid = OLD.cipher_uuid;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_cipher_auth uca WHERE uca.user_uuid = u.uuid AND (uca.cipher_uuid = OLD.cipher_uuid OR uca.cipher_uuid = NEW.cipher_uuid);
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_cipher_auth uca WHERE uca.user_uuid = u.uuid AND uca.cipher_uuid = NEW.cipher_uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;
CREATE TRIGGER attachment_changed BEFORE INSERT OR UPDATE OR DELETE ON attachments FOR EACH ROW EXECUTE FUNCTION attachment_changed();



CREATE FUNCTION collection_cipher_changed() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_collection_auth uca WHERE uca.user_uuid = u.uuid AND uca.collection_uuid = OLD.collection_uuid;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_collection_auth uca WHERE uca.user_uuid = u.uuid AND (uca.collection_uuid = OLD.collection_uuid OR uca.collection_uuid = NEW.collection_uuid);
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_collection_auth uca WHERE uca.user_uuid = u.uuid AND uca.collection_uuid = NEW.collection_uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;
CREATE TRIGGER collection_cipher_changed BEFORE INSERT OR UPDATE OR DELETE ON collection_ciphers FOR EACH ROW EXECUTE FUNCTION collection_cipher_changed();

CREATE FUNCTION collection_changed() RETURNS trigger AS $trgr$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_collection_auth uca WHERE uca.user_uuid = u.uuid AND uca.collection_uuid = OLD.uuid;
            RETURN OLD;
        ELSIF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') THEN
            UPDATE user_revisions u SET updated_at = now() FROM user_collection_auth uca WHERE uca.user_uuid = u.uuid AND uca.collection_uuid = NEW.uuid;
            RETURN NEW;
        END IF;
    END;
$trgr$ LANGUAGE plpgsql;
CREATE TRIGGER collection_changed BEFORE INSERT OR UPDATE OR DELETE ON collections FOR EACH ROW EXECUTE FUNCTION collection_changed();
