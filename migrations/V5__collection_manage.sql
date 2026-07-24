-- Flexible collections: the `manage` permission on a user's or group's access to a
-- collection. A manage grant implies edit + view-passwords, and additionally lets the
-- member manage the collection itself (rename/delete, edit membership).

ALTER TABLE collection_users ADD COLUMN manage BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE collection_groups ADD COLUMN manage BOOLEAN NOT NULL DEFAULT false;

-- Recompute the authorization views to surface `manage`. user_cipher_auth depends on
-- user_collection_auth, so drop it first and recreate both (CockroachDB-friendly).
DROP VIEW user_cipher_auth;
DROP VIEW user_collection_auth;

CREATE VIEW user_collection_auth AS
    SELECT co.uuid AS collection_uuid, sub.user_uuid,
           bool_and(sub.read_only) AS read_only,
           bool_and(sub.hide_passwords) AS hide_passwords,
           bool_or(sub.manage) AS manage
    FROM collections co
    INNER JOIN LATERAL (
        SELECT uc.user_uuid, uc.read_only, uc.hide_passwords, uc.manage
        FROM collection_users uc WHERE co.uuid = uc.collection_uuid
        UNION
        -- Groups with access_all get full access regardless of the per-collection flags.
        SELECT gu.user_uuid, gc.read_only AND NOT g.access_all, gc.hide_passwords AND NOT g.access_all, gc.manage AND NOT g.access_all
        FROM collection_groups gc
        INNER JOIN group_users gu ON gu.group_uuid = gc.group_uuid
        INNER JOIN groups g ON g.uuid = gu.group_uuid
        WHERE co.uuid = gc.collection_uuid
        UNION
        -- Owners/admins (atype < 2) manage every collection; access_all managers get access
        -- but not manage.
        SELECT uo.user_uuid, false, false, uo.atype < 2
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
