-- Flexible collections: the `manage` permission on a user's or group's access to a
-- collection. A manage grant implies edit + view-passwords, and additionally lets the
-- member manage the collection itself (rename/delete, edit membership).
--
-- NOTE: the columns are added here and the authorization views that reference them are
-- recreated in V6. They must live in separate migrations because CockroachDB cannot
-- reference a column added earlier in the *same* transaction, and refinery runs each
-- migration file in its own transaction.

ALTER TABLE collection_users ADD COLUMN manage BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE collection_groups ADD COLUMN manage BOOLEAN NOT NULL DEFAULT false;
