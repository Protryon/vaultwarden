CREATE TABLE archives (
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    cipher_uuid UUID NOT NULL REFERENCES ciphers(uuid) ON DELETE CASCADE,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_uuid, cipher_uuid)
);
