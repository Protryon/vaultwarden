CREATE TABLE auth_requests (
    uuid UUID NOT NULL PRIMARY KEY,
    user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    organization_uuid UUID REFERENCES organizations(uuid) ON DELETE CASCADE,
    request_device_identifier UUID NOT NULL,
    device_type INT4 NOT NULL,
    request_ip TEXT NOT NULL,
    response_device_id UUID,
    access_code TEXT NOT NULL,
    public_key TEXT NOT NULL,
    enc_key TEXT,
    master_password_hash TEXT,
    approved BOOLEAN,
    creation_date TIMESTAMPTZ NOT NULL,
    response_date TIMESTAMPTZ,
    authentication_date TIMESTAMPTZ
);

CREATE INDEX auth_request_user ON auth_requests(user_uuid);
CREATE INDEX auth_request_creation ON auth_requests(creation_date);
