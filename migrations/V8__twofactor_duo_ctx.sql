-- Short-lived server-side context for the Duo Universal Prompt (OIDC) login flow. A row is
-- created when a user is redirected to Duo (state/nonce bound to their email) and consumed +
-- deleted when Duo redirects back with the authorization code. Expired rows are purged by a
-- background job.
CREATE TABLE twofactor_duo_ctx (
    state      TEXT NOT NULL PRIMARY KEY,
    user_email TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    exp        INT8 NOT NULL
);

CREATE INDEX twofactor_duo_ctx_exp ON twofactor_duo_ctx(exp);
