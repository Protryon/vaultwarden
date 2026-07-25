-- Force-password-reset flag: set when an org admin resets a member's master password via
-- account recovery, so the member is prompted to change it on next login. Cleared when the
-- user next changes their own password. Emitted as `forcePasswordReset` in the profile and
-- the `/connect/token` auth response.

ALTER TABLE users ADD COLUMN force_password_reset BOOLEAN NOT NULL DEFAULT false;
