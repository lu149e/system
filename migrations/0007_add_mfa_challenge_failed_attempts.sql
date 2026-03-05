ALTER TABLE mfa_challenges
ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;

ALTER TABLE mfa_challenges
ADD CONSTRAINT mfa_challenges_failed_attempts_nonnegative
CHECK (failed_attempts >= 0);
