DO $$
DECLARE
    missing_credentials_count BIGINT;
BEGIN
    SELECT COUNT(*)
    INTO missing_credentials_count
    FROM users u
    LEFT JOIN credentials c ON c.user_id = u.id
    WHERE c.user_id IS NULL;

    IF missing_credentials_count > 0 THEN
        RAISE EXCEPTION USING
            MESSAGE = format(
                'credentials coverage check failed: %s users without credentials rows',
                missing_credentials_count
            ),
            HINT = 'Backfill credentials rows first and force password reset for impacted users before deploying auth core.';
    END IF;
END;
$$;

ALTER TABLE credentials
    ADD CONSTRAINT credentials_password_hash_not_empty
    CHECK (length(trim(password_hash)) > 0);
