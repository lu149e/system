-- Parameterized snippets for dead-letter inspection/replay.
-- Use with psql variables, for example:
--   psql "$DATABASE_URL" -v provider='sendgrid' -v template='' -v ticket='' -v failed_after='' -v failed_before='' -v row_limit='100' -f scripts/sql/outbox-dead-letter-queries.sql

-- Shared filter logic (copy into your query block):
-- status = 'failed'
-- AND next_attempt_at IS NULL
-- AND (NULLIF(:'provider', '') IS NULL OR provider = :'provider')
-- AND (NULLIF(:'template', '') IS NULL OR template = :'template')
-- AND (NULLIF(:'failed_after', '') IS NULL OR failed_at >= :'failed_after'::timestamptz)
-- AND (NULLIF(:'failed_before', '') IS NULL OR failed_at < :'failed_before'::timestamptz)

-- Inspect exhausted messages.
SELECT id,
       provider,
       template,
       attempts,
       failed_at,
       last_error,
       updated_at
FROM email_outbox
WHERE status = 'failed'
  AND next_attempt_at IS NULL
  AND (NULLIF(:'provider', '') IS NULL OR provider = :'provider')
  AND (NULLIF(:'template', '') IS NULL OR template = :'template')
  AND (NULLIF(:'failed_after', '') IS NULL OR failed_at >= :'failed_after'::timestamptz)
  AND (NULLIF(:'failed_before', '') IS NULL OR failed_at < :'failed_before'::timestamptz)
ORDER BY failed_at ASC NULLS LAST, updated_at ASC
LIMIT GREATEST(1, LEAST(COALESCE(NULLIF(:'row_limit', '')::int, 100), 1000));

-- Report dead-letter buckets by provider/template.
WITH filtered AS (
  SELECT provider,
         template,
         NOW() - COALESCE(failed_at, updated_at) AS dead_letter_age
  FROM email_outbox
  WHERE status = 'failed'
    AND next_attempt_at IS NULL
    AND (NULLIF(:'provider', '') IS NULL OR provider = :'provider')
    AND (NULLIF(:'template', '') IS NULL OR template = :'template')
    AND (NULLIF(:'failed_after', '') IS NULL OR failed_at >= :'failed_after'::timestamptz)
    AND (NULLIF(:'failed_before', '') IS NULL OR failed_at < :'failed_before'::timestamptz)
)
SELECT provider,
       template,
       COUNT(*) FILTER (WHERE dead_letter_age < INTERVAL '1 hour') AS age_lt_1h,
       COUNT(*) FILTER (WHERE dead_letter_age >= INTERVAL '1 hour' AND dead_letter_age < INTERVAL '6 hours') AS age_1h_6h,
       COUNT(*) FILTER (WHERE dead_letter_age >= INTERVAL '6 hours' AND dead_letter_age < INTERVAL '24 hours') AS age_6h_24h,
       COUNT(*) FILTER (WHERE dead_letter_age >= INTERVAL '24 hours' AND dead_letter_age < INTERVAL '3 days') AS age_1d_3d,
       COUNT(*) FILTER (WHERE dead_letter_age >= INTERVAL '3 days') AS age_ge_3d,
       COUNT(*) AS total
FROM filtered
GROUP BY provider, template
ORDER BY total DESC, provider ASC, template ASC
LIMIT GREATEST(1, LEAST(COALESCE(NULLIF(:'row_limit', '')::int, 100), 1000));

-- Audit trail for manual requeue operations.
SELECT id,
       operation_type,
       actor_identifier,
       change_ticket,
       provider_filter,
       template_filter,
       failed_after_filter,
       failed_before_filter,
       row_limit,
       allow_unfiltered,
       is_apply,
       selected_count,
       updated_count,
       created_at
FROM outbox_replay_audit
WHERE (NULLIF(:'provider', '') IS NULL OR provider_filter = :'provider')
  AND (NULLIF(:'template', '') IS NULL OR template_filter = :'template')
  AND (NULLIF(:'ticket', '') IS NULL OR change_ticket = :'ticket')
  AND (NULLIF(:'failed_after', '') IS NULL OR created_at >= :'failed_after'::timestamptz)
  AND (NULLIF(:'failed_before', '') IS NULL OR created_at < :'failed_before'::timestamptz)
ORDER BY created_at DESC
LIMIT GREATEST(1, LEAST(COALESCE(NULLIF(:'row_limit', '')::int, 100), 1000));
