ALTER TABLE auth_flows
    ADD COLUMN IF NOT EXISTS rollout_tenant_id TEXT,
    ADD COLUMN IF NOT EXISTS rollout_request_channel TEXT,
    ADD COLUMN IF NOT EXISTS rollout_cohort TEXT;

CREATE INDEX IF NOT EXISTS idx_auth_flows_rollout_tenant_channel_status
ON auth_flows(rollout_tenant_id, rollout_request_channel, status);

CREATE INDEX IF NOT EXISTS idx_auth_flows_rollout_cohort_status
ON auth_flows(rollout_cohort, status);
