#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATES_DIR="${TEMPLATES_DIR:-${ROOT_DIR}/deploy/k8s/overlays/production/templates}"
GENERATED_DIR="${GENERATED_DIR:-${ROOT_DIR}/artifacts/production-overlay/generated}"
BASE_KUSTOMIZE_DIR="${BASE_KUSTOMIZE_DIR:-${ROOT_DIR}/deploy/k8s}"
NORMALIZE_AUTH_V2_COHORTS_SCRIPT="${ROOT_DIR}/scripts/normalize-auth-v2-cohorts.sh"

ENFORCE_DATABASE_TLS="${ENFORCE_DATABASE_TLS:-true}"
ENFORCE_REDIS_TLS="${ENFORCE_REDIS_TLS:-true}"
ENFORCE_SECURE_TRANSPORT="${ENFORCE_SECURE_TRANSPORT:-true}"
AUTH_V2_ENABLED="${AUTH_V2_ENABLED:-false}"
AUTH_V2_METHODS_ENABLED="${AUTH_V2_METHODS_ENABLED:-false}"
AUTH_V2_PASSWORD_PAKE_ENABLED="${AUTH_V2_PASSWORD_PAKE_ENABLED:-false}"
AUTH_V2_PASSWORD_UPGRADE_ENABLED="${AUTH_V2_PASSWORD_UPGRADE_ENABLED:-false}"
AUTH_V2_PASSKEY_NAMESPACE_ENABLED="${AUTH_V2_PASSKEY_NAMESPACE_ENABLED:-false}"
AUTH_V2_AUTH_FLOWS_ENABLED="${AUTH_V2_AUTH_FLOWS_ENABLED:-false}"
AUTH_V2_LEGACY_FALLBACK_MODE="${AUTH_V2_LEGACY_FALLBACK_MODE:-disabled}"
AUTH_V2_CLIENT_ALLOWLIST="${AUTH_V2_CLIENT_ALLOWLIST:-}"
AUTH_V2_SHADOW_AUDIT_ONLY="${AUTH_V2_SHADOW_AUDIT_ONLY:-false}"
AUTH_V2_AUTH_FLOW_PRUNE_INTERVAL_SECONDS="${AUTH_V2_AUTH_FLOW_PRUNE_INTERVAL_SECONDS:-60}"
AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS="${AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS:-25}"
PASSKEY_ENABLED="${PASSKEY_ENABLED:-false}"
PASSKEY_RP_ID="${PASSKEY_RP_ID:-}"
PASSKEY_RP_ORIGIN="${PASSKEY_RP_ORIGIN:-}"
PASSKEY_CHALLENGE_PRUNE_INTERVAL_SECONDS="${PASSKEY_CHALLENGE_PRUNE_INTERVAL_SECONDS:-60}"
LOGIN_RISK_MODE="${LOGIN_RISK_MODE:-baseline}"
LOGIN_RISK_BLOCKED_CIDRS="${LOGIN_RISK_BLOCKED_CIDRS:-}"
LOGIN_RISK_BLOCKED_USER_AGENT_SUBSTRINGS="${LOGIN_RISK_BLOCKED_USER_AGENT_SUBSTRINGS:-}"
LOGIN_RISK_BLOCKED_EMAIL_DOMAINS="${LOGIN_RISK_BLOCKED_EMAIL_DOMAINS:-}"
LOGIN_RISK_CHALLENGE_CIDRS="${LOGIN_RISK_CHALLENGE_CIDRS:-}"
LOGIN_RISK_CHALLENGE_USER_AGENT_SUBSTRINGS="${LOGIN_RISK_CHALLENGE_USER_AGENT_SUBSTRINGS:-}"
LOGIN_RISK_CHALLENGE_EMAIL_DOMAINS="${LOGIN_RISK_CHALLENGE_EMAIL_DOMAINS:-}"

required_vars=(
  IMAGE_DIGEST
  INGRESS_HOST
  TLS_SECRET_NAME
  POSTGRES_CIDR
  REDIS_CIDR
)

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

overlay_assert_eq() {
  local actual="$1"
  local expected="$2"
  local message="$3"

  if [[ "${actual}" != "${expected}" ]]; then
    printf 'self-test failed: %s\nexpected: %s\nactual: %s\n' "${message}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

overlay_assert_fails() {
  local expected_message="$1"
  shift
  local temp_output status
  temp_output="$(mktemp)"

  if "$@" >"${temp_output}" 2>&1; then
    printf 'self-test failed: expected command to fail: %s\n' "$*" >&2
    rm -f "${temp_output}"
    exit 1
  fi

  status=$?
  local output
  output="$(<"${temp_output}")"
  rm -f "${temp_output}"

  if [[ "${output}" != *"${expected_message}"* ]]; then
    printf 'self-test failed: unexpected failure output\nexpected substring: %s\noutput: %s\n' "${expected_message}" "${output}" >&2
    exit 1
  fi
}

require_non_empty() {
  local var_name="$1"
  local value="${!var_name:-}"
  if [[ -z "${value}" ]]; then
    fail "required variable '${var_name}' is missing or empty"
  fi
}

validate_image_digest() {
  if [[ ! "${IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    fail "IMAGE_DIGEST must match 'sha256:<64 lowercase hex characters>'"
  fi
}

validate_ingress_host() {
  if [[ ! "${INGRESS_HOST}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then
    fail "INGRESS_HOST must be a valid DNS hostname"
  fi

  if [[ "${INGRESS_HOST}" == *".."* ]]; then
    fail "INGRESS_HOST must not contain consecutive dots"
  fi
}

validate_tls_secret_name() {
  if [[ ! "${TLS_SECRET_NAME}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    fail "TLS_SECRET_NAME must be a valid Kubernetes metadata.name (RFC 1123 label)"
  fi
}

validate_boolean_flag() {
  local field_name="$1"
  local value="$2"
  if [[ "${value}" != "true" && "${value}" != "false" ]]; then
    fail "${field_name} must be either 'true' or 'false'"
  fi
}

validate_positive_u64() {
  local field_name="$1"
  local value="$2"

  if [[ ! "${value}" =~ ^[0-9]+$ ]] || [[ "${value}" == "0" ]]; then
    fail "${field_name} must be a positive integer"
  fi
}

validate_login_risk_mode() {
  if [[ "${LOGIN_RISK_MODE}" != "allow_all" && "${LOGIN_RISK_MODE}" != "baseline" ]]; then
    fail "LOGIN_RISK_MODE must be either 'allow_all' or 'baseline'"
  fi
}

validate_auth_v2_legacy_fallback_mode() {
  if [[ "${AUTH_V2_LEGACY_FALLBACK_MODE}" != "disabled" \
    && "${AUTH_V2_LEGACY_FALLBACK_MODE}" != "allowlisted" \
    && "${AUTH_V2_LEGACY_FALLBACK_MODE}" != "broad" ]]; then
    fail "AUTH_V2_LEGACY_FALLBACK_MODE must be one of: disabled, allowlisted, broad"
  fi
}

validate_passkey_origin_with_python() {
  local field_name="$1"
  local value="$2"

  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to validate ${field_name} URL"
  fi

  python3 - "$field_name" "$value" <<'PY'
import sys
from urllib.parse import urlparse

field = sys.argv[1]
raw = sys.argv[2].strip()

parsed = urlparse(raw)
if parsed.scheme.lower() != "https" or not parsed.netloc:
    print(f"ERROR: {field} must be a valid HTTPS origin URL: {raw}", file=sys.stderr)
    sys.exit(1)
PY
}

validate_passkey_configuration() {
  validate_boolean_flag "PASSKEY_ENABLED" "${PASSKEY_ENABLED}"
  validate_positive_u64 \
    "PASSKEY_CHALLENGE_PRUNE_INTERVAL_SECONDS" \
    "${PASSKEY_CHALLENGE_PRUNE_INTERVAL_SECONDS}"

  if [[ "${PASSKEY_ENABLED}" == "true" ]]; then
    if [[ -z "${PASSKEY_RP_ID//[[:space:]]/}" ]]; then
      fail "PASSKEY_RP_ID is required when PASSKEY_ENABLED=true"
    fi

    if [[ -z "${PASSKEY_RP_ORIGIN//[[:space:]]/}" ]]; then
      fail "PASSKEY_RP_ORIGIN is required when PASSKEY_ENABLED=true"
    fi

    validate_passkey_origin_with_python "PASSKEY_RP_ORIGIN" "${PASSKEY_RP_ORIGIN}"
  fi
}

validate_cidr_with_python() {
  local field_name="$1"
  local value="$2"

  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to validate ${field_name} CIDR"
  fi

  python3 - "$field_name" "$value" <<'PY'
import ipaddress
import sys

field = sys.argv[1]
raw = sys.argv[2]

try:
    ipaddress.ip_network(raw, strict=False)
except ValueError:
    print(f"ERROR: {field} must be a valid CIDR (IPv4 or IPv6): {raw}", file=sys.stderr)
    sys.exit(1)
PY
}

validate_optional_cidr_csv_with_python() {
  local field_name="$1"
  local value="$2"

  if [[ -z "${value//[[:space:]]/}" ]]; then
    return
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to validate ${field_name} CIDR CSV"
  fi

  python3 - "$field_name" "$value" <<'PY'
import ipaddress
import sys

field = sys.argv[1]
raw = sys.argv[2]

entries = [item.strip() for item in raw.split(",") if item.strip()]

for entry in entries:
    try:
        ipaddress.ip_network(entry, strict=False)
    except ValueError:
        print(f"ERROR: {field} contains invalid CIDR entry: {entry}", file=sys.stderr)
        sys.exit(1)
PY
}

load_auth_v2_normalizer() {
  [[ -f "${NORMALIZE_AUTH_V2_COHORTS_SCRIPT}" ]] || fail "missing auth v2 cohort normalizer: ${NORMALIZE_AUTH_V2_COHORTS_SCRIPT}"
  # shellcheck source=/dev/null
  source "${NORMALIZE_AUTH_V2_COHORTS_SCRIPT}"
}

normalize_auth_v2_rollout_inputs() {
  local normalized_allowlist
  local status=0

  normalized_allowlist="$(normalize_auth_v2_cohort_csv "${AUTH_V2_CLIENT_ALLOWLIST}")" || status=$?
  if [[ ${status} -ne 0 ]]; then
    return "${status}"
  fi

  AUTH_V2_CLIENT_ALLOWLIST="${normalized_allowlist}"
}

replace_tokens() {
  local template_file="$1"
  local output_file="$2"
  local base_kustomize_relpath="$3"
  local content

  content="$(<"${template_file}")"
  content="${content//__PRODUCTION_BASE_KUSTOMIZE_PATH__/${base_kustomize_relpath}}"
  content="${content//__PRODUCTION_IMAGE_DIGEST__/${IMAGE_DIGEST}}"
  content="${content//__PRODUCTION_INGRESS_HOST__/${INGRESS_HOST}}"
  content="${content//__PRODUCTION_TLS_SECRET_NAME__/${TLS_SECRET_NAME}}"
  content="${content//__PRODUCTION_POSTGRES_CIDR__/${POSTGRES_CIDR}}"
  content="${content//__PRODUCTION_REDIS_CIDR__/${REDIS_CIDR}}"
  content="${content//__PRODUCTION_ENFORCE_DATABASE_TLS__/${ENFORCE_DATABASE_TLS}}"
  content="${content//__PRODUCTION_ENFORCE_REDIS_TLS__/${ENFORCE_REDIS_TLS}}"
  content="${content//__PRODUCTION_ENFORCE_SECURE_TRANSPORT__/${ENFORCE_SECURE_TRANSPORT}}"
  content="${content//__PRODUCTION_AUTH_V2_ENABLED__/${AUTH_V2_ENABLED}}"
  content="${content//__PRODUCTION_AUTH_V2_METHODS_ENABLED__/${AUTH_V2_METHODS_ENABLED}}"
  content="${content//__PRODUCTION_AUTH_V2_PASSWORD_PAKE_ENABLED__/${AUTH_V2_PASSWORD_PAKE_ENABLED}}"
  content="${content//__PRODUCTION_AUTH_V2_PASSWORD_UPGRADE_ENABLED__/${AUTH_V2_PASSWORD_UPGRADE_ENABLED}}"
  content="${content//__PRODUCTION_AUTH_V2_PASSKEY_NAMESPACE_ENABLED__/${AUTH_V2_PASSKEY_NAMESPACE_ENABLED}}"
  content="${content//__PRODUCTION_AUTH_V2_AUTH_FLOWS_ENABLED__/${AUTH_V2_AUTH_FLOWS_ENABLED}}"
  content="${content//__PRODUCTION_AUTH_V2_LEGACY_FALLBACK_MODE__/${AUTH_V2_LEGACY_FALLBACK_MODE}}"
  content="${content//__PRODUCTION_AUTH_V2_CLIENT_ALLOWLIST__/${AUTH_V2_CLIENT_ALLOWLIST}}"
  content="${content//__PRODUCTION_AUTH_V2_SHADOW_AUDIT_ONLY__/${AUTH_V2_SHADOW_AUDIT_ONLY}}"
  content="${content//__PRODUCTION_AUTH_V2_AUTH_FLOW_PRUNE_INTERVAL_SECONDS__/${AUTH_V2_AUTH_FLOW_PRUNE_INTERVAL_SECONDS}}"
  content="${content//__PRODUCTION_AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS__/${AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS}}"
  content="${content//__PRODUCTION_PASSKEY_ENABLED__/${PASSKEY_ENABLED}}"
  content="${content//__PRODUCTION_PASSKEY_RP_ID__/${PASSKEY_RP_ID}}"
  content="${content//__PRODUCTION_PASSKEY_RP_ORIGIN__/${PASSKEY_RP_ORIGIN}}"
  content="${content//__PRODUCTION_PASSKEY_CHALLENGE_PRUNE_INTERVAL_SECONDS__/${PASSKEY_CHALLENGE_PRUNE_INTERVAL_SECONDS}}"
  content="${content//__PRODUCTION_LOGIN_RISK_MODE__/${LOGIN_RISK_MODE}}"
  content="${content//__PRODUCTION_LOGIN_RISK_BLOCKED_CIDRS__/${LOGIN_RISK_BLOCKED_CIDRS}}"
  content="${content//__PRODUCTION_LOGIN_RISK_BLOCKED_USER_AGENTS__/${LOGIN_RISK_BLOCKED_USER_AGENT_SUBSTRINGS}}"
  content="${content//__PRODUCTION_LOGIN_RISK_BLOCKED_EMAIL_DOMAINS__/${LOGIN_RISK_BLOCKED_EMAIL_DOMAINS}}"
  content="${content//__PRODUCTION_LOGIN_RISK_CHALLENGE_CIDRS__/${LOGIN_RISK_CHALLENGE_CIDRS}}"
  content="${content//__PRODUCTION_LOGIN_RISK_CHALLENGE_USER_AGENTS__/${LOGIN_RISK_CHALLENGE_USER_AGENT_SUBSTRINGS}}"
  content="${content//__PRODUCTION_LOGIN_RISK_CHALLENGE_EMAIL_DOMAINS__/${LOGIN_RISK_CHALLENGE_EMAIL_DOMAINS}}"

  printf '%s\n' "${content}" >"${output_file}"
}

relative_path_with_python() {
  local from_path="$1"
  local target_path="$2"

  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to calculate overlay-to-base path"
  fi

  python3 - "$from_path" "$target_path" <<'PY'
import os
import sys

from_path = sys.argv[1]
target_path = sys.argv[2]

print(os.path.relpath(target_path, from_path))
PY
}

run_overlay_generation() {
  for var_name in "${required_vars[@]}"; do
    require_non_empty "${var_name}"
  done

  validate_image_digest
  validate_ingress_host
  validate_tls_secret_name
  validate_boolean_flag "ENFORCE_DATABASE_TLS" "${ENFORCE_DATABASE_TLS}"
  validate_boolean_flag "ENFORCE_REDIS_TLS" "${ENFORCE_REDIS_TLS}"
  validate_boolean_flag "ENFORCE_SECURE_TRANSPORT" "${ENFORCE_SECURE_TRANSPORT}"
  validate_boolean_flag "AUTH_V2_ENABLED" "${AUTH_V2_ENABLED}"
  validate_boolean_flag "AUTH_V2_METHODS_ENABLED" "${AUTH_V2_METHODS_ENABLED}"
  validate_boolean_flag "AUTH_V2_PASSWORD_PAKE_ENABLED" "${AUTH_V2_PASSWORD_PAKE_ENABLED}"
  validate_boolean_flag "AUTH_V2_PASSWORD_UPGRADE_ENABLED" "${AUTH_V2_PASSWORD_UPGRADE_ENABLED}"
  validate_boolean_flag "AUTH_V2_PASSKEY_NAMESPACE_ENABLED" "${AUTH_V2_PASSKEY_NAMESPACE_ENABLED}"
  validate_boolean_flag "AUTH_V2_AUTH_FLOWS_ENABLED" "${AUTH_V2_AUTH_FLOWS_ENABLED}"
  validate_boolean_flag "AUTH_V2_SHADOW_AUDIT_ONLY" "${AUTH_V2_SHADOW_AUDIT_ONLY}"
  validate_positive_u64 \
    "AUTH_V2_AUTH_FLOW_PRUNE_INTERVAL_SECONDS" \
    "${AUTH_V2_AUTH_FLOW_PRUNE_INTERVAL_SECONDS}"
  validate_positive_u64 \
    "AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS" \
    "${AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS}"
  validate_auth_v2_legacy_fallback_mode
  validate_passkey_configuration
  validate_login_risk_mode
  validate_cidr_with_python "POSTGRES_CIDR" "${POSTGRES_CIDR}"
  validate_cidr_with_python "REDIS_CIDR" "${REDIS_CIDR}"
  validate_optional_cidr_csv_with_python "LOGIN_RISK_BLOCKED_CIDRS" "${LOGIN_RISK_BLOCKED_CIDRS}"
  validate_optional_cidr_csv_with_python "LOGIN_RISK_CHALLENGE_CIDRS" "${LOGIN_RISK_CHALLENGE_CIDRS}"

  [[ -d "${TEMPLATES_DIR}" ]] || fail "missing templates directory: ${TEMPLATES_DIR}"
  [[ -f "${TEMPLATES_DIR}/kustomization.yaml" ]] || fail "missing template: ${TEMPLATES_DIR}/kustomization.yaml"
  [[ -f "${TEMPLATES_DIR}/ingress-production.patch.yaml" ]] || fail "missing template: ${TEMPLATES_DIR}/ingress-production.patch.yaml"
  [[ -f "${TEMPLATES_DIR}/networkpolicy-production-egress.patch.yaml" ]] || fail "missing template: ${TEMPLATES_DIR}/networkpolicy-production-egress.patch.yaml"
  [[ -f "${TEMPLATES_DIR}/configmap-runtime-security.patch.yaml" ]] || fail "missing template: ${TEMPLATES_DIR}/configmap-runtime-security.patch.yaml"
  [[ -d "${BASE_KUSTOMIZE_DIR}" ]] || fail "missing base kustomize directory: ${BASE_KUSTOMIZE_DIR}"

  load_auth_v2_normalizer

  local normalize_status=0
  normalize_auth_v2_rollout_inputs || normalize_status=$?
  if [[ ${normalize_status} -ne 0 ]]; then
    return "${normalize_status}"
  fi

  mkdir -p "${GENERATED_DIR}"

  local base_kustomize_relpath
  base_kustomize_relpath="$(relative_path_with_python "${GENERATED_DIR}" "${BASE_KUSTOMIZE_DIR}")"

  replace_tokens "${TEMPLATES_DIR}/kustomization.yaml" "${GENERATED_DIR}/kustomization.yaml" "${base_kustomize_relpath}"
  replace_tokens "${TEMPLATES_DIR}/ingress-production.patch.yaml" "${GENERATED_DIR}/ingress-production.patch.yaml" "${base_kustomize_relpath}"
  replace_tokens "${TEMPLATES_DIR}/networkpolicy-production-egress.patch.yaml" "${GENERATED_DIR}/networkpolicy-production-egress.patch.yaml" "${base_kustomize_relpath}"
  replace_tokens "${TEMPLATES_DIR}/configmap-runtime-security.patch.yaml" "${GENERATED_DIR}/configmap-runtime-security.patch.yaml" "${base_kustomize_relpath}"

  echo "Generated production overlay in ${GENERATED_DIR}"
}

self_test() {
  local temp_dir expected_allowlist actual_allowlist
  temp_dir="$(mktemp -d)"

  IMAGE_DIGEST="sha256:1111111111111111111111111111111111111111111111111111111111111111"
  INGRESS_HOST="auth.example.org"
  TLS_SECRET_NAME="auth-prod-tls"
  POSTGRES_CIDR="10.20.0.0/24"
  REDIS_CIDR="10.30.0.0/24"
  ENFORCE_DATABASE_TLS="true"
  ENFORCE_REDIS_TLS="true"
  ENFORCE_SECURE_TRANSPORT="true"
  AUTH_V2_ENABLED="true"
  AUTH_V2_METHODS_ENABLED="true"
  AUTH_V2_PASSWORD_PAKE_ENABLED="true"
  AUTH_V2_PASSWORD_UPGRADE_ENABLED="true"
  AUTH_V2_PASSKEY_NAMESPACE_ENABLED="false"
  AUTH_V2_AUTH_FLOWS_ENABLED="true"
  AUTH_V2_LEGACY_FALLBACK_MODE="allowlisted"
  AUTH_V2_CLIENT_ALLOWLIST=" internal-web , ios-beta , internal , IOS "
  AUTH_V2_SHADOW_AUDIT_ONLY="false"
  AUTH_V2_AUTH_FLOW_PRUNE_INTERVAL_SECONDS="300"
  AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS="25"
  PASSKEY_ENABLED="false"
  PASSKEY_RP_ID=""
  PASSKEY_RP_ORIGIN=""
  PASSKEY_CHALLENGE_PRUNE_INTERVAL_SECONDS="60"
  LOGIN_RISK_MODE="baseline"
  LOGIN_RISK_BLOCKED_CIDRS=""
  LOGIN_RISK_BLOCKED_USER_AGENT_SUBSTRINGS=""
  LOGIN_RISK_BLOCKED_EMAIL_DOMAINS=""
  LOGIN_RISK_CHALLENGE_CIDRS=""
  LOGIN_RISK_CHALLENGE_USER_AGENT_SUBSTRINGS=""
  LOGIN_RISK_CHALLENGE_EMAIL_DOMAINS=""
  GENERATED_DIR="${temp_dir}/generated"

  run_overlay_generation >/dev/null

  expected_allowlist='  AUTH_V2_CLIENT_ALLOWLIST: "internal,canary_mobile"'
  actual_allowlist="$(python3 - "${GENERATED_DIR}/configmap-runtime-security.patch.yaml" <<'PY'
import pathlib
import re
import sys

content = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r'^\s*AUTH_V2_CLIENT_ALLOWLIST:\s*".*"\s*$', content, re.MULTILINE)
if match is None:
    raise SystemExit("missing AUTH_V2_CLIENT_ALLOWLIST in generated configmap patch")
print(match.group(0))
PY
)"
  overlay_assert_eq "${actual_allowlist}" "${expected_allowlist}" "normalizes rollout allowlist before templating"

  AUTH_V2_CLIENT_ALLOWLIST=""
  GENERATED_DIR="${temp_dir}/generated-empty"
  run_overlay_generation >/dev/null
  actual_allowlist="$(python3 - "${GENERATED_DIR}/configmap-runtime-security.patch.yaml" <<'PY'
import pathlib
import re
import sys

content = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r'^\s*AUTH_V2_CLIENT_ALLOWLIST:\s*".*"\s*$', content, re.MULTILINE)
if match is None:
    raise SystemExit("missing AUTH_V2_CLIENT_ALLOWLIST in generated configmap patch")
print(match.group(0))
PY
)"
  overlay_assert_eq "${actual_allowlist}" '  AUTH_V2_CLIENT_ALLOWLIST: ""' "preserves an empty rollout allowlist"

  AUTH_V2_CLIENT_ALLOWLIST="partner-preview"
  GENERATED_DIR="${temp_dir}/generated-invalid"
  overlay_assert_fails \
    "unsupported AUTH_V2_CLIENT_ALLOWLIST value: partner-preview" \
    run_overlay_generation

  rm -rf "${temp_dir}"
  printf 'production overlay auth v2 self-test passed\n'
}

main() {
  if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    return 0
  fi

  if [[ "$#" -gt 0 ]]; then
    printf 'usage: %s [--self-test]\n' "$0" >&2
    return 1
  fi

  run_overlay_generation
}

main "$@"
