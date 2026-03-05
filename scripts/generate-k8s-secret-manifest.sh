#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_OUTPUT_PATH="${ROOT_DIR}/artifacts/production-secrets/auth-api-secrets.yaml"
OUTPUT_PATH="${OUTPUT_SECRET_MANIFEST:-${1:-${DEFAULT_OUTPUT_PATH}}}"

required_vars=(
  DATABASE_URL
  REDIS_URL
  REFRESH_TOKEN_PEPPER
  MFA_ENCRYPTION_KEY_BASE64
  JWT_KEYSET
  JWT_PRIMARY_KID
)

optional_vars=(
  METRICS_BEARER_TOKEN
  SENDGRID_API_KEY
  SENDGRID_FROM_EMAIL
  VERIFY_EMAIL_URL_BASE
  PASSWORD_RESET_URL_BASE
)

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_non_empty() {
  local var_name="$1"
  local value="${!var_name:-}"
  if [[ -z "${value}" ]]; then
    fail "required variable '${var_name}' is missing or empty"
  fi
}

reject_placeholder_like_value() {
  local var_name="$1"
  local value="$2"
  local lower

  lower="$(printf '%s' "${value}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${lower}" == *"replace_me"* ]] || [[ "${lower}" == *"replace_with_"* ]] || [[ "${lower}" == *"example.internal"* ]]; then
    fail "variable '${var_name}' looks like a placeholder value; set a production value"
  fi
}

yaml_quote() {
  local value="$1"
  value=${value//\'/\'\'}
  printf "'%s'" "${value}"
}

main() {
  local var_name
  local parent_dir

  for var_name in "${required_vars[@]}"; do
    require_non_empty "${var_name}"
    reject_placeholder_like_value "${var_name}" "${!var_name}"
  done

  parent_dir="$(dirname "${OUTPUT_PATH}")"
  mkdir -p "${parent_dir}"

  umask 077
  {
    echo "apiVersion: v1"
    echo "kind: Secret"
    echo "metadata:"
    echo "  name: auth-api-secrets"
    echo "  namespace: auth"
    echo "type: Opaque"
    echo "stringData:"

    for var_name in "${required_vars[@]}"; do
      printf '  %s: %s\n' "${var_name}" "$(yaml_quote "${!var_name}")"
    done

    for var_name in "${optional_vars[@]}"; do
      if [[ -n "${!var_name:-}" ]]; then
        printf '  %s: %s\n' "${var_name}" "$(yaml_quote "${!var_name}")"
      fi
    done
  } >"${OUTPUT_PATH}"

  echo "Generated Kubernetes secret manifest at ${OUTPUT_PATH}"
}

main "$@"
