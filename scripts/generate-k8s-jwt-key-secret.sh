#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_OUTPUT_PATH="${ROOT_DIR}/artifacts/production-secrets/auth-jwt-keys.yaml"
OUTPUT_PATH="${OUTPUT_JWT_SECRET_MANIFEST:-${1:-${DEFAULT_OUTPUT_PATH}}}"

required_vars=(
  JWT_PRIVATE_KEY_PEM
  JWT_PUBLIC_KEY_PEM
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

validate_pem() {
  local var_name="$1"
  local value="${!var_name}"
  if [[ "${value}" != *"-----BEGIN "* ]] || [[ "${value}" != *"-----END "* ]]; then
    fail "variable '${var_name}' must contain a PEM value"
  fi
}

yaml_quote_multiline() {
  local value="$1"
  local prefix="$2"
  while IFS= read -r line; do
    printf '%s%s\n' "${prefix}" "${line}"
  done <<<"${value}"
}

main() {
  local var_name
  local parent_dir

  for var_name in "${required_vars[@]}"; do
    require_non_empty "${var_name}"
    validate_pem "${var_name}"
  done

  parent_dir="$(dirname "${OUTPUT_PATH}")"
  mkdir -p "${parent_dir}"

  umask 077
  {
    echo "apiVersion: v1"
    echo "kind: Secret"
    echo "metadata:"
    echo "  name: auth-jwt-keys"
    echo "  namespace: auth"
    echo "type: Opaque"
    echo "stringData:"
    echo "  private.pem: |-"
    yaml_quote_multiline "${JWT_PRIVATE_KEY_PEM}" "    "
    echo "  public.pem: |-"
    yaml_quote_multiline "${JWT_PUBLIC_KEY_PEM}" "    "
  } >"${OUTPUT_PATH}"

  echo "Generated Kubernetes JWT key secret manifest at ${OUTPUT_PATH}"
}

main "$@"
