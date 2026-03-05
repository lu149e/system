#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATES_DIR="${ROOT_DIR}/deploy/k8s/overlays/production/templates"
GENERATED_DIR="${ROOT_DIR}/artifacts/production-overlay/generated"
BASE_KUSTOMIZE_DIR="${ROOT_DIR}/deploy/k8s"

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

main() {
  for var_name in "${required_vars[@]}"; do
    require_non_empty "${var_name}"
  done

  validate_image_digest
  validate_ingress_host
  validate_tls_secret_name
  validate_cidr_with_python "POSTGRES_CIDR" "${POSTGRES_CIDR}"
  validate_cidr_with_python "REDIS_CIDR" "${REDIS_CIDR}"

  [[ -d "${TEMPLATES_DIR}" ]] || fail "missing templates directory: ${TEMPLATES_DIR}"
  [[ -f "${TEMPLATES_DIR}/kustomization.yaml" ]] || fail "missing template: ${TEMPLATES_DIR}/kustomization.yaml"
  [[ -f "${TEMPLATES_DIR}/ingress-production.patch.yaml" ]] || fail "missing template: ${TEMPLATES_DIR}/ingress-production.patch.yaml"
  [[ -f "${TEMPLATES_DIR}/networkpolicy-production-egress.patch.yaml" ]] || fail "missing template: ${TEMPLATES_DIR}/networkpolicy-production-egress.patch.yaml"
  [[ -d "${BASE_KUSTOMIZE_DIR}" ]] || fail "missing base kustomize directory: ${BASE_KUSTOMIZE_DIR}"

  mkdir -p "${GENERATED_DIR}"

  local base_kustomize_relpath
  base_kustomize_relpath="$(relative_path_with_python "${GENERATED_DIR}" "${BASE_KUSTOMIZE_DIR}")"

  replace_tokens "${TEMPLATES_DIR}/kustomization.yaml" "${GENERATED_DIR}/kustomization.yaml" "${base_kustomize_relpath}"
  replace_tokens "${TEMPLATES_DIR}/ingress-production.patch.yaml" "${GENERATED_DIR}/ingress-production.patch.yaml" "${base_kustomize_relpath}"
  replace_tokens "${TEMPLATES_DIR}/networkpolicy-production-egress.patch.yaml" "${GENERATED_DIR}/networkpolicy-production-egress.patch.yaml" "${base_kustomize_relpath}"

  echo "Generated production overlay in ${GENERATED_DIR}"
}

main "$@"
