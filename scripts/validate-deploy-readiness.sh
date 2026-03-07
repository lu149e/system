#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRODUCTION_OVERLAY_GENERATED_DIR="${ROOT_DIR}/artifacts/production-overlay/generated"
ARTIFACT_DIR="${ROOT_DIR}/artifacts/deploy-readiness"
STRICT_DEPLOY_VALIDATION="${STRICT_DEPLOY_VALIDATION:-false}"

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

failures=0
warnings=0

strict_mode_enabled() {
  case "${STRICT_DEPLOY_VALIDATION,,}" in
    true|1|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

info() {
  echo "INFO: $*"
}

warn() {
  echo "WARN: $*" >&2
  warnings=$((warnings + 1))
}

fail() {
  echo "ERROR: $*" >&2
  failures=$((failures + 1))
}

warn_or_fail_missing_tool() {
  local tool="$1"
  local purpose="$2"
  if strict_mode_enabled; then
    fail "missing optional tool '${tool}' required for strict mode (${purpose})"
  else
    warn "missing optional tool '${tool}' (${purpose}); continuing with fallback checks"
  fi
}

assert_generated_production_overlay_exists() {
  if [[ ! -d "${PRODUCTION_OVERLAY_GENERATED_DIR}" ]]; then
    fail "missing generated production overlay directory: ${PRODUCTION_OVERLAY_GENERATED_DIR}"
    fail "run scripts/generate-production-overlay.sh with required environment variables before validation"
    return
  fi

  if [[ ! -f "${PRODUCTION_OVERLAY_GENERATED_DIR}/kustomization.yaml" ]]; then
    fail "missing generated production overlay kustomization: ${PRODUCTION_OVERLAY_GENERATED_DIR}/kustomization.yaml"
    fail "run scripts/generate-production-overlay.sh with required environment variables before validation"
  fi

  if [[ ! -f "${PRODUCTION_OVERLAY_GENERATED_DIR}/ingress-production.patch.yaml" ]]; then
    fail "missing generated ingress patch: ${PRODUCTION_OVERLAY_GENERATED_DIR}/ingress-production.patch.yaml"
  fi

  if [[ ! -f "${PRODUCTION_OVERLAY_GENERATED_DIR}/networkpolicy-production-egress.patch.yaml" ]]; then
    fail "missing generated network policy patch: ${PRODUCTION_OVERLAY_GENERATED_DIR}/networkpolicy-production-egress.patch.yaml"
  fi
}

check_unresolved_placeholders() {
  info "Checking unresolved placeholder tokens in generated production overlay"
  local report_file="${ARTIFACT_DIR}/production-placeholder-report.txt"
  local pattern='(__[A-Z0-9_]+__|REPLACE_ME|replace_me|replace_with_[A-Za-z0-9_]+|auth\.example\.com|example\.internal|(192\.0\.2\.0/24|198\.51\.100\.0/24|203\.0\.113\.0/24)|sha256:a{64})'

  if grep -R -n -E --include='*.yaml' --include='*.yml' "${pattern}" "${PRODUCTION_OVERLAY_GENERATED_DIR}" >"${report_file}"; then
    fail "unresolved placeholders detected in generated production overlay (see ${report_file})"
    return
  fi

  echo "No unresolved placeholders detected in generated overlay." >"${report_file}"
  info "No unresolved placeholders found"
}

render_production_overlay_if_available() {
  local rendered_file="${ARTIFACT_DIR}/production-rendered.yaml"
  local render_log_file="${ARTIFACT_DIR}/production-kustomize.log"

  if command -v kustomize >/dev/null 2>&1; then
    info "Rendering generated production overlay with kustomize"
    if kustomize build "${PRODUCTION_OVERLAY_GENERATED_DIR}" >"${rendered_file}" 2>"${render_log_file}"; then
      info "Kustomize render succeeded (${rendered_file})"
    else
      fail "kustomize render failed for generated production overlay (see ${render_log_file})"
    fi
    return
  fi

  warn_or_fail_missing_tool "kustomize" "production overlay render"
}

check_production_images_digest_pinned() {
  info "Checking production image pinning policy"
  local digest_report_file="${ARTIFACT_DIR}/production-image-digest-report.txt"
  local rendered_file="${ARTIFACT_DIR}/production-rendered.yaml"
  local production_kustomization="${PRODUCTION_OVERLAY_GENERATED_DIR}/kustomization.yaml"
  local has_failure=0

  : >"${digest_report_file}"

  if [[ -s "${rendered_file}" ]]; then
    local image_line
    local image_ref
    local has_images=0
    while IFS= read -r image_line; do
      has_images=1
      image_ref="${image_line#*image: }"
      image_ref="${image_ref%% *}"
      if [[ ! "${image_ref}" =~ @sha256:[0-9a-f]{64}$ ]]; then
        printf 'Non-digest image in rendered manifest: %s\n' "${image_ref}" >>"${digest_report_file}"
        has_failure=1
      fi
    done < <(grep -E '^[[:space:]]*image:[[:space:]]*' "${rendered_file}" || true)

    if [[ ${has_images} -eq 0 ]]; then
      printf 'No image fields found in rendered generated production overlay.\n' >>"${digest_report_file}"
      has_failure=1
    fi
  else
    if grep -E '^[[:space:]]*digest:[[:space:]]*sha256:[0-9a-f]{64}$' "${production_kustomization}" >/dev/null 2>&1; then
      printf 'Found digest field in production kustomization (fallback check).\n' >>"${digest_report_file}"
    else
      printf 'Missing digest pin in production kustomization image override.\n' >>"${digest_report_file}"
      has_failure=1
    fi
  fi

  if [[ ${has_failure} -ne 0 ]]; then
    fail "production overlay image policy requires digest pinning (see ${digest_report_file})"
    return
  fi

  info "Production image digest pinning check passed"
}

check_auth_v2_rollout_contract() {
  info "Checking auth v2 rollout contract in generated production overlay"

  local configmap_patch="${PRODUCTION_OVERLAY_GENERATED_DIR}/configmap-runtime-security.patch.yaml"
  local report_file="${ARTIFACT_DIR}/production-auth-v2-rollout-report.txt"

  if [[ ! -f "${configmap_patch}" ]]; then
    fail "missing generated configmap patch: ${configmap_patch}"
    return
  fi

  if ! python3 - "${configmap_patch}" "${report_file}" \
    "AUTH_V2_ENABLED=${AUTH_V2_ENABLED}" \
    "AUTH_V2_METHODS_ENABLED=${AUTH_V2_METHODS_ENABLED}" \
    "AUTH_V2_PASSWORD_PAKE_ENABLED=${AUTH_V2_PASSWORD_PAKE_ENABLED}" \
    "AUTH_V2_PASSWORD_UPGRADE_ENABLED=${AUTH_V2_PASSWORD_UPGRADE_ENABLED}" \
    "AUTH_V2_PASSKEY_NAMESPACE_ENABLED=${AUTH_V2_PASSKEY_NAMESPACE_ENABLED}" \
    "AUTH_V2_AUTH_FLOWS_ENABLED=${AUTH_V2_AUTH_FLOWS_ENABLED}" \
    "AUTH_V2_LEGACY_FALLBACK_MODE=${AUTH_V2_LEGACY_FALLBACK_MODE}" \
    "AUTH_V2_CLIENT_ALLOWLIST=${AUTH_V2_CLIENT_ALLOWLIST}" \
    "AUTH_V2_SHADOW_AUDIT_ONLY=${AUTH_V2_SHADOW_AUDIT_ONLY}" \
    "AUTH_V2_AUTH_FLOW_PRUNE_INTERVAL_SECONDS=${AUTH_V2_AUTH_FLOW_PRUNE_INTERVAL_SECONDS}" <<'PY'
import pathlib
import re
import sys

patch_path = pathlib.Path(sys.argv[1])
report_path = pathlib.Path(sys.argv[2])
expected_pairs = [arg.split("=", 1) for arg in sys.argv[3:]]
content = patch_path.read_text(encoding="utf-8")
errors = []
lines = []

for key, expected in expected_pairs:
    pattern = re.compile(rf"^\s*{re.escape(key)}:\s*\"(.*)\"\s*$", re.MULTILINE)
    match = pattern.search(content)
    if match is None:
        errors.append(f"missing key in generated configmap patch: {key}")
        continue

    actual = match.group(1)
    if actual != expected:
        errors.append(
            f"{key} mismatch: expected {expected!r}, found {actual!r} in generated configmap patch"
        )
    else:
        lines.append(f"OK {key}={actual!r}")

feature_flags = {
    "AUTH_V2_METHODS_ENABLED": dict(expected_pairs).get("AUTH_V2_METHODS_ENABLED", "false"),
    "AUTH_V2_PASSWORD_PAKE_ENABLED": dict(expected_pairs).get("AUTH_V2_PASSWORD_PAKE_ENABLED", "false"),
    "AUTH_V2_PASSWORD_UPGRADE_ENABLED": dict(expected_pairs).get("AUTH_V2_PASSWORD_UPGRADE_ENABLED", "false"),
    "AUTH_V2_PASSKEY_NAMESPACE_ENABLED": dict(expected_pairs).get("AUTH_V2_PASSKEY_NAMESPACE_ENABLED", "false"),
    "AUTH_V2_AUTH_FLOWS_ENABLED": dict(expected_pairs).get("AUTH_V2_AUTH_FLOWS_ENABLED", "false"),
}

auth_v2_enabled = dict(expected_pairs).get("AUTH_V2_ENABLED", "false")
if auth_v2_enabled != "true":
    enabled_children = [name for name, value in feature_flags.items() if value == "true"]
    if enabled_children:
        errors.append(
            "AUTH_V2_ENABLED=false is inconsistent with enabled child rollout flags: "
            + ", ".join(enabled_children)
        )

report_lines = [f"Validated auth v2 rollout contract in {patch_path}."]
report_lines.extend(lines)
if errors:
    report_lines.append("")
    report_lines.append("Errors:")
    report_lines.extend(f"- {error}" for error in errors)

report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY
  then
    fail "auth v2 rollout contract validation failed (see ${report_file})"
    return
  fi

  info "Auth v2 rollout contract check passed"
}

main() {
  cd "${ROOT_DIR}"
  mkdir -p "${ARTIFACT_DIR}"

  info "Starting deploy readiness validation"
  info "STRICT_DEPLOY_VALIDATION=${STRICT_DEPLOY_VALIDATION}"

  assert_generated_production_overlay_exists
  check_unresolved_placeholders
  render_production_overlay_if_available
  check_production_images_digest_pinned
  check_auth_v2_rollout_contract

  if [[ ${failures} -gt 0 ]]; then
    echo ""
    echo "Deploy readiness validation failed: ${failures} error(s), ${warnings} warning(s)." >&2
    echo "Artifacts: ${ARTIFACT_DIR}" >&2
    exit 1
  fi

  echo ""
  echo "Deploy readiness validation passed with ${warnings} warning(s)."
  echo "Artifacts: ${ARTIFACT_DIR}"
}

main "$@"
