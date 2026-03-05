#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K8S_DIR="${ROOT_DIR}/deploy/k8s"
ARTIFACT_DIR="${ROOT_DIR}/artifacts/k8s-manifest-validation"
STRICT_K8S_VALIDATION="${STRICT_K8S_VALIDATION:-false}"

failures=0
warnings=0

strict_mode_enabled() {
  case "${STRICT_K8S_VALIDATION,,}" in
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

check_placeholder_values() {
  info "Checking unresolved placeholders in ${K8S_DIR}"

  local report_file="${ARTIFACT_DIR}/placeholder-report.txt"
  if python3 - "${K8S_DIR}" "${report_file}" <<'PY'; then
import pathlib
import re
import sys

base_dir = pathlib.Path(sys.argv[1])
report_file = pathlib.Path(sys.argv[2])

patterns = [
    (re.compile(r"ghcr\.io/example(?:/|:)"), "example image registry placeholder"),
    (re.compile(r"\b(?:192\.0\.2\.0/24|198\.51\.100\.0/24|203\.0\.113\.0/24)\b"), "TEST-NET placeholder CIDR"),
    (re.compile(r"\bREPLACE_ME\b"), "REPLACE_ME placeholder"),
    (re.compile(r"\breplace_me\b"), "replace_me placeholder"),
    (re.compile(r"\breplace_with_[a-zA-Z0-9_]+\b"), "replace_with_* placeholder"),
    (re.compile(r"\bauth\.example\.com\b"), "example ingress hostname placeholder"),
    (re.compile(r"\bexample\.internal\b"), "example internal domain placeholder"),
    (re.compile(r"^\s*image:\s*[^#]+:stable\s*$"), "non-pinned image tag placeholder (:stable)"),
]

ignored_suffixes = (".template.yaml", ".template.yml")
matches = []

for file_path in sorted(base_dir.glob("*.y*ml")):
    if file_path.name.endswith(ignored_suffixes):
        continue
    lines = file_path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern, description in patterns:
            if pattern.search(line):
                matches.append((file_path, line_number, description, line.rstrip()))

report_file.parent.mkdir(parents=True, exist_ok=True)
with report_file.open("w", encoding="utf-8") as f:
    if not matches:
        f.write("No unresolved placeholders detected.\n")
    else:
        for path, line_number, description, line in matches:
            rel_path = path.relative_to(base_dir.parent.parent)
            f.write(f"{rel_path}:{line_number}: {description} -> {line}\n")

if matches:
    print(f"Found {len(matches)} unresolved placeholder value(s).")
    sys.exit(2)

print("No unresolved placeholders found.")
PY
    info "Placeholder detection completed"
  else
    fail "unresolved placeholders detected (see ${report_file})"
  fi
}

validate_yaml_syntax() {
  info "Validating YAML syntax in ${K8S_DIR}"
  local syntax_report="${ARTIFACT_DIR}/yaml-syntax.log"

  if command -v yamllint >/dev/null 2>&1; then
    local yamllint_config='{extends: default, rules: {document-start: disable, line-length: disable}}'
    if yamllint -d "${yamllint_config}" "${K8S_DIR}" >"${syntax_report}" 2>&1; then
      info "YAML syntax validation passed with yamllint"
    else
      fail "YAML syntax validation failed (yamllint, see ${syntax_report})"
    fi
    return
  fi

  if command -v yq >/dev/null 2>&1; then
    local rc=0
    : >"${syntax_report}"
    for file in "${K8S_DIR}"/*.yaml; do
      if ! yq eval '.' "${file}" >/dev/null 2>>"${syntax_report}"; then
        rc=1
      fi
    done
    if [[ ${rc} -eq 0 ]]; then
      info "YAML syntax validation passed with yq"
    else
      fail "YAML syntax validation failed (yq, see ${syntax_report})"
    fi
    return
  fi

  if python3 - "${K8S_DIR}" >"${syntax_report}" 2>&1 <<'PY'; then
import pathlib
import sys

base_dir = pathlib.Path(sys.argv[1])
try:
    import yaml
except ModuleNotFoundError as exc:
    raise SystemExit(f"PyYAML not installed: {exc}")

for file_path in sorted(base_dir.glob("*.yaml")):
    with file_path.open("r", encoding="utf-8") as f:
        list(yaml.safe_load_all(f))
    print(f"OK: {file_path}")
PY
    info "YAML syntax validation passed with python3 + PyYAML"
    return
  fi

  warn_or_fail_missing_tool "yamllint/yq/python3+PyYAML" "YAML syntax validation"
}

render_with_kustomize_if_available() {
  local rendered_file="${ARTIFACT_DIR}/kustomize-rendered.yaml"
  if command -v kustomize >/dev/null 2>&1; then
    info "Rendering manifests via kustomize"
    if kustomize build "${K8S_DIR}" >"${rendered_file}" 2>"${ARTIFACT_DIR}/kustomize.log"; then
      info "Kustomize render succeeded (${rendered_file})"
    else
      fail "kustomize render failed (see ${ARTIFACT_DIR}/kustomize.log)"
    fi
    return
  fi

  warn_or_fail_missing_tool "kustomize" "rendering full manifest set"
  warn "Falling back to basic file-level validation (no rendered manifest available)"
}

validate_basic_file_level_sanity() {
  info "Running basic file-level Kubernetes resource checks"
  local report_file="${ARTIFACT_DIR}/basic-file-checks.log"

  if python3 - "${K8S_DIR}" >"${report_file}" 2>&1 <<'PY'; then
import pathlib
import re
import sys

base_dir = pathlib.Path(sys.argv[1])
resource_files = sorted(
    p for p in base_dir.glob("*.yaml") if p.name != "kustomization.yaml"
)

missing = []
for file_path in resource_files:
    text = file_path.read_text(encoding="utf-8")
    if not re.search(r"(?m)^\s*apiVersion\s*:\s*", text):
        missing.append((file_path, "apiVersion"))
    if not re.search(r"(?m)^\s*kind\s*:\s*", text):
        missing.append((file_path, "kind"))

if missing:
    for path, field in missing:
        print(f"MISSING {field}: {path}")
    sys.exit(3)

for file_path in resource_files:
    print(f"OK basic checks: {file_path}")
PY
    info "Basic file-level checks passed"
  else
    fail "basic file-level checks failed (see ${report_file})"
  fi
}

validate_kubeconform_if_available() {
  local rendered_file="${ARTIFACT_DIR}/kustomize-rendered.yaml"
  local report_file="${ARTIFACT_DIR}/kubeconform.log"

  if ! command -v kubeconform >/dev/null 2>&1; then
    warn_or_fail_missing_tool "kubeconform" "Kubernetes schema validation"
    return
  fi

  info "Running kubeconform schema validation"

  if [[ -s "${rendered_file}" ]]; then
    if kubeconform -strict -summary "${rendered_file}" >"${report_file}" 2>&1; then
      info "kubeconform validation passed for rendered manifest"
    else
      fail "kubeconform validation failed (see ${report_file})"
    fi
    return
  fi

  local resource_files=()
  for file in "${K8S_DIR}"/*.yaml; do
    if [[ "$(basename "${file}")" == "kustomization.yaml" ]]; then
      continue
    fi
    resource_files+=("${file}")
  done

  if kubeconform -strict -summary "${resource_files[@]}" >"${report_file}" 2>&1; then
    info "kubeconform validation passed for file-level manifests"
  else
    fail "kubeconform validation failed (see ${report_file})"
  fi
}

main() {
  cd "${ROOT_DIR}"
  mkdir -p "${ARTIFACT_DIR}"

  info "Starting Kubernetes manifest validation"
  info "STRICT_K8S_VALIDATION=${STRICT_K8S_VALIDATION}"

  check_placeholder_values
  validate_yaml_syntax
  render_with_kustomize_if_available
  validate_basic_file_level_sanity
  validate_kubeconform_if_available

  if [[ ${failures} -gt 0 ]]; then
    echo ""
    echo "Validation failed: ${failures} error(s), ${warnings} warning(s)." >&2
    echo "Artifacts: ${ARTIFACT_DIR}" >&2
    exit 1
  fi

  echo ""
  echo "Validation passed with ${warnings} warning(s)."
  echo "Artifacts: ${ARTIFACT_DIR}"
}

main "$@"
