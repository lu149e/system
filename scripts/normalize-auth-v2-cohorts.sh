#!/usr/bin/env bash

set -euo pipefail

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

resolve_auth_v2_cohort() {
  local value
  value="$(trim "$1")"
  value="${value,,}"

  case "${value}" in
    "")
      return 1
      ;;
    internal|internal-web|staff|qa)
      printf 'internal\n'
      ;;
    canary_web|web)
      printf 'canary_web\n'
      ;;
    canary_mobile|ios|android|ios-beta|android-beta)
      printf 'canary_mobile\n'
      ;;
    beta_external|external-beta)
      printf 'beta_external\n'
      ;;
    broad_general|general|prod)
      printf 'broad_general\n'
      ;;
    legacy_holdout|legacy)
      printf 'legacy_holdout\n'
      ;;
    *)
      printf 'unsupported AUTH_V2_CLIENT_ALLOWLIST value: %s\n' "${value}" >&2
      return 2
      ;;
  esac
}

normalize_auth_v2_cohort_csv() {
  local raw_csv="$1"
  local -A seen=()
  local -a normalized_values=()
  local entry normalized

  IFS=',' read -r -a entries <<< "${raw_csv}"
  for entry in "${entries[@]}"; do
    entry="$(trim "${entry}")"
    if [[ -z "${entry}" ]]; then
      continue
    fi

    if normalized="$(resolve_auth_v2_cohort "${entry}")"; then
      :
    else
      return $?
    fi

    if [[ -z "${seen[${normalized}]:-}" ]]; then
      seen["${normalized}"]=1
      normalized_values+=("${normalized}")
    fi
  done

  local joined=""
  for normalized in "${normalized_values[@]}"; do
    if [[ -n "${joined}" ]]; then
      joined+="," 
    fi
    joined+="${normalized}"
  done

  printf '%s\n' "${joined}"
}

assert_eq() {
  local actual="$1"
  local expected="$2"
  local message="$3"

  if [[ "${actual}" != "${expected}" ]]; then
    printf 'self-test failed: %s\nexpected: %s\nactual: %s\n' "${message}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

assert_fails() {
  local input="$1"
  local expected_message="$2"
  local output

  if output="$(normalize_auth_v2_cohort_csv "${input}" 2>&1)"; then
    printf 'self-test failed: expected normalization to fail for %s\n' "${input}" >&2
    exit 1
  fi

  if [[ "${output}" != *"${expected_message}"* ]]; then
    printf 'self-test failed: unexpected failure output for %s\noutput: %s\n' "${input}" "${output}" >&2
    exit 1
  fi
}

self_test() {
  assert_eq \
    "$(normalize_auth_v2_cohort_csv ' canary_web , WEB , ios-beta ,, internal-web , IOS ')" \
    "canary_web,canary_mobile,internal" \
    "normalizes aliases and deduplicates cohorts"
  assert_eq \
    "$(normalize_auth_v2_cohort_csv 'beta_external,prod,legacy,qa')" \
    "beta_external,broad_general,legacy_holdout,internal" \
    "normalizes the full canonical cohort vocabulary"
  assert_eq \
    "$(normalize_auth_v2_cohort_csv '')" \
    "" \
    "preserves an empty allowlist"
  assert_fails \
    'canary_web,partner-preview' \
    'unsupported AUTH_V2_CLIENT_ALLOWLIST value: partner-preview'

  printf 'auth v2 cohort normalization self-test passed\n'
}

main() {
  if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    return 0
  fi

  if [[ "$#" -gt 1 ]]; then
    printf 'usage: %s [CSV_ALLOWLIST | --self-test]\n' "$0" >&2
    return 1
  fi

  normalize_auth_v2_cohort_csv "${1:-}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
