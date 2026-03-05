#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def metric_value(summary: dict, metric_name: str, key: str):
    metric = summary.get("metrics", {}).get(metric_name, {})
    values = metric.get("values", {})
    return values.get(key)


def to_number(value):
    if value is None:
        return None
    return float(value)


def build_check(name: str, actual, comparator: str, threshold: float, reference: str):
    if actual is None:
        return {
            "name": name,
            "actual": None,
            "comparator": comparator,
            "threshold": threshold,
            "pass": False,
            "reference": reference,
            "note": "metric missing in k6 summary",
        }

    passed = actual <= threshold if comparator == "<=" else actual >= threshold
    return {
        "name": name,
        "actual": actual,
        "comparator": comparator,
        "threshold": threshold,
        "pass": passed,
        "reference": reference,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate auth load KPI gates from k6 summary export")
    parser.add_argument("--summary", required=True, help="Path to k6 summary export JSON")
    parser.add_argument("--output", required=True, help="Path to KPI evaluation JSON output")
    parser.add_argument("--mode", required=True, help="Execution mode (load/soak)")
    parser.add_argument("--login-p95-ms", type=float, default=300.0)
    parser.add_argument("--refresh-p95-ms", type=float, default=200.0)
    parser.add_argument("--me-p95-ms", type=float, default=250.0)
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--min-throughput-rps", type=float, default=200.0)
    args = parser.parse_args()

    summary_path = Path(args.summary)
    output_path = Path(args.output)

    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    login_p95_ms = to_number(metric_value(summary, "login_duration", "p(95)"))
    refresh_p95_ms = to_number(metric_value(summary, "refresh_duration", "p(95)"))
    me_p95_ms = to_number(metric_value(summary, "me_duration", "p(95)"))
    auth_error_rate = to_number(metric_value(summary, "auth_flow_error_rate", "rate"))
    throughput_rps = to_number(metric_value(summary, "http_reqs", "rate"))

    checks = [
        build_check(
            "login_p95_ms",
            login_p95_ms,
            "<=",
            args.login_p95_ms,
            "PRD 3 KPI: p95 POST /v1/auth/login < 300ms",
        ),
        build_check(
            "refresh_p95_ms",
            refresh_p95_ms,
            "<=",
            args.refresh_p95_ms,
            "PRD 3 KPI: p95 POST /v1/auth/token/refresh < 200ms",
        ),
        build_check(
            "me_p95_ms",
            me_p95_ms,
            "<=",
            args.me_p95_ms,
            "Operational guardrail for GET /v1/auth/me in critical flow",
        ),
        build_check(
            "error_rate",
            auth_error_rate,
            "<=",
            args.max_error_rate,
            "PRD 3 KPI: error rate in nominal load < 1%",
        ),
        build_check(
            "throughput_rps",
            throughput_rps,
            ">=",
            args.min_throughput_rps,
            "PRD 9 NFR / 14.4: sustained throughput >= 200 req/s",
        ),
    ]

    overall_pass = all(item["pass"] for item in checks)
    payload = {
        "mode": args.mode,
        "overall_pass": overall_pass,
        "checks": checks,
        "source_summary": str(summary_path),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"KPI result ({args.mode}): {'PASS' if overall_pass else 'FAIL'}")
    for item in checks:
        actual = "n/a" if item["actual"] is None else f"{item['actual']:.3f}"
        print(
            f"- {item['name']}: {actual} {item['comparator']} {item['threshold']} => "
            f"{'PASS' if item['pass'] else 'FAIL'}"
        )

    raise SystemExit(0 if overall_pass else 1)


if __name__ == "__main__":
    main()
