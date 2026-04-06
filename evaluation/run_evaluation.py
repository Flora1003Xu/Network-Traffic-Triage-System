#!/usr/bin/env python3
"""
Automated evaluation script for n8n SOC triage pipeline.
Sends each test case to n8n webhook and compares against expected verdicts.

Usage:
  python3 run_evaluation.py

Requirements:
  pip3 install requests
"""

import json
import time
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings()

# ── CONFIG ─────────────────────────────────────────────────────────────────
N8N_WEBHOOK_URL = "http://localhost:5678/webhook/soc-triage"
# If you're still using the Chat trigger for manual testing, set:
# N8N_WEBHOOK_URL = None  (script will print inputs to paste manually)
DELAY_BETWEEN_TESTS = 3  # seconds, avoid rate limiting Gemini
# ───────────────────────────────────────────────────────────────────────────

def extract_verdict(response_text):
    if not response_text:
        return None, None
    # 把整个 response 转成字符串来搜索
    text = str(response_text).lower()
    verdict = None
    severity = None
    for v in ["malicious", "suspicious", "benign"]:
        if v in text:
            verdict = v
            break
    for s in ["critical", "high", "medium", "low"]:
        if s in text:
            severity = s.capitalize()
            break
    return verdict, severity

def load_test_cases():
    with open("test_cases.json") as f:
        return json.load(f)["test_cases"]

def send_to_n8n(test_case):
    payload = json.dumps(test_case["input"])
    if N8N_WEBHOOK_URL:
        try:
            resp = requests.post(
                N8N_WEBHOOK_URL,
                json={"chatInput": payload},
                timeout=120,
                verify=False
            )
            return resp.json()
        except Exception as e:
            return {"error": str(e)}
    else:
        print(f"\n── Paste into n8n chat for {test_case['id']} ──")
        print(payload)
        return None

def evaluate(test_case, response):
    expected_v = test_case["expected_verdict"]
    expected_s = test_case["expected_severity"]

    if response and "error" not in response:
        response_text = response.get("response") or response.get("output") or str(response)
        got_verdict, got_severity = extract_verdict(response_text)
    else:
        got_verdict, got_severity = None, None

    verdict_match = (got_verdict == expected_v)
    # For benign cases severity is null so skip severity check
    severity_match = (expected_s is None) or (got_severity == expected_s)

    return {
        "id": test_case["id"],
        "scenario": test_case["scenario"],
        "expected_verdict": expected_v,
        "expected_severity": expected_s,
        "got_verdict": got_verdict,
        "got_severity": got_severity,
        "verdict_correct": verdict_match,
        "severity_correct": severity_match,
        "pass": verdict_match and severity_match
    }

def print_results(results):
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    verdict_correct = sum(1 for r in results if r["verdict_correct"])

    print("\n" + "═"*65)
    print(f"  EVALUATION RESULTS  —  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("═"*65)
    print(f"{'ID':<10} {'Scenario':<22} {'Exp V':<12} {'Got V':<12} {'Pass'}")
    print("─"*65)
    for r in results:
        icon = "✅" if r["pass"] else ("⚠️ " if r["verdict_correct"] else "❌")
        print(f"{r['id']:<10} {r['scenario']:<22} {r['expected_verdict']:<12} {str(r['got_verdict']):<12} {icon}")

    print("─"*65)
    print(f"\nVerdict accuracy : {verdict_correct}/{total} ({100*verdict_correct//total}%)")
    print(f"Full pass (v+s)  : {passed}/{total} ({100*passed//total}%)")

    # Per-scenario breakdown
    scenarios = {}
    for r in results:
        s = r["scenario"]
        if s not in scenarios:
            scenarios[s] = {"total": 0, "pass": 0}
        scenarios[s]["total"] += 1
        if r["pass"]:
            scenarios[s]["pass"] += 1

    print("\nPer-scenario:")
    for s, v in scenarios.items():
        pct = 100 * v["pass"] // v["total"]
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        print(f"  {s:<22} {bar} {v['pass']}/{v['total']}")

    # Save results
    out_file = f"./eval_results/{total}_eval_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n📁 Full results saved to {out_file}")

def main():
    test_cases = load_test_cases()
    print(f"Loaded {len(test_cases)} test cases")
    print(f"Target: {N8N_WEBHOOK_URL or 'MANUAL MODE'}\n")

    results = []
    for i, tc in enumerate(test_cases):
        print(f"[{i+1}/{len(test_cases)}] Running {tc['id']} — {tc['scenario']}...", end=" ", flush=True)
        response = send_to_n8n(tc)
        result = evaluate(tc, response)
        results.append(result)
        icon = "✅" if result["pass"] else "❌"
        print(f"{icon} got={result['got_verdict']}")
        if i < len(test_cases) - 1:
            time.sleep(DELAY_BETWEEN_TESTS)

    print_results(results)

if __name__ == "__main__":
    main()
