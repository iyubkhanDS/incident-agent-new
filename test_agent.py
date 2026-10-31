import json
import urllib.request
import urllib.error
import sys

BASE_URL = "http://127.0.0.1:8000"

def send_post(endpoint, payload_dict):
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=json.dumps(payload_dict).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode("utf-8")), res.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8")), e.code
        except Exception:
            return {"error": e.reason}, e.code

print("=== STEP 1: Starting Python Agent Test Runner ===")
try:
    with open("mock_payload.json", "r") as f:
        payload = json.load(f)
except FileNotFoundError:
    print("Error: Ensure mock_payload.json is created in the working directory.")
    sys.exit(1)

run_id = payload["runId"]

print(f"\n---> Triggering first-seen incident request for runId: {run_id}")
res, code = send_post("/v2/incidents", payload)
print(f"Response Code: {code}")
print(f"Status: {res.get('status')}")
print(f"Diagnosis Result: {res.get('diagnosis')}")
print(f"Dispatched Actions Count: {len(res.get('dispatches', []))}")

dispatches = res.get("dispatches", [])
if not dispatches:
    print("CRITICAL EXCEPTION: Agent didn't return initial diagnostic tools!")
    sys.exit(1)

for d in dispatches:
    print(f" - Tool Issued: {d['toolName']} (Action ID: {d['actionId']}, Call ID: {d['callId']})")
    assert len(d.get("evidence", [])) > 0, "Error: Dispatches must cite evidence codes!"

# Save structural identifiers for the diagnostic tool
action_id_diag = dispatches[0]["actionId"]
call_id_diag = dispatches[0]["callId"]

print("\n=== STEP 2: Verifying Changed-Content Conflict Protections ===")
mutated_payload = dict(payload)
mutated_payload["policy"] = dict(payload["policy"])
mutated_payload["policy"]["maximumDiagnostics"] = 99  

print("---> Posting mutated layout payload parameters to identical runId...")
conflict_res, conflict_code = send_post("/v2/incidents", mutated_payload)
print(f"Response Code: {conflict_code} (Expected: 409)")
if conflict_code != 409:
    print("CRITICAL EXCEPTION: Agent permitted duplicate execution context content modifications!")
    sys.exit(1)
print("Success: Changed-content conflict engine intercepted modification attempt.")

print("\n=== STEP 3: Submitting Authoritative Outcome Receipts ===")
receipt_payload = {
    "receiptId": "rcpt_diag_confirm_001",
    "outcomes": [{
        "actionId": action_id_diag,
        "callId": call_id_diag,
        "attempt": 1,
        "status": 200,
        "resultClass": "diagnosis_confirmed",
        "nonce": "uuid-unpredictable-nonce-token-string"
    }],
    "approvals": []
}

print(f"---> Simulating grader test confirmation hook callback...")
rcpt_res, rcpt_code = send_post(f"/v2/incidents/{run_id}/receipts", receipt_payload)
print(f"Response Code: {rcpt_code}")
print(f"State Machine Status: {rcpt_res.get('status')}")
print(f"Active Approval Requests Evaluated: {rcpt_res.get('approvals')}")

approvals = rcpt_res.get("approvals", [])
assert len(approvals) == 1, "Error: Destructive repair tool was not halted by approval constraints!"
approval_id = approvals[0]["approvalId"]
digest_hash = approvals[0]["argumentsDigest"]
print(f" -> Generated Approval Token: {approval_id}")
print(f" -> Key-Sorted Arguments Digest Hash: {digest_hash}")

print("\n=== STEP 4: Injecting Authorization Approval Clearance Signature ===")
approval_clearance_payload = {
    "receiptId": "rcpt_approval_clearance_002",
    "outcomes": [],
    "approvals": [{
        "approvalId": approval_id,
        "decision": "approved",
        "nonce": "approved-nonce-secure-validation-token"
    }]
}

print("---> Releasing approval lock block to execute remedy tool path...")
final_res, final_code = send_post(f"/v2/incidents/{run_id}/receipts", approval_clearance_payload)
print(f"Response Code: {final_code}")
print(f"State Machine Status Post Clearance: {final_res.get('status')}")

dispatches_effect = final_res.get("dispatches", [])
print(f"Dispatched Remedy Tools: {[d['toolName'] for d in dispatches_effect]}")
assert len(dispatches_effect) == 1, "Error: Remedy tool was not successfully dispatched after approval!"

# Save structural identifiers for the dispatched remediation effect tool
action_id_effect = dispatches_effect[0]["actionId"]
call_id_effect = dispatches_effect[0]["callId"]

print("\n=== STEP 5: Submitting Terminal Remediation Receipt ===")
remediation_receipt_payload = {
    "receiptId": "rcpt_remediation_final_003",
    "outcomes": [{
        "actionId": action_id_effect,
        "callId": call_id_effect,
        "attempt": 1,
        "status": 200,
        "resultClass": "remediation_success",
        "nonce": "final-execution-trace-nonce-token"
    }],
    "approvals": []
}

print("---> Simulating final grader response confirming remediation resolution...")
terminal_res, terminal_code = send_post(f"/v2/incidents/{run_id}/receipts", remediation_receipt_payload)
print(f"Response Code: {terminal_code}")
print(f"Terminal State Machine Status: {terminal_res.get('status')}")
print(f"Chosen Remediation Effect Stored: {terminal_res.get('chosenEffect')}")
print(f"Action Log Records Persistent Count: {len(terminal_res.get('actionLog', []))}")
print(f"Receipt Log Records Persistent Count: {len(terminal_res.get('receiptLog', []))}")

assert terminal_res.get("status") == "completed", "Error: State machine failed to reach terminal 'completed' status!"
print("\n=== Local Incident Integration Triage Test Completed Successfully ===")
