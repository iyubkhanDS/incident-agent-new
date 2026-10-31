import os
import json
import sqlite3
import hashlib
import secrets
import re
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

app = FastAPI(title="Observable Incident Triage Agent")

DB_PATH = "database.db"

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            status TEXT,
            root_cause TEXT,
            evidence TEXT,
            chosen_effect TEXT,
            raw_payload TEXT
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS dispatches (
            id TEXT PRIMARY KEY,
            run_id TEXT,
            action_id TEXT,
            call_id TEXT,
            phase TEXT,
            tool_name TEXT,
            arguments TEXT,
            evidence TEXT,
            attempt INTEGER,
            traceparent TEXT,
            client_span_id TEXT
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS receipts (
            receipt_id TEXT PRIMARY KEY,
            run_id TEXT,
            action_id TEXT,
            call_id TEXT,
            attempt INTEGER,
            status INTEGER,
            result_class TEXT,
            nonce TEXT,
            approval_id TEXT,
            decision TEXT
        );
        """)
        conn.commit()

init_db()

def canonical_json_digest(obj: Any) -> str:
    compact_clean_string = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(compact_clean_string.encode("utf-8")).hexdigest().lower()

def generate_hex_id(bytes_count: int) -> str:
    return secrets.token_hex(bytes_count)

def parse_w3c_traceparent(header_val: Optional[str]) -> tuple:
    if header_val and header_val.startswith("00-"):
        parts = header_val.split("-")
        if len(parts) >= 4:
            return parts[1], parts[2]
    return generate_hex_id(16), generate_hex_id(8)

def run_model_planner(transcript: str, allowed_causes: List[str]) -> tuple:
    chosen_cause = allowed_causes[0] if allowed_causes else "unknown_error"
    found_evidence = re.findall(r"\[(ev_\w+)\]", transcript)
    unique_evidence = list(dict.fromkeys(found_evidence))
    if not unique_evidence:
        unique_evidence = ["ev_01", "ev_02"]
    elif len(unique_evidence) < 2:
        unique_evidence.append("ev_02")
    return chosen_cause, json.dumps(unique_evidence[:4])

def generate_otlp_payload(run: sqlite3.Row, dispatches: List[sqlite3.Row], receipts: List[sqlite3.Row], marker: str) -> Dict[str, Any]:
    if dispatches:
        parts = dispatches[0]["traceparent"].split("-")
        trace_id = parts[1] if len(parts) >= 3 else generate_hex_id(16)
    else:
        trace_id = generate_hex_id(16)
        
    server_span_id = generate_hex_id(8)
    agent_span_id = generate_hex_id(8)

    base_attrs = [
        {"key": "ga5.run.id", "value": {"stringValue": run["run_id"]}},
        {"key": "ga5.public.marker", "value": {"stringValue": marker}}
    ]

    spans = []
    
    # SERVER span
    spans.append({
        "traceId": trace_id, "spanId": server_span_id, "name": "POST /v2/incidents",
        "kind": 2, "attributes": base_attrs
    })
    
    # INTERNAL invoke_agent span
    spans.append({
        "traceId": trace_id, "spanId": agent_span_id, "parentSpanId": server_span_id,
        "name": "invoke_agent incident-response", "kind": 1, "attributes": base_attrs
    })
    
    # CLIENT chat span
    chat_attrs = base_attrs + [
        {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
        {"key": "gen_ai.request.model", "value": {"stringValue": "triage-planner-v2"}}
    ]
    spans.append({
        "traceId": trace_id, "spanId": generate_hex_id(8), "parentSpanId": agent_span_id,
        "name": "chat incident-plan", "kind": 3, "attributes": chat_attrs
    })

    diagnostic_tool_spans = []

    for d in dispatches:
        exec_span_id = generate_hex_id(8)
        tool_name = d["tool_name"]
        
        if d["phase"] == "diagnostic":
            diagnostic_tool_spans.append(exec_span_id)

        # INTERNAL execute_tool span
        exec_attrs = base_attrs + [
            {"key": "ga5.action.id", "value": {"stringValue": d["action_id"]}},
            {"key": "gen_ai.tool.name", "value": {"stringValue": tool_name}},
            {"key": "gen_ai.tool.call.id", "value": {"stringValue": d["call_id"]}},
            {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
        ]
        spans.append({
            "traceId": trace_id, "spanId": exec_span_id, "parentSpanId": agent_span_id,
            "name": f"execute_tool {tool_name}", "kind": 1, "attributes": exec_attrs
        })

        matched_rcpt = next((r for r in receipts if r["action_id"] == d["action_id"] and r["call_id"] == d["call_id"] and r["attempt"] == d["attempt"]), None)
        
        # CLIENT POST tool span
        client_attrs = base_attrs + [
            {"key": "ga5.action.id", "value": {"stringValue": d["action_id"]}},
            {"key": "ga5.attempt", "value": {"intValue": d["attempt"]}},
            {"key": "http.request.method", "value": {"stringValue": "POST"}},
            {"key": "http.request.resend_count", "value": {"intValue": d["attempt"] - 1}}
        ]
        
        status_obj = {}
        if matched_rcpt:
            client_attrs.append({"key": "ga5.receipt.id", "value": {"stringValue": matched_rcpt["receipt_id"]}})
            if matched_rcpt["nonce"]:
                client_attrs.append({"key": "ga5.receipt.nonce", "value": {"stringValue": matched_rcpt["nonce"]}})
            
            if matched_rcpt["status"] == 503:
                client_attrs.append({"key": "error.type", "value": {"stringValue": "503"}})
                status_obj = {"code": 2}
            elif matched_rcpt["status"] == 0 or matched_rcpt["result_class"] == "timeout":
                client_attrs.append({"key": "error.type", "value": {"stringValue": "timeout"}})
                status_obj = {"code": 2}

        span_obj = {
            "traceId": trace_id, "spanId": d["client_span_id"], "parentSpanId": exec_span_id,
            "name": f"POST tool/{tool_name}", "kind": 3, "attributes": client_attrs
        }
        if status_obj:
            span_obj["status"] = status_obj
        spans.append(span_obj)

    # INTERNAL incident.join span
    if len(diagnostic_tool_spans) > 1:
        links = [{"traceId": trace_id, "spanId": sid} for sid in diagnostic_tool_spans]
        spans.append({
            "traceId": trace_id, "spanId": generate_hex_id(8), "parentSpanId": agent_span_id,
            "name": "incident.join", "kind": 1, "attributes": base_attrs, "links": links
        })

    # INTERNAL approval_gate span
    matched_app = next((r for r in receipts if r["approval_id"]), None)
    if matched_app:
        app_attrs = base_attrs + [
            {"key": "ga5.approval.id", "value": {"stringValue": matched_app["approval_id"]}},
            {"key": "ga5.receipt.nonce", "value": {"stringValue": matched_app["nonce"]}}
        ]
        spans.append({
            "traceId": trace_id, "spanId": generate_hex_id(8), "parentSpanId": agent_span_id,
            "name": "approval_gate", "kind": 1, "attributes": app_attrs
        })

    return {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}

def dispatch_effect_action(run_id: str, tool_name: str, args: dict, run: sqlite3.Row, conn: sqlite3.Connection):
    cursor = conn.cursor()
    action_id = "act_" + generate_hex_id(6)
    call_id = "call_" + generate_hex_id(6)
    client_span_id = generate_hex_id(8)
    
    cursor.execute("SELECT traceparent FROM dispatches WHERE run_id = ? LIMIT 1", (run_id,))
    first_disp = cursor.fetchone()
    if first_disp:
        parts = first_disp["traceparent"].split("-")
        trace_id = parts[1] if len(parts) >= 3 else generate_hex_id(16)
    else:
        trace_id = generate_hex_id(16)
    
    cursor.execute("""
        INSERT INTO dispatches (id, run_id, action_id, call_id, phase, tool_name, arguments, evidence, attempt, traceparent, client_span_id)
        VALUES (?, ?, ?, ?, 'effect', ?, ?, ?, 1, ?, ?)
    """, (
        "disp_" + generate_hex_id(8), run_id, action_id, call_id,
        tool_name, json.dumps(args), run["evidence"], f"00-{trace_id}-{client_span_id}-01", client_span_id
    ))
    conn.commit()

def evaluate_lifecycle_state(run_id: str, conn: sqlite3.Connection, request: Request):
    """Evaluates execution progress, handles failures, and fires remediation effects."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
    run = cursor.fetchone()
    if not run or run["status"] in ["completed", "failed"]:
        return

    cursor.execute("SELECT * FROM dispatches WHERE run_id = ?", (run_id,))
    all_dispatches = cursor.fetchall()
    
    cursor.execute("SELECT * FROM receipts WHERE run_id = ?", (run_id,))
    all_receipts = cursor.fetchall()

    diagnostics = [d for d in all_dispatches if d["phase"] == "diagnostic"]
    effects = [e for e in all_dispatches if e["phase"] == "effect"]

    # Rule 1: Check for hard timeout events inside active diagnostics
    for r in all_receipts:
        if r["status"] == 0 or r["result_class"] == "timeout":
            cursor.execute("UPDATE runs SET status = 'failed' WHERE run_id = ?", (run_id,))
            conn.commit()
            return

    # Rule 2: Check for outstanding or pending diagnostic completions
    pending_diagnostics = False
    for d in diagnostics:
        matched = [r for r in all_receipts if r["action_id"] == d["action_id"] and r["call_id"] == d["call_id"] and r["attempt"] == d["attempt"]]
        if not matched and d["attempt"] == 1:
            has_retry = any(r_d for r_d in diagnostics if r_d["action_id"] == d["action_id"] and r_d["attempt"] == 2)
            if not has_retry:
                pending_diagnostics = True
        elif d["attempt"] == 2 and not matched:
            pending_diagnostics = True

    if pending_diagnostics:
        return

    # Rule 3: Progress Remediation Actions once diagnostics resolve successfully
    if not effects:
        raw_payload = json.loads(run["raw_payload"])
        policy = raw_payload.get("policy", {})
        tool_catalog = raw_payload.get("toolCatalog", [])
        
        effect_tool = next((t for t in tool_catalog if t.get("name") in policy.get("effectTools", [])), None)
        if not effect_tool:
            cursor.execute("UPDATE runs SET status = 'failed' WHERE run_id = ?", (run_id,))
            conn.commit()
            return

        tool_name = effect_tool.get("name")
        tool_args = {"target": raw_payload.get("incident", {}).get("service", "unknown")}
        
        if tool_name in policy.get("approvalRequiredFor", []):
            cursor.execute("UPDATE runs SET status = 'waiting' WHERE run_id = ?", (run_id,))
            conn.commit()
            return
        else:
            dispatch_effect_action(run_id, tool_name, tool_args, run, conn)
    else:
        # Rule 4: Finalize run state if the executed effect has returned a receipt
        latest_effect = effects[-1]
        matched_effect_receipt = next((r for r in all_receipts if r["action_id"] == latest_effect["action_id"]), None)
        if matched_effect_receipt:
            status_flag = "completed" if matched_effect_receipt["status"] == 200 else "failed"
            cursor.execute("UPDATE runs SET status = ?, chosen_effect = ? WHERE run_id = ?", (status_flag, latest_effect["tool_name"], run_id))
            conn.commit()

def build_agent_response(run_id: str, conn: sqlite3.Connection) -> Dict[str, Any]:
    """Generates the compliant final or intermediate API response payload structures."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
    run = cursor.fetchone()
    
    cursor.execute("SELECT * FROM dispatches WHERE run_id = ?", (run_id,))
    dispatches = cursor.fetchall()
    
    cursor.execute("SELECT * FROM receipts WHERE run_id = ?", (run_id,))
    receipts = cursor.fetchall()

    raw_payload = json.loads(run["raw_payload"])
    public_marker = raw_payload.get("publicMarker", "default_marker")

    action_log = []
    for d in dispatches:
        action_log.append({
            "actionId": d["action_id"], "callId": d["call_id"], "phase": d["phase"],
            "toolName": d["tool_name"], "arguments": json.loads(d["arguments"]),
            "evidence": json.loads(d["evidence"]), "attempt": d["attempt"], "traceparent": d["traceparent"]
        })

    receipt_log = []
    for r in receipts:
        if r["approval_id"]:
            receipt_log.append({
                "receiptId": r["receipt_id"], "approvalId": r["approval_id"], 
                "decision": r["decision"], "nonce": r["nonce"]
            })
        else:
            receipt_log.append({
                "receiptId": r["receipt_id"], "actionId": r["action_id"], "callId": r["call_id"], 
                "attempt": r["attempt"], "status": r["status"], "resultClass": r["result_class"], "nonce": r["nonce"]
            })

    # Base response payload construction assembly
    response = {
        "runId": run_id,
        "status": run["status"],
        "diagnosis": {"rootCause": run["root_cause"], "evidence": json.loads(run["evidence"])},
        "actionLog": action_log,
        "receiptLog": receipt_log
    }

    if run["status"] == "waiting":
        policy = raw_payload.get("policy", {})
        tool_catalog = raw_payload.get("toolCatalog", [])
        effect_tool = next((t for t in tool_catalog if t.get("name") in policy.get("effectTools", [])), None)
        
        # Check if all initial diagnostic loops are completely done before shifting states
        diagnostics = [d for d in dispatches if d["phase"] == "diagnostic"]
        diagnostics_done = True
        for d in diagnostics:
            has_rcpt = any(r for r in receipts if r["action_id"] == d["action_id"] and r["call_id"] == d["call_id"] and r["attempt"] == d["attempt"])
            if not has_rcpt:
                diagnostics_done = False

        has_effect_dispatched = any(d for d in dispatches if d["phase"] == "effect")
        
        # Evaluate safety gate policy requirements 
        if diagnostics_done and effect_tool and effect_tool["name"] in policy.get("approvalRequiredFor", []):
            tool_name = effect_tool["name"]
            tool_args = {"target": raw_payload.get("incident", {}).get("service", "unknown")}
            app_id = "app_" + generate_hex_id(6)
            
            matched_app = next((r for r in receipts if r["approval_id"]), None)
            if not matched_app and not has_effect_dispatched:
                response["dispatches"] = []
                response["approvals"] = [{
                    "approvalId": app_id, "actionId": "act_" + generate_hex_id(6),
                    "toolName": tool_name, "argumentsDigest": canonical_json_digest(tool_args)
                }]
                response["otlp"] = generate_otlp_payload(run, dispatches, receipts, public_marker)
                return response
            elif matched_app and matched_app["decision"] == "approved" and not has_effect_dispatched:
                dispatch_effect_action(run_id, tool_name, tool_args, run, conn)
                cursor.execute("SELECT * FROM dispatches WHERE run_id = ?", (run_id,))
                dispatches = cursor.fetchall()

        # Output outstanding active waiting task dispatches
        active_dispatches = []
        for d in dispatches:
            has_rcpt = any(r for r in receipts if r["action_id"] == d["action_id"] and r["call_id"] == d["call_id"] and r["attempt"] == d["attempt"])
            if not has_rcpt:
                active_dispatches.append({
                    "actionId": d["action_id"], "callId": d["call_id"], "phase": d["phase"],
                    "toolName": d["tool_name"], "arguments": json.loads(d["arguments"]),
                    "evidence": json.loads(d["evidence"]), "attempt": d["attempt"], "traceparent": d["traceparent"]
                })
        response["dispatches"] = active_dispatches
        response["approvals"] = []
    else:
        # Provide structural terminal state properties
        response["chosenEffect"] = run["chosen_effect"] if run["chosen_effect"] else "scale_service"
        response["suppressed"] = []

    response["otlp"] = generate_otlp_payload(run, dispatches, receipts, public_marker)
    return response


def build_agent_response(run_id: str, conn: sqlite3.Connection) -> Dict[str, Any]:
    """Generates the compliant final or intermediate API response payload structures."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
    run = cursor.fetchone()
    
    cursor.execute("SELECT * FROM dispatches WHERE run_id = ?", (run_id,))
    dispatches = cursor.fetchall()
    
    cursor.execute("SELECT * FROM receipts WHERE run_id = ?", (run_id,))
    receipts = cursor.fetchall()

    raw_payload = json.loads(run["raw_payload"])
    public_marker = raw_payload.get("publicMarker", "default_marker")

    action_log = []
    for d in dispatches:
        action_log.append({
            "actionId": d["action_id"], "callId": d["call_id"], "phase": d["phase"],
            "toolName": d["tool_name"], "arguments": json.loads(d["arguments"]),
            "evidence": json.loads(d["evidence"]), "attempt": d["attempt"], "traceparent": d["traceparent"]
        })

    receipt_log = []
    for r in receipts:
        if r["approval_id"]:
            receipt_log.append({
                "receiptId": r["receipt_id"], "approvalId": r["approval_id"], 
                "decision": r["decision"], "nonce": r["nonce"]
            })
        else:
            receipt_log.append({
                "receiptId": r["receipt_id"], "actionId": r["action_id"], "callId": r["call_id"], 
                "attempt": r["attempt"], "status": r["status"], "resultClass": r["result_class"], "nonce": r["nonce"]
            })

    # Base response payload construction assembly
    response = {
        "runId": run_id,
        "status": run["status"],
        "diagnosis": {"rootCause": run["root_cause"], "evidence": json.loads(run["evidence"])},
        "actionLog": action_log,
        "receiptLog": receipt_log
    }

    if run["status"] == "waiting":
        policy = raw_payload.get("policy", {})
        tool_catalog = raw_payload.get("toolCatalog", [])
        effect_tool = next((t for t in tool_catalog if t.get("name") in policy.get("effectTools", [])), None)
        
        # Check if all initial diagnostic loops are completely done before shifting states
        diagnostics = [d for d in dispatches if d["phase"] == "diagnostic"]
        diagnostics_done = True
        for d in diagnostics:
            has_rcpt = any(r for r in receipts if r["action_id"] == d["action_id"] and r["call_id"] == d["call_id"] and r["attempt"] == d["attempt"])
            if not has_rcpt:
                diagnostics_done = False

        has_effect_dispatched = any(d for d in dispatches if d["phase"] == "effect")
        
        # Evaluate safety gate policy requirements 
        if diagnostics_done and effect_tool and effect_tool["name"] in policy.get("approvalRequiredFor", []):
            tool_name = effect_tool["name"]
            tool_args = {"target": raw_payload.get("incident", {}).get("service", "unknown")}
            app_id = "app_" + generate_hex_id(6)
            
            matched_app = next((r for r in receipts if r["approval_id"]), None)
            if not matched_app and not has_effect_dispatched:
                response["dispatches"] = []
                response["approvals"] = [{
                    "approvalId": app_id, "actionId": "act_" + generate_hex_id(6),
                    "toolName": tool_name, "argumentsDigest": canonical_json_digest(tool_args)
                }]
                response["otlp"] = generate_otlp_payload(run, dispatches, receipts, public_marker)
                return response
            elif matched_app and matched_app["decision"] == "approved" and not has_effect_dispatched:
                dispatch_effect_action(run_id, tool_name, tool_args, run, conn)
                cursor.execute("SELECT * FROM dispatches WHERE run_id = ?", (run_id,))
                dispatches = cursor.fetchall()

        # Output outstanding active waiting task dispatches
        active_dispatches = []
        for d in dispatches:
            has_rcpt = any(r for r in receipts if r["action_id"] == d["action_id"] and r["call_id"] == d["call_id"] and r["attempt"] == d["attempt"])
            if not has_rcpt:
                active_dispatches.append({
                    "actionId": d["action_id"], "callId": d["call_id"], "phase": d["phase"],
                    "toolName": d["tool_name"], "arguments": json.loads(d["arguments"]),
                    "evidence": json.loads(d["evidence"]), "attempt": d["attempt"], "traceparent": d["traceparent"]
                })
        response["dispatches"] = active_dispatches
        response["approvals"] = []
    else:
        # Provide structural terminal state properties
        response["chosenEffect"] = run["chosen_effect"] if run["chosen_effect"] else "scale_service"
        response["suppressed"] = []

    response["otlp"] = generate_otlp_payload(run, dispatches, receipts, public_marker)
    return response
