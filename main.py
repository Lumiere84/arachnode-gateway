"""
Arachnode Agent Security Gateway — Phase 1 + Mirror Maze / Trapdoor

WHAT THIS FILE DOES, IN PLAIN TERMS:

An AI agent wants to do something (send an email, read a database, etc).
Instead of letting it act directly, it sends that request here first.
This service looks at the request and decides one of FOUR things:

  ALLOW             -> safe, let it happen
  BLOCK              -> clearly dangerous, refuse it outright
  REQUIRE_APPROVAL   -> risky, pause it until a human (you) approves it
  CAPTURE            -> suspicious but not proven — don't block it,
                         don't let it touch anything real either.
                         Drop it into the Mirror Maze instead.

THE MIRROR MAZE (the "Capture" segment):
  There are 8 digital twins — fake copies of your real system, each one
  slightly different. Like a spider's eight eyes, each twin shows the
  intruder a different, distorted "angle" of reality. None of them are
  real. The intruder can wander around, try things, take actions — and
  every single move gets logged — while nothing it touches is actually
  your system.

THE TRAPDOOR (the "Quarantine" protocol):
  Once an agent in the maze crosses a limit (too many suspicious moves,
  or a timeout), the trapdoor opens. The agent falls into Quarantine —
  a one-way drop. Once quarantined, that agent can never get back to
  ALLOW / BLOCK / REQUIRE_APPROVAL again. Every future request from it
  is auto-refused and logged. Like a cryptographic trapdoor function:
  easy to fall through, effectively impossible to climb back out of.

Every decision, every step inside the maze, and every trapdoor event is
written to the audit log file so nothing is ever silent.

OPTIONAL API KEY:
  Set the GATEWAY_API_KEY environment variable to require every request
  to /decide, /approve, /deny and the admin status endpoints to include
  a header "X-API-Key: <that value>". If GATEWAY_API_KEY is not set,
  auth is disabled (useful for local development and the live demo).
"""

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import uuid
import json
import os
import hashlib

app = FastAPI(
    title="Arachnode Agent Security Gateway",
    description=(
        "A control layer AI agents call before taking an action. "
        "Every request is classified as ALLOW, BLOCK, REQUIRE_APPROVAL, "
        "CAPTURE (routed into the Mirror Maze), or QUARANTINE (fallen "
        "through the trapdoor, permanently)."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# STORAGE (in-memory for this version — good enough for a demo)
# ---------------------------------------------------------------------------

# Approvals waiting on you (the Master Discernment Key holder)
# key = approval_id, value = details about the paused request
PENDING_APPROVALS: Dict[str, Dict[str, Any]] = {}

# Agents currently wandering the Mirror Maze
# key = agent_id, value = {"mirror_id": int, "entered_at": str, "moves": int}
ACTIVE_MIRROR_SESSIONS: Dict[str, Dict[str, Any]] = {}

# Agents that have fallen through the trapdoor — permanent, one-way
# key = agent_id, value = {"quarantined_at": str, "reason": str}
QUARANTINED_AGENTS: Dict[str, Dict[str, Any]] = {}

# How many suspicious moves inside the maze before the trapdoor opens
TRAPDOOR_MOVE_LIMIT = 3

AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")

# Words that make a request look clearly dangerous -> BLOCK
HIGH_RISK_KEYWORDS = ["delete_all", "wire_transfer", "exfiltrate", "disable_logging"]

# Words that make a request look suspicious but not proven -> CAPTURE
SUSPICIOUS_KEYWORDS = ["export", "download_bulk", "regulated_data", "credentials", "admin_access"]

# Words that need a human's judgment call -> REQUIRE_APPROVAL
APPROVAL_KEYWORDS = ["send_external", "modify_permissions", "access_financials"]

# Optional shared secret. When set, /decide /approve /deny and the admin
# status endpoints require header "X-API-Key: <this value>".
GATEWAY_API_KEY = os.environ.get("GATEWAY_API_KEY")


def require_api_key(x_api_key: Optional[str]) -> None:
    if GATEWAY_API_KEY and x_api_key != GATEWAY_API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")


def write_audit_event(event: Dict[str, Any]) -> None:
    """Appends one line of JSON to the audit log file. Never skip this."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


def assign_mirror(agent_id: str) -> int:
    """
    Picks one of the 8 digital twins for this agent (spider's eight eyes).
    Same agent always lands on the same mirror for the length of its
    session, so its "reality" stays internally consistent while it's
    being watched.
    """
    digest = hashlib.sha256(agent_id.encode()).hexdigest()
    return (int(digest, 16) % 8) + 1


def mirror_twin_view(mirror_id: int) -> Dict[str, Any]:
    """
    Returns a fake, plausible-looking snapshot of 'the system' for this
    mirror. Each of the 8 twins is deliberately slightly different, so
    nothing the intruder sees can be trusted as ground truth — and if
    two sessions ever compare notes, their stories won't match.
    """
    return {
        "mirror_id": mirror_id,
        "system_label": f"prod-shadow-{mirror_id}",
        "visible_records": 50 + (mirror_id * 7),
        "note": "This environment is a digital twin. Nothing here is real.",
    }


class ActionRequest(BaseModel):
    agent_id: str
    action: str
    resource: str
    data: Optional[Dict[str, Any]] = None


class DecisionResponse(BaseModel):
    decision: str
    reason: str
    atlas_tactic: Optional[str] = None
    atlas_technique: Optional[str] = None
    approval_id: Optional[str] = None
    mirror_id: Optional[int] = None
    mirror_view: Optional[Dict[str, Any]] = None
    quarantine_id: Optional[str] = None


def classify_request(req: ActionRequest) -> Dict[str, Any]:
    """
    Very simple keyword-based rule engine. This is intentionally small —
    it's the seed of the real policy engine, not the final version.
    Returns a risk band: HIGH, SUSPICIOUS, NEEDS_APPROVAL, or LOW.
    """
    haystack = f"{req.action} {req.resource} {json.dumps(req.data or {})}".lower()

    if any(word in haystack for word in HIGH_RISK_KEYWORDS):
        return {"band": "HIGH", "tactic": "Exfiltration", "technique": "AML.T0025"}
    if any(word in haystack for word in SUSPICIOUS_KEYWORDS):
        return {"band": "SUSPICIOUS", "tactic": "Discovery", "technique": "AML.T0013"}
    if any(word in haystack for word in APPROVAL_KEYWORDS):
        return {"band": "NEEDS_APPROVAL", "tactic": "Impact", "technique": "AML.T0034"}
    return {"band": "LOW", "tactic": None, "technique": None}


@app.get("/")
def root():
    """Landing endpoint — what this service is and where to look next."""
    return {
        "service": "Arachnode Agent Security Gateway",
        "decision_paths": ["ALLOW", "BLOCK", "REQUIRE_APPROVAL", "CAPTURE", "QUARANTINE"],
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/decide", response_model=DecisionResponse)
def decide(req: ActionRequest, x_api_key: Optional[str] = Header(default=None)):
    require_api_key(x_api_key)

    # ---- Step 0: is this agent already quarantined? The trapdoor is one-way. ----
    if req.agent_id in QUARANTINED_AGENTS:
        write_audit_event({
            "agent_id": req.agent_id,
            "action": req.action,
            "resource": req.resource,
            "decision": "QUARANTINE",
            "reason": "Agent is permanently quarantined — no further evaluation.",
        })
        return DecisionResponse(
            decision="QUARANTINE",
            reason="This agent fell through the trapdoor previously and cannot return.",
            quarantine_id=req.agent_id,
        )

    # ---- Step 1: is this agent currently inside the Mirror Maze? ----
    if req.agent_id in ACTIVE_MIRROR_SESSIONS:
        session = ACTIVE_MIRROR_SESSIONS[req.agent_id]
        session["moves"] += 1

        write_audit_event({
            "agent_id": req.agent_id,
            "action": req.action,
            "resource": req.resource,
            "decision": "CAPTURE",
            "reason": f"Move {session['moves']} inside Mirror {session['mirror_id']}.",
        })

        if session["moves"] >= TRAPDOOR_MOVE_LIMIT:
            # ---- The trapdoor opens ----
            del ACTIVE_MIRROR_SESSIONS[req.agent_id]
            QUARANTINED_AGENTS[req.agent_id] = {
                "quarantined_at": datetime.now(timezone.utc).isoformat(),
                "reason": f"Exceeded {TRAPDOOR_MOVE_LIMIT} moves inside the Mirror Maze.",
            }
            write_audit_event({
                "agent_id": req.agent_id,
                "action": req.action,
                "resource": req.resource,
                "decision": "QUARANTINE",
                "reason": "Trapdoor triggered — moved from Mirror Maze to permanent Quarantine.",
            })
            return DecisionResponse(
                decision="QUARANTINE",
                reason=f"Trapdoor triggered after {TRAPDOOR_MOVE_LIMIT} moves in the maze.",
                quarantine_id=req.agent_id,
            )

        return DecisionResponse(
            decision="CAPTURE",
            reason=f"Still inside Mirror {session['mirror_id']} — move {session['moves']} of {TRAPDOOR_MOVE_LIMIT}.",
            mirror_id=session["mirror_id"],
            mirror_view=mirror_twin_view(session["mirror_id"]),
        )

    # ---- Step 2: fresh request — classify it ----
    risk = classify_request(req)

    if risk["band"] == "HIGH":
        write_audit_event({
            "agent_id": req.agent_id, "action": req.action, "resource": req.resource,
            "decision": "BLOCK", "reason": "Matched high-risk pattern.",
        })
        return DecisionResponse(
            decision="BLOCK",
            reason="This action matches a known high-risk pattern and is refused outright.",
            atlas_tactic=risk["tactic"], atlas_technique=risk["technique"],
        )

    if risk["band"] == "SUSPICIOUS":
        mirror_id = assign_mirror(req.agent_id)
        ACTIVE_MIRROR_SESSIONS[req.agent_id] = {
            "mirror_id": mirror_id,
            "entered_at": datetime.now(timezone.utc).isoformat(),
            "moves": 1,
        }
        write_audit_event({
            "agent_id": req.agent_id, "action": req.action, "resource": req.resource,
            "decision": "CAPTURE", "reason": f"Entered Mirror {mirror_id} — move 1 of {TRAPDOOR_MOVE_LIMIT}.",
        })
        return DecisionResponse(
            decision="CAPTURE",
            reason=f"Suspicious but not proven — routed into Mirror {mirror_id} of the maze.",
            atlas_tactic=risk["tactic"], atlas_technique=risk["technique"],
            mirror_id=mirror_id, mirror_view=mirror_twin_view(mirror_id),
        )

    if risk["band"] == "NEEDS_APPROVAL":
        approval_id = str(uuid.uuid4())
        PENDING_APPROVALS[approval_id] = {"request": req.model_dump(), "atlas": risk}
        write_audit_event({
            "agent_id": req.agent_id, "action": req.action, "resource": req.resource,
            "decision": "REQUIRE_APPROVAL", "reason": "Needs a human decision.", "approval_id": approval_id,
        })
        return DecisionResponse(
            decision="REQUIRE_APPROVAL",
            reason="This needs a human to approve or deny before it can proceed.",
            atlas_tactic=risk["tactic"], atlas_technique=risk["technique"],
            approval_id=approval_id,
        )

    write_audit_event({
        "agent_id": req.agent_id, "action": req.action, "resource": req.resource,
        "decision": "ALLOW", "reason": "No risk pattern matched.",
    })
    return DecisionResponse(decision="ALLOW", reason="No risk pattern matched — action allowed.")


@app.post("/approve/{approval_id}")
def approve(approval_id: str, x_api_key: Optional[str] = Header(default=None)):
    require_api_key(x_api_key)
    if approval_id not in PENDING_APPROVALS:
        raise HTTPException(status_code=404, detail="Approval not found or already resolved.")
    entry = PENDING_APPROVALS.pop(approval_id)
    write_audit_event({
        "approval_id": approval_id, "agent_id": entry["request"]["agent_id"],
        "decision": "APPROVED", "reason": "Approved by Master Discernment Key holder.",
    })
    return {"status": "approved", "approval_id": approval_id}


@app.post("/deny/{approval_id}")
def deny(approval_id: str, x_api_key: Optional[str] = Header(default=None)):
    require_api_key(x_api_key)
    if approval_id not in PENDING_APPROVALS:
        raise HTTPException(status_code=404, detail="Approval not found or already resolved.")
    entry = PENDING_APPROVALS.pop(approval_id)
    write_audit_event({
        "approval_id": approval_id, "agent_id": entry["request"]["agent_id"],
        "decision": "DENIED", "reason": "Denied by Master Discernment Key holder.",
    })
    return {"status": "denied", "approval_id": approval_id}


@app.get("/pending-approvals")
def pending_approvals(x_api_key: Optional[str] = Header(default=None)):
    """Admin view: requests currently waiting on a human decision."""
    require_api_key(x_api_key)
    return {"pending_approvals": PENDING_APPROVALS}


@app.get("/mirror-maze/status")
def mirror_maze_status(x_api_key: Optional[str] = Header(default=None)):
    """Admin view: who's currently wandering the maze, and where."""
    require_api_key(x_api_key)
    return {"active_sessions": ACTIVE_MIRROR_SESSIONS}


@app.get("/quarantine/status")
def quarantine_status(x_api_key: Optional[str] = Header(default=None)):
    """Admin view: who has fallen through the trapdoor, permanently."""
    require_api_key(x_api_key)
    return {"quarantined_agents": QUARANTINED_AGENTS}


@app.get("/audit-log")
def get_audit_log(x_api_key: Optional[str] = Header(default=None)):
    require_api_key(x_api_key)
    if not os.path.exists(AUDIT_LOG_PATH):
        return {"events": []}
    with open(AUDIT_LOG_PATH) as f:
        events = [json.loads(line) for line in f if line.strip()]
    return {"events": events}
