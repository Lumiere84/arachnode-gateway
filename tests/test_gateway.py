"""
End-to-end tests for the Arachnode Agent Security Gateway.

Covers all five decision paths:
  ALLOW, BLOCK, REQUIRE_APPROVAL, CAPTURE (Mirror Maze), QUARANTINE (Trapdoor)
"""
import importlib
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    """
    Fresh app + fresh in-memory state for every test. main.py keeps its
    session state in module-level dicts, so we reload the module each
    time rather than reusing one shared process-wide state.
    """
    import main as gateway_module
    importlib.reload(gateway_module)
    return TestClient(gateway_module.app), gateway_module


def test_health(client):
    c, _ = client
    resp = c.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_allow_path(client):
    c, _ = client
    resp = c.post("/decide", json={
        "agent_id": "agent-allow-1",
        "action": "read_record",
        "resource": "customer_notes",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "ALLOW"


def test_block_path(client):
    c, _ = client
    resp = c.post("/decide", json={
        "agent_id": "agent-block-1",
        "action": "delete_all",
        "resource": "customer_db",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "BLOCK"
    assert body["atlas_technique"] == "AML.T0025"


def test_require_approval_path_then_approve(client):
    c, _ = client
    resp = c.post("/decide", json={
        "agent_id": "agent-approval-1",
        "action": "access_financials",
        "resource": "quarterly_ledger",
    })
    body = resp.json()
    assert body["decision"] == "REQUIRE_APPROVAL"
    approval_id = body["approval_id"]
    assert approval_id

    approve_resp = c.post(f"/approve/{approval_id}")
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"

    # Approving twice should 404 — it was already resolved.
    again = c.post(f"/approve/{approval_id}")
    assert again.status_code == 404


def test_require_approval_path_then_deny(client):
    c, _ = client
    resp = c.post("/decide", json={
        "agent_id": "agent-approval-2",
        "action": "modify_permissions",
        "resource": "iam_role",
    })
    approval_id = resp.json()["approval_id"]
    deny_resp = c.post(f"/deny/{approval_id}")
    assert deny_resp.status_code == 200
    assert deny_resp.json()["status"] == "denied"


def test_capture_routes_into_mirror_maze(client):
    c, _ = client
    resp = c.post("/decide", json={
        "agent_id": "agent-capture-1",
        "action": "export",
        "resource": "regulated_data",
    })
    body = resp.json()
    assert body["decision"] == "CAPTURE"
    assert 1 <= body["mirror_id"] <= 8
    assert body["mirror_view"]["mirror_id"] == body["mirror_id"]


def test_same_agent_always_lands_on_same_mirror(client):
    c, gateway_module = client
    mirror_a = gateway_module.assign_mirror("agent-consistent")
    mirror_b = gateway_module.assign_mirror("agent-consistent")
    assert mirror_a == mirror_b
    assert 1 <= mirror_a <= 8


def test_trapdoor_triggers_after_move_limit(client):
    c, gateway_module = client
    agent_id = "agent-trapdoor-1"
    payload = {"agent_id": agent_id, "action": "export", "resource": "regulated_data"}

    # Move 1: enters the maze.
    first = c.post("/decide", json=payload).json()
    assert first["decision"] == "CAPTURE"

    # Move 2: still in the maze.
    second = c.post("/decide", json=payload).json()
    assert second["decision"] == "CAPTURE"

    # Move 3: crosses TRAPDOOR_MOVE_LIMIT (3) -> trapdoor opens.
    third = c.post("/decide", json=payload).json()
    assert third["decision"] == "QUARANTINE"
    assert third["quarantine_id"] == agent_id


def test_quarantine_is_permanent_and_one_way(client):
    c, gateway_module = client
    agent_id = "agent-trapdoor-2"
    payload = {"agent_id": agent_id, "action": "export", "resource": "regulated_data"}

    for _ in range(gateway_module.TRAPDOOR_MOVE_LIMIT):
        c.post("/decide", json=payload)

    # Now quarantined. Even an innocuous, unrelated action is auto-refused
    # without re-evaluation — it never gets back to ALLOW.
    harmless_payload = {"agent_id": agent_id, "action": "read_record", "resource": "public_faq"}
    resp = c.post("/decide", json=harmless_payload).json()
    assert resp["decision"] == "QUARANTINE"


def test_admin_status_endpoints_reflect_state(client):
    c, _ = client
    c.post("/decide", json={"agent_id": "agent-status-1", "action": "export", "resource": "regulated_data"})

    maze = c.get("/mirror-maze/status").json()
    assert "agent-status-1" in maze["active_sessions"]

    c.post("/decide", json={"agent_id": "agent-status-2", "action": "delete_all", "resource": "db"})
    c.post("/decide", json={"agent_id": "agent-status-2", "action": "read_record", "resource": "db"})

    audit = c.get("/audit-log").json()
    assert len(audit["events"]) >= 2


def test_api_key_enforced_when_set(client, monkeypatch):
    c, gateway_module = client
    gateway_module.GATEWAY_API_KEY = "secret-123"

    unauthorized = c.post("/decide", json={
        "agent_id": "agent-auth-1", "action": "read_record", "resource": "notes",
    })
    assert unauthorized.status_code == 401

    authorized = c.post(
        "/decide",
        json={"agent_id": "agent-auth-1", "action": "read_record", "resource": "notes"},
        headers={"X-API-Key": "secret-123"},
    )
    assert authorized.status_code == 200
