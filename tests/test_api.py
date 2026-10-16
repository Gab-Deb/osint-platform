from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_config_shape():
    r = client.get("/api/config")
    assert r.status_code == 200
    data = r.json()
    for key in ("premium", "groq", "pappers", "hibp"):
        assert key in data


def test_report_requires_premium():
    r = client.post("/api/report", json={"query": "test", "mode": "particulier"})
    assert r.status_code == 402


def test_batch_reports_premium_error_per_target_without_crashing():
    r = client.post("/api/batch", json={"targets": ["test"], "mode": "particulier"})
    assert r.status_code == 200
    result = r.json()["results"][0]
    assert result["status"] == "error"


def test_export_pdf_requires_premium():
    r = client.post("/api/export/pdf", json={"report": {"target": "x"}})
    assert r.status_code == 402


def test_cases_crud():
    r = client.post("/api/cases", json={"name": "Dossier Test"})
    assert r.status_code == 200
    case_id = r.json()["id"]

    r = client.get("/api/cases")
    assert any(c["id"] == case_id for c in r.json())

    r = client.put(f"/api/cases/{case_id}", json={"status": "Clôturé", "risk": 42})
    assert r.status_code == 200
    assert r.json()["status"] == "Clôturé"
    assert r.json()["risk"] == 42

    r = client.delete(f"/api/cases/{case_id}")
    assert r.json()["ok"] is True

    r = client.get("/api/cases")
    assert not any(c["id"] == case_id for c in r.json())


def test_update_unknown_case_404():
    r = client.put("/api/cases/999999", json={"status": "x"})
    assert r.status_code == 404


def test_history_list_and_clear():
    r = client.get("/api/history")
    assert r.status_code == 200
    assert isinstance(r.json(), list)

    r = client.delete("/api/history")
    assert r.json()["ok"] is True


def test_waitlist_valid_email():
    r = client.post("/api/waitlist", json={"email": "nouveau@example.com"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_waitlist_invalid_email_rejected():
    r = client.post("/api/waitlist", json={"email": "pas-un-email"})
    assert r.status_code == 400


def test_waitlist_duplicate_does_not_error():
    client.post("/api/waitlist", json={"email": "doublon@example.com"})
    r = client.post("/api/waitlist", json={"email": "doublon@example.com"})
    assert r.status_code == 200


def test_username_checker_returns_all_links():
    r = client.post("/api/username", json={"username": "octocat"})
    assert r.status_code == 200
    data = r.json()
    assert data["total"] > 40
    assert "api_results" in data and "links" in data
