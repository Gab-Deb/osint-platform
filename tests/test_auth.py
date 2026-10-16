import base64
import main
from fastapi.testclient import TestClient


def test_no_password_set_allows_access():
    main.APP_PASSWORD = ""
    client = TestClient(main.app)
    r = client.get("/api/config")
    assert r.status_code == 200


def test_password_required_when_set():
    main.APP_PASSWORD = "secret123"
    try:
        client = TestClient(main.app)
        r = client.get("/api/config")
        assert r.status_code == 401

        r = client.get("/api/config", headers={"Authorization": "Basic bm90Ondyb25n"})  # not:wrong
        assert r.status_code == 401

        creds = base64.b64encode(b"user:secret123").decode()
        r = client.get("/api/config", headers={"Authorization": f"Basic {creds}"})
        assert r.status_code == 200
    finally:
        main.APP_PASSWORD = ""
