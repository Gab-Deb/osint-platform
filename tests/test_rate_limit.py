import main
from fastapi.testclient import TestClient


def test_rate_limit_blocks_after_threshold():
    main._rate_buckets.clear()
    old_limit = main.RATE_LIMIT
    main.RATE_LIMIT = 3
    try:
        client = TestClient(main.app)
        for _ in range(3):
            r = client.get("/api/config")
            assert r.status_code == 200
        r = client.get("/api/config")
        assert r.status_code == 429
    finally:
        main.RATE_LIMIT = old_limit
        main._rate_buckets.clear()


def test_rate_limit_does_not_apply_to_static_files():
    main._rate_buckets.clear()
    old_limit = main.RATE_LIMIT
    main.RATE_LIMIT = 2
    try:
        client = TestClient(main.app)
        for _ in range(5):
            r = client.get("/")
            assert r.status_code == 200
    finally:
        main.RATE_LIMIT = old_limit
        main._rate_buckets.clear()
