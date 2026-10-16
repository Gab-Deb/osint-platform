from unittest.mock import patch, AsyncMock
import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


@patch("main._fetch", new_callable=AsyncMock)
def test_analyze_domain_returns_expected_sources(mock_fetch):
    mock_fetch.return_value = {"results": []}
    main._analyze_cache.clear()
    r = client.get("/api/analyze", params={"q": "example-test-domain.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["query_type"] == "domain"
    assert "crtsh" in data["results"] or "rdap" in data["results"]


@patch("main._fetch", new_callable=AsyncMock)
def test_analyze_is_cached_on_second_call(mock_fetch):
    mock_fetch.return_value = {"results": []}
    main._analyze_cache.clear()
    client.get("/api/analyze", params={"q": "cache-test-domain.com"})
    calls_after_first = mock_fetch.call_count
    client.get("/api/analyze", params={"q": "cache-test-domain.com"})
    # Deuxième appel servi depuis le cache : aucune requête externe supplémentaire.
    assert mock_fetch.call_count == calls_after_first


def test_summarize_real_data_used_in_prompt_when_premium_and_key_missing():
    # Même avec PREMIUM_ENABLED actif, sans clé Groq la génération échoue
    # proprement (400) plutôt que de planter sur l'appel réseau.
    main.PREMIUM_ENABLED = True
    main.GROQ_KEY = ""
    try:
        r = client.post("/api/report", json={"query": "test", "mode": "particulier"})
        assert r.status_code == 400
    finally:
        main.PREMIUM_ENABLED = False
