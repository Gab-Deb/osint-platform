from main import detect_query_type, clean_json, pdf_safe, summarize_real_data


def test_detect_query_type_ip():
    assert detect_query_type("8.8.8.8") == "ip"


def test_detect_query_type_email():
    assert detect_query_type("test@example.com") == "email"


def test_detect_query_type_siren():
    assert detect_query_type("123456789") == "siren"


def test_detect_query_type_domain():
    assert detect_query_type("example.com") == "domain"


def test_detect_query_type_name_fallback():
    assert detect_query_type("Jean Dupont") == "name"


def test_clean_json_strips_surrounding_text():
    raw = 'Voici le JSON:\n```json\n{"a": 1}\n```\nMerci.'
    assert clean_json(raw) == {"a": 1}


def test_clean_json_plain():
    assert clean_json('{"a": 1, "b": [1,2,3]}') == {"a": 1, "b": [1, 2, 3]}


def test_pdf_safe_replaces_unicode_punctuation():
    out = pdf_safe("a — b … c")
    assert "—" not in out and "…" not in out


def test_pdf_safe_replaces_emoji_markers():
    assert pdf_safe("🚩 attention") == "[!] attention"


def test_pdf_safe_handles_empty():
    assert pdf_safe("") == ""
    assert pdf_safe(None) is None


def test_pdf_safe_never_raises_on_arbitrary_unicode():
    # Ne doit jamais lever, même avec des caractères totalement hors latin-1.
    pdf_safe("日本語 emoji 🎉 math ∑∞")


def test_summarize_real_data_no_results():
    s = summarize_real_data("domain", {})
    assert "Aucune donnée" in s


def test_summarize_real_data_annuaire():
    results = {"annuaire": {"results": [{"nom_complet": "ACME SAS", "siren": "123456789"}]}}
    s = summarize_real_data("name", results)
    assert "ACME SAS" in s and "123456789" in s


def test_summarize_real_data_skips_error_sources():
    results = {"opensanctions": {"error": "401 Unauthorized"}}
    s = summarize_real_data("name", results)
    assert "401" not in s


def test_summarize_real_data_crtsh_list_value_not_skipped():
    # Régression : crt.sh/wayback renvoient une LISTE, pas un dict — un filtre
    # `isinstance(v, dict)` mal placé les excluait silencieusement de la boucle.
    results = {"crtsh": [{"name_value": "www.example.com\nexample.com"}]}
    s = summarize_real_data("domain", results)
    assert "sous-domaine" in s


def test_summarize_real_data_wayback():
    header = ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"]
    results = {"wayback": [header, ["x"] * 7, ["y"] * 7]}
    s = summarize_real_data("domain", results)
    assert "2 capture" in s


def test_summarize_real_data_greynoise_noise():
    results = {"greynoise": {"ip": "1.2.3.4", "noise": True, "classification": "malicious"}}
    s = summarize_real_data("ip", results)
    assert "scan internet" in s and "malicious" in s


def test_summarize_real_data_greynoise_clean_is_omitted():
    results = {"greynoise": {"ip": "1.2.3.4", "noise": False, "riot": False}}
    s = summarize_real_data("ip", results)
    assert "GreyNoise" not in s


def test_summarize_real_data_opencorporates():
    results = {"opencorporates": {"results": {"companies": [{"company": {"name": "ACME Ltd", "jurisdiction_code": "us_de"}}]}}}
    s = summarize_real_data("name", results)
    assert "ACME Ltd" in s and "us_de" in s
