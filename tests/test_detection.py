from php2shell.detection import detect_php, merge_detections


def test_direct_php_header_is_confirmed_and_versioned():
    result = detect_php({"X-Powered-By": "PHP/8.3.36"}, "")
    assert result.confidence == "CONFIRMED"
    assert result.version == "8.3.36"
    assert result.php_detected is True


def test_header_names_are_case_insensitive():
    result = detect_php({"x-powered-by": "PHP/8.2.35"}, "")
    assert result.confidence == "CONFIRMED"
    assert result.version == "8.2.35"


def test_cookie_alone_is_not_confirmation():
    result = detect_php({"Set-Cookie": "PHPSESSID=abc; Path=/; HttpOnly"}, "")
    assert result.confidence == "MEDIUM"
    assert result.php_detected is False


def test_known_application_is_detected_from_public_html():
    result = detect_php({}, '<link href="/wp-content/themes/site/style.css">')
    assert result.application == "WordPress"
    assert result.confidence == "HIGH"


def test_missing_php_path_is_not_evidence():
    result = detect_php({}, "not found", "/index.php", 404)
    assert result.confidence == "UNKNOWN"


def test_merge_keeps_best_evidence_and_version():
    merged = merge_detections(
        [detect_php({}, "", "/index.php"), detect_php({"Server": "PHP/8.4.27"}, "")]
    )
    assert merged.confidence == "CONFIRMED"
    assert merged.version == "8.4.27"
    assert len(merged.evidence) == 2
