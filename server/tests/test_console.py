from app import create_app


def test_console_served_without_credentials_but_not_cached(config):
    client = create_app(config, check_database=False).test_client()
    response = client.get("/console")
    assert response.status_code == 200
    assert response.content_type == "text/html; charset=utf-8"
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert config.ADMIN_TOKEN not in response.text
    assert config.TRANSPORT_KEY_TEXT not in response.text
    assert client.get("/").headers["Location"] == "/console"


def test_console_version_has_three_views_and_production_transport_guidance(config):
    html = create_app(config, check_database=False).test_client().get("/console").text
    for page in ("analytics", "policy", "assets"):
        assert f'data-page="{page}"' in html
    assert 'data-page="analytics" aria-current="page"' in html
    assert "EndpointAIDLP 0.1.22" in html
    assert "AES-GCM" in html
    assert "HTTP 地址需显式允许 HTTP 网关" in html
