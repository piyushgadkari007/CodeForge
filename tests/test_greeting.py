from PhantomGuard.app import get_time_based_greeting, resolve_attacker_location


def test_greeting_for_morning():
    assert get_time_based_greeting(8) == "Hello"


def test_greeting_for_afternoon():
    assert get_time_based_greeting(14) == "Hello"


def test_greeting_for_evening():
    assert get_time_based_greeting(20) == "Hello"


def test_resolve_attacker_location_returns_coordinates():
    position = resolve_attacker_location(19.0760, 72.8777)
    assert position["lat"] == 19.0760
    assert position["lon"] == 72.8777
    assert "Mumbai" in position["location"] or "India" in position["location"]


def test_secure_cookie_config_is_enabled():
    from PhantomGuard.app import app
    assert app.config.get("SESSION_COOKIE_HTTPONLY") is True
    assert app.config.get("SESSION_COOKIE_SAMESITE") == "Lax"


def test_login_page_includes_csrf_token():
    from PhantomGuard.app import app
    client = app.test_client()
    response = client.get('/login')
    assert response.status_code == 200
    assert b'name="csrf_token"' in response.data


def test_login_throttling_blocks_repeated_failures():
    from PhantomGuard.app import app, reset_login_attempts
    client = app.test_client()
    reset_login_attempts()
    token = 'test-csrf-token'
    with client.session_transaction() as sess:
        sess['csrf_token'] = token
    for _ in range(5):
        response = client.post('/login', data={'email': 'wrong@example.com', 'password': 'badpass', 'csrf_token': token}, follow_redirects=True)
        assert response.status_code == 200
    response = client.post('/login', data={'email': 'wrong@example.com', 'password': 'badpass', 'csrf_token': token}, follow_redirects=True)
    assert b'Too many failed login attempts' in response.data


def test_vercel_environment_uses_temp_db_and_secure_cookies(monkeypatch):
    import importlib
    import PhantomGuard.app as app_module

    monkeypatch.setenv('VERCEL', '1')
    monkeypatch.setenv('FLASK_ENV', 'production')
    reloaded = importlib.reload(app_module)

    assert reloaded.app.config.get('SESSION_COOKIE_SECURE') is True
    assert '/tmp/' in reloaded.app.config.get('SQLALCHEMY_DATABASE_URI', '')
