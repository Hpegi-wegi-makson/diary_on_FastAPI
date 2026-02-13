def test_refresh_flow(client):
    registration = client.post(
        "/registration",
        json={"email": "user@example.com", "password": "password123"}
    )
    assert registration.status_code == 200

    login = client.post(
        "/login",
        json={"email": "user@example.com", "password": "password123"}
    )
    assert login.status_code == 200
    tokens = login.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

    refresh = client.post(
        "/token/refresh",
        json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh.status_code == 200
    refreshed_tokens = refresh.json()
    assert refreshed_tokens["access_token"] != tokens["access_token"]

    logout = client.post(
        "/logout",
        json={"refresh_token": refreshed_tokens["refresh_token"]}
    )
    assert logout.status_code == 200

    refresh_after_logout = client.post(
        "/token/refresh",
        json={"refresh_token": refreshed_tokens["refresh_token"]}
    )
    assert refresh_after_logout.status_code == 401