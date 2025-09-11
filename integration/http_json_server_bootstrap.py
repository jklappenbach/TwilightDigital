#!/usr/bin/env python3
import time
from threading import Thread
from app import _http_json

from twilight_digital_api import create_app

def _wait_for_server(base_url, timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            code, _ = _http_json("GET", f"{base_url}/", None,None, timeout=2)
            if code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def main():
    # Config
    host = "127.0.0.1"
    port = 5055
    base_url = f"http://{host}:{port}"

    # Start server in background thread
    app = create_app()
    t = Thread(target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False))
    t.daemon = True
    t.start()

    # Wait until server is healthy
    if not _wait_for_server(base_url):
        raise SystemExit("Server did not become ready in time")

    # 2) Create a user with the 'Publisher' role and a catchy screen name
    # Note: credential_config_id can be None as per API contract.
    user_payload = {
        "screen_name": "NovaPulse",  # catchy screen name
        "credential_config_id": None,
        "role": "Publisher",
    }
    code, user_resp = _http_json("POST", f"{base_url}/users", "integration_test", user_payload)
    if code != 201:
        raise SystemExit(f"Failed to create user: HTTP {code} {user_resp}")
    print(f"Created user: {user_resp}")

    # Optionally verify with a GET by id
    user_id = user_resp.get("user_id")
    code, fetched = _http_json("GET", f"{base_url}/users/{user_id}")
    if code == 200:
        print(f"Verified user fetch: {fetched}")
    else:
        print(f"Warning: could not verify user fetch, HTTP {code}: {fetched}")

    print("Integration bootstrap complete.")


if __name__ == "__main__":
    main()
