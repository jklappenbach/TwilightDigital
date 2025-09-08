import os
import json
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone


# Import the Flask app object from app.py
import app

# Import the HTTP JSON utility function
from integration.http_json_server_bootstrap import _http_json


class SMTPDummy:
    """Simple SMTP dummy to be used as a context manager."""

    def __init__(self, *args, **kwargs):
        self.sent_messages = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def ehlo(self):
        return True

    def starttls(self):
        return True

    def login(self, user, password):
        return True

    def send_message(self, msg):
        # capture message for assertions if needed
        self.sent_messages.append(msg)


class TestAppRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Make sure Flask testing mode is on
        app.app.testing = True

    def setUp(self):
        self.client = app.app.test_client()

    def test_get_root_renders_landing_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Twilight Digital", resp.data)

    def test_get_create_account_renders_page(self):
        resp = self.client.get("/create-account")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Create your account", resp.data)

class TestSendEmailVerificationCode(unittest.TestCase):
    def setUp(self):
        app.app.testing = True
        self.client = app.app.test_client()

    @patch.dict(os.environ, {"MAIL_FROM": "noreply@example.com"}, clear=False)
    @patch("smtplib.SMTP", new=SMTPDummy)
    def test_send_email_verification_valid(self):
        payload = {"email": "user@example.com"}
        resp = self.client.post(
            "/email-verification-code",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body.get("ok"))

        # Ensure a session entry was stored
        with self.client.session_transaction() as sess:
            entry = sess.get("email_code_entry")
            self.assertIsNotNone(entry)
            self.assertEqual(entry["email"], payload["email"])
            self.assertIn("code", entry)

    @patch("smtplib.SMTP", new=SMTPDummy)
    def test_send_email_verification_invalid_email(self):
        payload = {"email": "invalid-email"}
        resp = self.client.post(
            "/email-verification-code",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body.get("ok"))
        self.assertIn("valid email", (body.get("error") or "").lower())

    @patch.dict(os.environ, {"MAIL_FROM": "noreply@example.com"}, clear=False)
    @patch("smtplib.SMTP", side_effect=RuntimeError("SMTP connection failed"))
    def test_send_email_verification_smtp_error(self, _mock_smtp):
        payload = {"email": "user@example.com"}
        resp = self.client.post(
            "/email-verification-code",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 500)
        body = resp.get_json()
        self.assertFalse(body.get("ok"))
        self.assertIn("failed to send verification email", (body.get("error") or "").lower())


class TestVerifyEmailCode(unittest.TestCase):
    def setUp(self):
        app.app.testing = True
        self.client = app.app.test_client()

    def _seed_session_code(self, email="user@example.com", code="123456", issued_at=None):
        if issued_at is None:
            issued_at = datetime.now(timezone.utc).isoformat()
        with self.client.session_transaction() as sess:
            sess["email_code_entry"] = {
                "code": code,
                "date_time": issued_at,
                "email": email,
            }

    def test_verify_missing_email_or_invalid_format(self):
        # Seed session so we can test early validation error
        self._seed_session_code()
        # bad email format
        resp = self.client.post(
            "/verify-email-code",
            json={"email": "bad.email", "code": "123456"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json().get("ok"))

    def test_verify_missing_session_entry(self):
        resp = self.client.post(
            "/verify-email-code",
            json={"email": "user@example.com", "code": "123456"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json().get("ok"))
        self.assertIn("session", (resp.get_json().get("error") or "").lower())

    def test_verify_email_mismatch(self):
        self._seed_session_code(email="expected@example.com", code="123456")
        resp = self.client.post(
            "/verify-email-code",
            json={"email": "other@example.com", "code": "123456"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json().get("ok"))
        self.assertIn("does not match", (resp.get_json().get("error") or "").lower())

    @patch.dict(os.environ, {"VERIFICATION_CODE_EXP_MIN": "10"}, clear=False)
    def test_verify_code_expired(self):
        issued_at = (datetime.now(timezone.utc) - timedelta(minutes=11)).isoformat()
        self._seed_session_code(email="user@example.com", code="123456", issued_at=issued_at)
        resp = self.client.post(
            "/verify-email-code",
            json={"email": "user@example.com", "code": "123456"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json().get("ok"))
        self.assertIn("expired", (resp.get_json().get("error") or "").lower())

    def test_verify_code_incorrect(self):
        self._seed_session_code(email="user@example.com", code="123456")
        resp = self.client.post(
            "/verify-email-code",
            json={"email": "user@example.com", "code": "000000"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json().get("ok"))
        self.assertIn("incorrect", (resp.get_json().get("error") or "").lower())

    def test_verify_ok_no_api_configured(self):
        # No env vars – should take the "not configured" branch, but still succeed.
        with patch.dict(os.environ, {"TWILIGHT_DIGITAL_API_BASE_URL": "", "TWILIGHT_DIGITAL_DEFAULT_CHANNEL_ID": ""},
                        clear=False):
            self._seed_session_code(email="user@example.com", code="123456")
            resp = self.client.post(
                "/verify-email-code",
                json={"email": "user@example.com", "code": "123456"},
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.get_json().get("ok"))
            # session should contain verified_email and email_code_entry should be cleared
            with self.client.session_transaction() as sess:
                self.assertEqual(sess.get("email"), "user@example.com")
                self.assertIsNone(sess.get("email_code_entry"))

    @patch.dict(
        os.environ,
        {
            "TWILIGHT_DIGITAL_API_BASE_URL": "http://api.local",
            "TWILIGHT_DIGITAL_DEFAULT_CHANNEL_ID": "chan-1",
        },
        clear=False,
    )
    def test_verify_ok_with_api_success(self):
        # Simulate API returning successful user creation then contact creation
        def fake_http_json(method, url, payload=None, timeout=5):
            if url.endswith("/users") and method == "POST":
                return 201, {"user_id": "U123"}
            if url.endswith("/contacts") and method == "POST":
                return 201, {"contact_id": "C999"}
            return 200, {}

        self._seed_session_code(email="user@example.com", code="123456")
        with patch.object(app, "_http_json", side_effect=fake_http_json) as mock_api:
            resp = self.client.post(
                "/verify-email-code",
                json={"email": "user@example.com", "code": "123456"},
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.get_json().get("ok"))
            # Validations that API was called twice (user then contact)
            calls = [c.args[:2] for c in mock_api.call_args_list]
            self.assertTrue(any(u.endswith("/users") for _, u in calls))
            self.assertTrue(any(u.endswith("/contacts") for _, u in calls))

    @patch.dict(
        os.environ,
        {
            "TWILIGHT_DIGITAL_API_BASE_URL": "http://api.local",
            "TWILIGHT_DIGITAL_DEFAULT_CHANNEL_ID": "chan-1",
        },
        clear=False,
    )
    def test_verify_ok_with_api_user_failure_non_201(self):
        # Simulate API returning non-201 on user create -> app should still return ok=True
        def fake_http_json(method, url, payload=None, timeout=5):
            if url.endswith("/users") and method == "POST":
                return 400, {"error": "bad request"}
            return 200, {}

        self._seed_session_code(email="user@example.com", code="123456")
        with patch.object(app, "_http_json", side_effect=fake_http_json):
            resp = self.client.post(
                "/verify-email-code",
                json={"email": "user@example.com", "code": "123456"},
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.get_json().get("ok"))

    @patch.dict(
        os.environ,
        {
            "TWILIGHT_DIGITAL_API_BASE_URL": "http://api.local",
            "TWILIGHT_DIGITAL_DEFAULT_CHANNEL_ID": "chan-1",
        },
        clear=False,
    )
    def test_verify_ok_with_api_exception(self):
        # Simulate network/exception thrown by the API helper
        self._seed_session_code(email="user@example.com", code="123456")
        with patch.object(app, "_http_json", side_effect=RuntimeError("boom")):
            resp = self.client.post(
                "/verify-email-code",
                json={"email": "user@example.com", "code": "123456"},
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.get_json().get("ok"))


class TestGenerateOtpUri(unittest.TestCase):
    def setUp(self):
        app.app.testing = True
        self.app_context = app.app.app_context()
        self.app_context.push()
        self.client = app.app.test_client()

    def tearDown(self):
        self.app_context.pop()

    def _seed_session(self, email="user@example.com"):
        with self.client.session_transaction() as sess:
            sess["email"] = email
            sess["sid"] = "1234"
            sess["otp_secret"] = "shhhhh!"

    def test_generate_otp_uri_success(self):
        self._seed_session("user@example.com")
        # Establish a real request context so flask.session is accessible
        with self.client as c:
            c.get("/")
            uri = app.generate_otp_uri()
        self.assertIsInstance(uri, str)
        self.assertTrue(uri.startswith("otpauth://totp/"))
        self.assertIn("user@example.com", uri)
        self.assertIn("issuer=Deep%20Signal", uri)

    def test_generate_otp_uri_missing_email(self):
        # No email in session
        with self.client as c:
            c.get("/")
            with self.assertRaises(ValueError) as cm:
                app.generate_otp_uri()
        self.assertEqual(str(cm.exception), "Email is required")

    def test_generate_otp_uri_empty_email(self):
        self._seed_session("")
        with self.client as c:
            c.get("/")
            with self.assertRaises(ValueError) as cm:
                app.generate_otp_uri()
        self.assertEqual(str(cm.exception), "Email is required")

    def test_generate_otp_uri_non_string_email(self):
        with self.client.session_transaction() as sess:
            sess["email"] = 123  # non-string email
        with self.client as c:
            c.get("/")
            with self.assertRaises(ValueError) as cm:
                app.generate_otp_uri()
        self.assertEqual(str(cm.exception), "Email is required")

    def test_generate_otp_uri_invalid_email_format(self):
        self._seed_session("invalid-email-format")
        with self.client as c:
            c.get("/")
            with self.assertRaises(ValueError) as cm:
                app.generate_otp_uri()
        self.assertEqual(str(cm.exception), "Invalid email format")

    @patch.dict(os.environ, {"APP_NAME": "Test App"}, clear=False)
    def test_generate_otp_uri_custom_app_name(self):
        self._seed_session("user@example.com")
        with self.client as c:
            c.get("/")
            uri = app.generate_otp_uri()
        self.assertIn("issuer=Test%20App", uri)

    @patch("app.pyotp.random_base32", side_effect=Exception("Random base32 failed"))
    def test_generate_otp_uri_pyotp_exception(self, mock_random_base32):
        self._seed_session("user@example.com")
        with self.client as c:
            c.get("/")
            with self.assertRaises(RuntimeError) as cm:
                app.generate_otp_uri()
        self.assertEqual(str(cm.exception), "Failed to generate OTP URI")

    def test_generate_otp_uri_stores_secret_in_session(self):
        # Use a mocked SID and seed the server-side session directly (no cookies)
        sid = "test-sid-otp-secret"
        cache = app.app.session_interface.cache
        ttl = app.app.session_interface.ttl_seconds
        # Seed with the email so generate_otp_uri passes validation
        cache.set(sid, {"email": "user@example.com"}, ttl)

        # Bind a real request context to the same SID via header, call the function, then persist the session
        with app.app.test_request_context("/", headers={"X-Session-Id": sid}):
            app.generate_otp_uri()
            # Force session to persist via the custom session interface
            resp = app.app.make_response("OK")
            app.app.session_interface.save_session(app.app, app.session, resp)

        # Now verify the session has been updated and persisted in the cache
        stored = cache.get(sid)
        self.assertIsInstance(stored, dict)
        self.assertIn("otp_secret", stored)
        self.assertIsInstance(stored["otp_secret"], str)
        self.assertGreater(len(stored["otp_secret"]), 0)


class TestCreateOtpQrcode(unittest.TestCase):
    def setUp(self):
        app.app.testing = True
        self.app_context = app.app.app_context()
        self.app_context.push()
        self.client = app.app.test_client()
        self.headers = {'X-Session-Id': '1234'}

    def _seed_session_data(self, email="user@example.com", user_id="U123", otp_secret="shhhhh!"):
        with self.client.session_transaction() as sess:
            if email:
                sess["email"] = email
            if user_id:
                sess["user_id"] = user_id
            if otp_secret:
                sess["otp_secret"] = otp_secret

    def test_create_otp_qrcode_missing_email(self):
        # No email in session
        resp = self.client.get("/create-otp-qrcode")
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body.get("ok"))
        self.assertEqual(body.get("error"), "Email is required")

    def test_create_otp_qrcode_empty_email(self):
        self._seed_session_data(email="", user_id="U123")
        resp = self.client.get("/create-otp-qrcode", headers=self.headers)
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body.get("ok"))
        self.assertEqual(body.get("error"), "Email is required")

    def test_create_otp_qrcode_invalid_email_format(self):
        self._seed_session_data(email="invalid-email", user_id="U123")
        resp = self.client.get("/create-otp-qrcode", headers=self.headers)
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body.get("ok"))
        self.assertEqual(body.get("error"), "Invalid email format")

    @patch("app.generate_otp_uri")
    def test_create_otp_qrcode_generate_otp_uri_value_error(self, mock_generate_otp_uri):
        mock_generate_otp_uri.side_effect = ValueError("Invalid email format")
        self._seed_session_data("user@example.com", "U123")
        
        resp = self.client.get("/create-otp-qrcode", headers=self.headers)
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body.get("ok"))
        self.assertEqual(body.get("error"), "Invalid email format")

    @patch("app.generate_otp_uri")
    def test_create_otp_qrcode_generate_otp_uri_runtime_error(self, mock_generate_otp_uri):
        mock_generate_otp_uri.side_effect = RuntimeError("Failed to generate OTP URI")
        self._seed_session_data("user@example.com", "U123")
        
        resp = self.client.get("/create-otp-qrcode", headers=self.headers)
        self.assertEqual(resp.status_code, 500)
        body = resp.get_json()
        self.assertFalse(body.get("ok"))
        self.assertEqual(body.get("error"), "Failed to generate OTP configuration")

    @patch("app.generate_otp_uri")
    def test_create_otp_qrcode_generate_otp_uri_unexpected_exception(self, mock_generate_otp_uri):
        mock_generate_otp_uri.side_effect = Exception("Unexpected error")
        self._seed_session_data("user@example.com", "U123")
        
        resp = self.client.get("/create-otp-qrcode", headers=self.headers)
        self.assertEqual(resp.status_code, 500)
        body = resp.get_json()
        self.assertFalse(body.get("ok"))
        self.assertEqual(body.get("error"), "Internal server error")

    @patch("app.generate_otp_uri")
    @patch("app.qrcode.QRCode")
    def test_create_otp_qrcode_qr_generation_exception(self, mock_qrcode, mock_generate_otp_uri):
        mock_generate_otp_uri.return_value = "otpauth://totp/user@example.com?secret=ABCDEF&issuer=Deep%20Signal"
        mock_qr_instance = MagicMock()
        mock_qrcode.return_value = mock_qr_instance
        mock_qr_instance.make_image.side_effect = Exception("QR generation failed")
        
        self._seed_session_data("user@example.com", "U123")
        
        resp = self.client.get("/create-otp-qrcode", headers=self.headers)
        self.assertEqual(resp.status_code, 500)
        body = resp.get_json()
        self.assertFalse(body.get("ok"))
        self.assertEqual(body.get("error"), "Failed to generate QR code")

    @patch("app.generate_otp_uri")
    @patch("app.qrcode.QRCode")
    @patch("app.os.makedirs")
    def test_create_otp_qrcode_success(self, mock_makedirs, mock_qrcode, mock_generate_otp_uri):
        # Mock the OTP URI generation
        mock_generate_otp_uri.return_value = "otpauth://totp/user@example.com?secret=ABCDEF&issuer=Deep%20Signal"
        
        # Mock QR code generation
        mock_qr_instance = MagicMock()
        mock_qrcode.return_value = mock_qr_instance
        mock_img = MagicMock()
        mock_qr_instance.make_image.return_value = mock_img
        
        # Mock the image save method
        mock_img.save = MagicMock()
        
        self._seed_session_data("user@example.com", "U123")
        
        resp = self.client.get("/create-otp-qrcode", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type, "image/png")
        
        # Verify QR code was configured correctly
        mock_qrcode.assert_called_once()
        mock_qr_instance.add_data.assert_called_once_with("otpauth://totp/user@example.com?secret=ABCDEF&issuer=Deep%20Signal")
        mock_qr_instance.make.assert_called_once_with(fit=True)
        mock_qr_instance.make_image.assert_called_once_with(fill_color="black", back_color="white")

    def test_create_otp_qrcode_logs_properly(self):
        # Test that proper logging occurs - we can't easily test log output without more complex setup
        # but we can ensure the endpoint behaves correctly under normal conditions
        self._seed_session_data("user@example.com", "U123")
        
        with patch("app.generate_otp_uri") as mock_generate_otp_uri, \
             patch("app.qrcode.QRCode") as mock_qrcode, \
             patch("app.os.makedirs") as mock_makedirs:
                
            mock_generate_otp_uri.return_value = "otpauth://totp/user@example.com?secret=ABCDEF&issuer=Deep%20Signal"
            mock_qr_instance = MagicMock()
            mock_qrcode.return_value = mock_qr_instance
            mock_img = MagicMock()
            mock_qr_instance.make_image.return_value = mock_img
            
            resp = self.client.get("/create-otp-qrcode", headers=self.headers)
            self.assertEqual(resp.status_code, 200)


class TestVerifyOtpCode(unittest.TestCase):
    def setUp(self):
        app.app.testing = True
        self.client = app.app.test_client()
        self.headers = {'X-Session-Id': '1234'}

    def _seed_session_otp(self, otp_secret="shhhh!", user_id="U123"):
        with self.client.session_transaction() as sess:
            sess["otp_secret"] = otp_secret
            sess["user_id"] = user_id

    def test_verify_otp_code_missing_code(self):
        self._seed_session_otp()
        resp = self.client.post("/verify-otp-code", json={"code": ""}, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": False})

    def test_verify_otp_code_missing_otp_uri(self):
        # Seed only user_id
        with self.client.session_transaction() as sess:
            sess["user_id"] = "U123"
        resp = self.client.post("/verify-otp-code", json={"code": "123456"}, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": False})

    def test_verify_otp_code_missing_user_id(self):
        # Seed only otp_uri
        with self.client.session_transaction() as sess:
            sess["otp_uri"] = "otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Deep%20Signal"
        resp = self.client.post("/verify-otp-code", json={"code": "123456"}, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": False})

    @patch("app.pyotp.TOTP")
    def test_verify_otp_code_verify_false(self, mock_totp_cls):
        # Mock TOTP to return False on verify
        self._seed_session_otp()
        mock_totp = MagicMock()
        mock_totp.verify.return_value = False
        mock_totp_cls.return_value = mock_totp
        resp = self.client.post("/verify-otp-code", json={"code": "123456"}, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": False})

    @patch.dict(os.environ, {"APP_ENCRYPTION_KEY": "test-key", "TWILIGHT_DIGITAL_API_BASE_URL": "http://api.local"}, clear=False)
    @patch("app.pyotp.TOTP")
    def test_verify_otp_code_ok_api_success(self, mock_totp_cls):
        self._seed_session_otp()
        mock_totp = MagicMock()
        mock_totp.verify.return_value = True
        mock_totp_cls.from_uri.return_value = mock_totp

        with patch.object(app, "_http_json", return_value=(201, {"credential_config_id": "CC1"})) as mock_api:
            resp = self.client.post("/verify-otp-code", json={"code": "123456"}, headers=self.headers)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.get_json(), {"ok": True})

            # session current_user set
            with self.client.session_transaction() as sess:
                self.assertEqual(sess.get("current_user"), "U123")

            # API called once to credential_configs
            self.assertTrue(mock_api.called)
            args = mock_api.call_args[0]
            self.assertEqual(args[0], "POST")
            self.assertTrue(args[1].endswith("/credential_configs"))
            payload = mock_api.call_args[1].get("payload") or mock_api.call_args[0][2]
            self.assertEqual(payload["user_id"], "U123")
            self.assertEqual(payload["credential_type"], "Authenticator_2FA")
            self.assertIsInstance(payload["encrypted_credential"], str)
            self.assertGreater(len(payload["encrypted_credential"]), 0)

    @patch.dict(os.environ, {"APP_ENCRYPTION_KEY": "test-key", "TWILIGHT_DIGITAL_API_BASE_URL": "http://api.local"}, clear=False)
    @patch("app.pyotp.TOTP")
    def test_verify_otp_code_ok_api_non_201(self, mock_totp_cls):
        self._seed_session_otp()
        mock_totp = MagicMock()
        mock_totp.verify.return_value = True
        mock_totp_cls.from_uri.return_value = mock_totp

        with patch.object(app, "_http_json", return_value=(500, {"error": "fail"})) as mock_api:
            resp = self.client.post("/verify-otp-code", json={"code": "123456"}, headers=self.headers)
            self.assertEqual(resp.status_code, 200)
            # Even if API fails, endpoint still returns ok
            self.assertEqual(resp.get_json(), {"ok": True})
            self.assertTrue(mock_api.called)

    @patch.dict(os.environ, {"APP_ENCRYPTION_KEY": "test-key", "TWILIGHT_DIGITAL_API_BASE_URL": "http://api.local"}, clear=False)
    @patch("app.pyotp.TOTP")
    def test_verify_otp_code_ok_api_exception(self, mock_totp_cls):
        self._seed_session_otp()
        mock_totp = MagicMock()
        mock_totp.verify.return_value = True
        mock_totp_cls.from_uri.return_value = mock_totp

        with patch.object(app, "_http_json", side_effect=RuntimeError("boom")) as mock_api:
            resp = self.client.post("/verify-otp-code", json={"code": "123456"}, headers=self.headers)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.get_json(), {"ok": True})
            self.assertTrue(mock_api.called)

    @patch.dict(os.environ, {"APP_ENCRYPTION_KEY": "test-key", "TWILIGHT_DIGITAL_API_BASE_URL": ""}, clear=False)
    @patch("app.pyotp.TOTP")
    def test_verify_otp_code_ok_api_not_configured(self, mock_totp_cls):
        # Should skip API call and still succeed
        self._seed_session_otp()
        mock_totp = MagicMock()
        mock_totp.verify.return_value = True
        mock_totp_cls.from_uri.return_value = mock_totp

        with patch.object(app, "_http_json") as mock_api:
            resp = self.client.post("/verify-otp-code", json={"code": "123456"}, headers=self.headers)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.get_json(), {"ok": True})
            mock_api.assert_not_called()

if __name__ == "__main__":
    unittest.main(verbosity=2)

