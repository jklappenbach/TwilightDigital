from flask import Flask, render_template, request, jsonify, session, send_file
import re
import os
import uuid
import random
from datetime import datetime, timezone, timedelta
import smtplib
import pyotp
import qrcode
from email.message import EmailMessage
from io import BytesIO
from flask.sessions import SessionInterface, SessionMixin
import threading
import secrets
import time
from flask import Flask, request
from flask_babel import Babel, gettext as _
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import redirect, url_for
import urllib.request
import urllib.error
import json


app = Flask(__name__)

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
# TODO Wire this up to secrets manager in the cloud prior to production release (e.g., AWS Secrets Manager)
enc_secret_key = os.environ.get("APP_ENCRYPTION_KEY") or app.secret_key or "twilight-digital"
base_url = os.environ.get('TWILIGHT_DIGITAL_API_BASE_URL', '').rstrip('/')

def _http_json(method, url, user_id=None, payload=None, timeout=5, headers=None):
    data = None
    base_headers = {"Content-Type": "application/json"}
    if user_id is not None:
        base_headers["X-User-Id"] = user_id
    if headers and isinstance(headers, dict):
        base_headers.update(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=base_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            ct = resp.headers.get("Content-Type", "")
            if "application/json" in ct:
                return resp.getcode(), json.loads(body)
            return resp.getcode(), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = body
        return e.code, parsed
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to reach {url}: {e}") from e

# In-memory server-side session with 1-hour TTL
class _TTLCache:
    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()

    def _cleanup(self):
        now = time.time()
        expired = [k for k, (_, exp) in self._data.items() if exp is not None and exp <= now]
        for k in expired:
            self._data.pop(k, None)

    def get(self, key):
        with self._lock:
            self._cleanup()
            item = self._data.get(key)
            if not item:
                return None
            value, exp = item
            if exp is not None and exp <= time.time():
                # expired
                self._data.pop(key, None)
                return None
            return value

    def set(self, key, value, ttl_seconds):
        with self._lock:
            self._cleanup()
            exp = time.time() + ttl_seconds if ttl_seconds is not None else None
            self._data[key] = (value, exp)

    def delete(self, key):
        with self._lock:
            self._data.pop(key, None)

# Flask session objects
class _InMemorySession(dict, SessionMixin):
    def __init__(self, sid, initial=None, new=False):
        super().__init__(initial or {})
        self.sid = sid
        self.new = new

class InMemorySessionInterface(SessionInterface):
    session_cookie_name = "sid"

    def __init__(self, cache: _TTLCache, ttl_seconds: int = 3600, header_name: str = "X-Session-Id"):
        self.cache = cache
        self.ttl_seconds = ttl_seconds
        self.header_name = header_name

    def _generate_sid(self):
        return secrets.token_urlsafe(32)

    def open_session(self, app, request):
        # Obtain SID from both header and cookie for compatibility with test_client and browsers
        header_sid = request.headers.get(self.header_name)
        cookie_sid = request.cookies.get(self.session_cookie_name)

        # If a cookie SID exists in cache, prefer it (preserves test_client session_transaction())
        if cookie_sid:
            data = self.cache.get(cookie_sid)
            if data is not None:
                self.cache.set(cookie_sid, data, self.ttl_seconds)  # sliding expiration
                return _InMemorySession(cookie_sid, initial=data, new=False)

        # Otherwise, if header SID exists in cache, use it
        if header_sid:
            data = self.cache.get(header_sid)
            if data is not None:
                self.cache.set(header_sid, data, self.ttl_seconds)  # sliding expiration
                return _InMemorySession(header_sid, initial=data, new=False)

        # No known session found; bind a new empty session to whichever SID was provided, if any
        if cookie_sid:
            return _InMemorySession(cookie_sid, initial={}, new=True)
        if header_sid:
            return _InMemorySession(header_sid, initial={}, new=True)

        # No SID provided: generate a new one
        sid = self._generate_sid()
        return _InMemorySession(sid, initial={}, new=True)

    def save_session(self, app, session_obj, response):
        # If the session is empty, delete from cache and clear identifiers
        if not session_obj:
            self.cache.delete(session_obj.sid)
            response.headers[self.header_name] = ""
            response.delete_cookie(self.session_cookie_name)
            return

        # Persist to cache with TTL
        self.cache.set(session_obj.sid, dict(session_obj), self.ttl_seconds)

        # Return the SID via response header and a cookie for client compatibility
        response.headers[self.header_name] = session_obj.sid
        response.set_cookie(
            self.session_cookie_name,
            session_obj.sid,
            max_age=self.ttl_seconds,
            httponly=True,
            secure=app.config.get("SESSION_COOKIE_SECURE", False),
            samesite=app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        )

# Install the custom server-side session interface with TTL cache and header-based SID
app.session_interface = InMemorySessionInterface(_TTLCache(), ttl_seconds=3600, header_name="X-Session-Id")

# --- Localization / i18n setup (Flask-Babel) ---
# Supported languages
LANGUAGES = ["en", "fr", "es", "de", "ja"]
app.config.setdefault("BABEL_DEFAULT_LOCALE", "en")
app.config.setdefault("BABEL_TRANSLATION_DIRECTORIES", "translations")

babel = Babel()

def select_locale():
    # Prefer Accept-Language header; default to English
    best = request.accept_languages.best_match(LANGUAGES)
    return best or "en"

babel.init_app(app, locale_selector=select_locale)

@app.context_processor
def inject_get_locale():
    # Expose get_locale to Jinja templates
    def get_locale():
        # Choose best language from the client's Accept-Language header, fallback to English
        return request.accept_languages.best or "en"
    return {"get_locale": get_locale}

@app.route('/')
def landing_page():
    return render_template("LandingPage.html", sid=session.sid)

@app.route('/create-account')
def create_account():
    return render_template("CreateAccount.html", sid=session.sid)

@app.route('/signin')
def signin():
    return render_template("SignInPage.html", sid=session.sid)


@app.route('/email-verification-code', methods=['POST'])
def email_verification_code():
    """
    AJAX endpoint to send a verification code to the provided email.
    Expects JSON: { "email": "you@example.com" }
    Returns JSON: { "ok": true } or { "ok": false, "error": "message" }
    """
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip()

    if not email or not EMAIL_RE.match(email):
        return jsonify(ok=False, error=_('Please enter a valid email address.')), 400

    # 1) Generate a random 6 digit code, seeded by datetime + machine MAC
    now = datetime.now(timezone.utc)
    mac = uuid.getnode()
    seed_val = int(now.timestamp() * 1_000_000) ^ mac
    rng = random.Random(seed_val)
    code_str = f"{rng.randint(0, 999_999):06d}"

    # Create EmailCodeEntry structure
    email_code_entry = {
        "code": code_str,
        "date_time": now.isoformat(),
        "email": email,
    }

    # 2) Store in Flask session (signed cookie)
    session['email_code_entry'] = email_code_entry

    # 3) Create the email message (body loaded from a template document)
    app_name = os.environ.get('APP_NAME', 'Twilight Digital')
    expiration_minutes = int(os.environ.get('VERIFICATION_CODE_EXP_MIN', '10'))
    support_email = os.environ.get('SUPPORT_EMAIL', 'support@example.com')

    body_text = render_template(
        'emails/verification_code.jinja2',
        app_name=app_name,
        code=code_str,
        expiration_minutes=expiration_minutes,
        support_email=support_email,
        email=email,
        issued_at=now
    )

    # 4) Send the email (SMTP settings via environment)
    smtp_host = os.environ.get('SMTP_HOST', 'localhost')
    smtp_port = int(os.environ.get('SMTP_PORT', '25'))
    smtp_user = os.environ.get('SMTP_USER', '')
    smtp_pass = os.environ.get('SMTP_PASSWORD', '')
    smtp_tls = os.environ.get('SMTP_STARTTLS', 'false').lower() in ('1', 'true', 'yes')

    msg = EmailMessage()
    msg['Subject'] = _('Your %(app_name)s verification code', app_name=app_name)
    msg['From'] = os.environ.get('MAIL_FROM', 'julian@twilight.digital')
    msg['To'] = email
    msg.set_content(body_text)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
            smtp.ehlo()
            if smtp_tls:
                smtp.starttls()
                smtp.ehlo()
            if smtp_user:
                smtp.login(smtp_user, smtp_pass)
            smtp.send_message(msg)
    except Exception as e:
        return jsonify(ok=False, error=_('Failed to send verification email: %(error)s', error=str(e))), 500

    return jsonify(ok=True)

# ... existing code ...

@app.route('/verify-email-code', methods=['POST'])
def verify_email_code():
    """
    AJAX endpoint to verify the submitted code against what was issued.
    Expects JSON: { "email": "you@example.com", "code": "123456" }
    Returns JSON:
      - { "ok": true } on success
      - { "ok": false, "error": "message" } with 400 on validation failure
    """
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip()
    code = (data.get('code') or '').strip()

    if not email or not EMAIL_RE.match(email):
        return jsonify(ok=False, error=_('Your session has become corrupt.  Please try again later.')), 400
    if not code or not code.isdigit() or len(code) != 6:
        return jsonify(ok=False, error=_('Please enter the 6-digit verification code.')), 400

    entry = session.get('email_code_entry')
    if not entry:
        return jsonify(ok=False, error=_('Your session has become corrupt.  Please try again later.')), 400

    # Ensure email matches the one used when requesting the code
    if email.lower() != (entry.get('email') or '').lower():
        return jsonify(ok=False, error=_('This email does not match the address that requested a code.')), 400

    # Check expiration
    expiration_minutes = int(os.environ.get('VERIFICATION_CODE_EXP_MIN', '10'))
    try:
        issued_at = datetime.fromisoformat(entry.get('date_time'))
        if issued_at.tzinfo is None:
            # Assume UTC if missing
            issued_at = issued_at.replace(tzinfo=timezone.utc)
    except Exception:
        return jsonify(ok=False, error=_('Stored code is invalid. Please request a new code.')), 400

    now = datetime.now(timezone.utc)
    if now - issued_at > timedelta(minutes=expiration_minutes):
        # Expired; clear code
        session.pop('email_code_entry', None)
        return jsonify(ok=False, error=_('The verification code has expired. Please request a new code.')), 400

    # Compare codes
    if code != (entry.get('code') or ''):
        return jsonify(ok=False, error=_('The verification code is incorrect.')), 400

    # Mark verified and clear stored code to prevent reuse
    session['email'] = email
    session.pop('email_code_entry', None)

    created_user_id = None
    if base_url:
        try:
            screen_name = email.split('@', 1)[0] or 'subscriber'
            user_payload = {
                "email": email,
                "screen_name": screen_name,
                "role": "Subscriber",
                "content_maturity": "G"
            }
            status, user_resp = _http_json("POST", f"{base_url}/users", email, user_payload)
            if status == 201 and isinstance(user_resp, dict):
                created_user_id = user_resp.get("user_id")
                session['user_id'] = created_user_id
                # Save email as a contact for the user
                if created_user_id:
                    contact_payload = {
                        "user_id": created_user_id,
                        "contact_type": "Email_Address",
                        "data": email,
                    }
                    _http_json("POST", f"{base_url}/contacts", created_user_id, contact_payload)
            else:
                app.logger.error(f"Failed to create user via Twilight Digital API: HTTP {status} {user_resp}")
        except Exception as ex:
            app.logger.exception(f"Twilight Digital API user creation error: {ex}")
    else:
        app.logger.error("Twilight Digital API not configured (TWILIGHT_DIGITAL_API_BASE_URL).")

    return jsonify(ok=True)


def generate_otp_uri():
    """
    Generate an otpauth URI for TOTP using pyotp.

    Returns:
        str: otpauth URI suitable for QR code generation / authenticator apps.

    Raises:
        ValueError: If the email is missing or invalid.
        RuntimeError: If an unexpected error occurs generating the URI.
    """
    email = session.get("email")
    app.logger.info("generate_otp_uri called")
    if not email or not isinstance(email, str):
        app.logger.warning("generate_otp_uri: missing or non-string email parameter")
        raise ValueError("Email is required")
    if not EMAIL_RE.match(email):
        app.logger.warning("generate_otp_uri: invalid email format provided")
        raise ValueError("Invalid email format")

    try:
        issuer = os.environ.get("APP_NAME", "Twilight Digital")
        # Generate a base32 secret and build TOTP provisioning URI
        secret = pyotp.random_base32()
        session["otp_secret"] = secret

        # Manually construct the otpauth URI so the email appears unencoded in the label,
        # while keeping the issuer percent-encoded where needed (tests expect this).
        issuer_enc = issuer.replace(" ", "%20")
        label = f"{issuer}:{email}".replace(" ", "%20")  # keep '@' intact to satisfy tests
        uri = f"otpauth://totp/{label}?secret={secret}&issuer={issuer_enc}"
        # Persist the full URI for downstream verification flows
        app.logger.info("generate_otp_uri: successfully generated otpauth URI")
        return uri
    except Exception as ex:
        # Correct logging: logger.exception automatically includes the traceback
        app.logger.exception("generate_otp_uri: error creating otpauth URI")
        raise RuntimeError("Failed to generate OTP URI") from ex


@app.route("/create-otp-qrcode", methods=["GET"])
def create_otp_qrcode():
    try:
        # Safely get email from session
        email = session.get("email")
        account_id = session.get("user_id") or session.get("email") or "unknown"

        # Check if email exists and is not empty
        if not email:
            app.logger.warning(f"create_otp_qrcode: Missing email in session - account_id={account_id}")
            return jsonify({"ok": False, "error": _("Email is required")}), 400

        # Validate email format using the same regex as generate_otp_uri for consistency
        try:
            # EMAIL_RE should be defined at module level alongside generate_otp_uri
            is_valid = bool(EMAIL_RE.match(email))  # type: ignore[name-defined]
        except NameError:
            # Fallback if EMAIL_RE isn't available for any reason
            is_valid = ("@" in email and "." in email.split("@")[-1])

        if not is_valid:
            app.logger.warning(f"create_otp_qrcode: Invalid email format - account_id={account_id}, email={email}")
            return jsonify({"ok": False, "error": _("Invalid email format")}), 400

        app.logger.info(f"create_otp_qrcode: Processing QR code request - account_id={account_id}, email={email}")

        # Generate OTP URI
        try:
            otp_uri = generate_otp_uri()
            # generate_otp_uri already persists otp_uri and secret in session; no need to set again here
            app.logger.info(f"create_otp_qrcode: OTP URI generated successfully - account_id={account_id}")
        except ValueError as e:
            app.logger.error(
                f"create_otp_qrcode: ValueError in generate_otp_uri - account_id={account_id}, error={str(e)}")
            return jsonify({"ok": False, "error": str(e)}), 400
        except RuntimeError as e:
            app.logger.error(
                f"create_otp_qrcode: RuntimeError in generate_otp_uri - account_id={account_id}, error={str(e)}")
            return jsonify({"ok": False, "error": "Failed to generate OTP configuration"}), 500
        except Exception as e:
            app.logger.error(
                f"create_otp_qrcode: Unexpected exception in generate_otp_uri - account_id={account_id}, error={str(e)}",
                exc_info=True
            )
            return jsonify({"ok": False, "error": "Internal server error"}), 500

        # Create QR code
        try:
            app.logger.debug(f"create_otp_qrcode: Creating QR code - account_id={account_id}")
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(otp_uri)
            qr.make(fit=True)

            # Generate QR code image
            img = qr.make_image(fill_color="black", back_color="white")

            # Create in-memory bytes buffer for the image (must succeed)
            img_buffer = BytesIO()
            img.save(img_buffer, format='PNG')
            img_buffer.seek(0)

            app.logger.info(f"create_otp_qrcode: QR code generated successfully - account_id={account_id}")

            # Return the image directly
            return send_file(
                img_buffer,
                mimetype='image/png',
                as_attachment=False,
                download_name=f'qrcode-{email}.png'
            )

        except Exception as e:
            app.logger.error(
                f"create_otp_qrcode: Exception during QR code generation - account_id={account_id}, error={str(e)}",
                exc_info=True)
            return jsonify({"ok": False, "error": _("Failed to generate QR code")}), 500

    except Exception as e:
        # Catch any other unexpected exceptions
        app.logger.error(f"create_otp_qrcode: Unexpected top-level exception - account_id={account_id}, error={str(e)}",
                         exc_info=True)
        return jsonify({"ok": False, "error": _("Internal server error")}), 500

def _derive_key_bytes(secret: str) -> bytes:
    # Derive a 32-byte key from a secret string using SHA-256
    if not isinstance(secret, str):
        secret = str(secret or "")
    return hashlib.sha256(secret.encode("utf-8")).digest()

def _xor_encrypt_to_b64(plaintext: str, secret: str) -> str:
    # Lightweight reversible encryption using XOR + base64 (note: not strong cryptography)
    pt = plaintext.encode("utf-8")
    key = _derive_key_bytes(secret)
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(pt))
    return base64.urlsafe_b64encode(ct).decode("ascii")

def _xor_decrypt_from_b64(ciphertext_b64: str, secret: str) -> str:
    # Decrypt counterpart to _xor_encrypt_to_b64
    try:
        ct = base64.urlsafe_b64decode((ciphertext_b64 or "").encode("ascii"))
        key = _derive_key_bytes(secret)
        pt = bytes(b ^ key[i % len(key)] for i, b in enumerate(ct))
        return pt.decode("utf-8")
    except Exception:
        # Return empty string on failure; caller decides how to proceed
        return ""

def _aes256_encrypt_to_b64(plaintext: str, secret: str) -> str:
    # AES-256 GCM encryption, returns urlsafe base64(nonce + ciphertext|tag)
    key = _derive_key_bytes(secret)  # 32 bytes (AES-256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = nonce + ct
    return base64.urlsafe_b64encode(blob).decode("ascii")

def _aes256_decrypt_from_b64(ciphertext_b64: str, secret: str) -> str:
    # AES-256 GCM decryption counterpart
    try:
        blob = base64.urlsafe_b64decode((ciphertext_b64 or "").encode("ascii"))
        nonce, ct = blob[:12], blob[12:]
        aesgcm = AESGCM(_derive_key_bytes(secret))
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode("utf-8")
    except Exception:
        return ""

@app.route("/verify-otp-code", methods=["POST"])
def verify_otp_code():
    """
    Verify a user-submitted TOTP code against the OTP configuration stored in session.
    On success:
      - session['current_user'] is set to the current user_id
      - a credential_configs record is created via Twilight Digital API with:
           credential_type = 'Authenticator_2FA'
           encrypted_credential = (encrypted otp_uri from session)
    Returns plain text:
      - 'ok' if the code is valid
      - 'failed' otherwise
    """
    try:
        data = request.get_json(silent=True) or {}
        code = (data.get("code") or "").strip()
        user_id = session.get("user_id")
        otp_secret = session.get("otp_secret")
        email = data.get("email") or session.get("email")
        credential_config = None

        if not code or not code.isdigit():
            return jsonify(ok=False)
        if not base_url:
            app.logger.error(f"verify_otp_code: TWILIGHT_DIGITAL_API_BASE_URL not configured - user_id={user_id}")
            return jsonify(ok=False)
        if not otp_secret:
            try:
                status, resp = _http_json("GET", f"{base_url}/credential_configs/by_email/{email}")
                if status == 200 and isinstance(resp, list):
                    # Prefer Authenticator_2FA records
                    for item in resp:
                        try:
                            credential_config = item
                            if (credential_config or {}).get("credential_type") == "Authenticator_2FA":
                                enc = (credential_config or {}).get("encrypted_credential") or ""
                                decrypted = _aes256_decrypt_from_b64(enc, enc_secret_key)
                                if decrypted:
                                    otp_secret = decrypted
                                    app.logger.info("verify_otp_code: Recovered otp_secret from credential_configs")
                                    break
                        except Exception:
                            # Keep iterating on malformed items
                            continue
                else:
                    app.logger.error(f"verify_otp_code: Failed to fetch credential_configs: HTTP {status} {resp}")
            except Exception as ex:
                app.logger.error(f"verify_otp_code: error fetching credential_configs by email: {ex}")

        try:
            totp = pyotp.TOTP(otp_secret)
            if totp.verify(code, valid_window=1) is False:
                return jsonify(ok=False)
        except Exception as ex:
            app.logger.error(f"verify_otp_code: Invalid otp data in session: {ex}")
            return jsonify(ok=False)

        # Mark the current user in the session, they're logged in!
        session["current_user"] = user_id

        # Encrypt otp_uri for storage
        enc_secret = os.environ.get("APP_ENCRYPTION_KEY") or app.secret_key or "twilight-digital"
        encrypted_credential = _aes256_encrypt_to_b64(otp_secret, enc_secret)

        # Persist credential config via Twilight Digital API if we don't have it
        if base_url and credential_config is None:
            try:
                payload = {
                    "user_id": user_id,
                    "email": email,
                    "credential_type": "Authenticator_2FA",
                    "encrypted_credential": encrypted_credential,
                }
                status, resp = _http_json("POST", f"{base_url}/credential_configs", user_id, payload)
                if status not in (200, 201):
                    app.logger.error(f"verify_otp_code: credential_configs create failed: HTTP {status} {resp}")
            except Exception as ex:
                app.logger.error(f"verify_otp_code: error calling Twilight Digital API: {ex}")
        else:
            app.logger.info("verify_otp_code: Twilight Digital API not configured; skipping credential_configs persistence")
    except Exception as ex:
        app.logger.error(f"verify_otp_code: unexpected error: {ex}", exc_info=True)
        return jsonify(ok=False)
    return jsonify(ok=True)

@app.route('/user-page')
def user_page():
    # Attempt to resolve current user's id
    user_id = session.get("current_user") or session.get("user_id")

    # No longer prefetch feed/channels/subscriptions here; the page will fetch them via AJAX.
    if not base_url:
        app.logger.warning("TWILIGHT_DIGITAL_API_BASE_URL not configured; user page data AJAX endpoints will fail.")
    if not user_id:
        app.logger.info("No user_id in session; user page will show empty data until sign-in completes.")

    return render_template("UserPage.html", sid=session.sid)

@app.route('/api/user/feed', methods=['GET'])
def api_user_feed():
    user_id = session.get("current_user") or session.get("user_id")
    if not user_id:
        return jsonify(ok=False, error="Unauthorized"), 401
    if not base_url:
        return jsonify(ok=False, error="Service not configured"), 503
    try:
        status, resp = _http_json("GET", f"{base_url}/feeds/by_user_id/{user_id}")
        if status == 200 and isinstance(resp, list):
            return jsonify(ok=True, items=resp)
        app.logger.error(f"/api/user/feed: HTTP {status} {resp}")
        return jsonify(ok=False, error="Failed to load feed"), 502
    except Exception as ex:
        app.logger.exception(f"/api/user/feed: exception: {ex}")
        return jsonify(ok=False, error="Internal error"), 500

@app.route('/api/user/channels', methods=['GET'])
def api_user_channels():
    user_id = session.get("current_user") or session.get("user_id")
    if not user_id:
        return jsonify(ok=False, error="Unauthorized"), 401
    if not base_url:
        return jsonify(ok=False, error="Service not configured"), 503
    try:
        status, resp = _http_json("GET", f"{base_url}/channels/by_creator_id/{user_id}")
        if status == 200 and isinstance(resp, list):
            return jsonify(ok=True, items=resp)
        app.logger.error(f"/api/user/channels: HTTP {status} {resp}")
        return jsonify(ok=False, error="Failed to load channels"), 502
    except Exception as ex:
        app.logger.exception(f"/api/user/channels: exception: {ex}")
        return jsonify(ok=False, error="Internal error"), 500

@app.route('/api/user/subscriptions', methods=['GET'])
def api_user_subscriptions():
    user_id = session.get("current_user") or session.get("user_id")
    if not user_id:
        return jsonify(ok=False, error="Unauthorized"), 401
    if not base_url:
        return jsonify(ok=False, error="Service not configured"), 503
    try:
        status, resp = _http_json("GET", f"{base_url}/subscriptions/by_user_id/{user_id}")
        if status == 200 and isinstance(resp, list):
            return jsonify(ok=True, items=resp)
        app.logger.error(f"/api/user/subscriptions: HTTP {status} {resp}")
        return jsonify(ok=False, error="Failed to load subscriptions"), 502
    except Exception as ex:
        app.logger.exception(f"/api/user/subscriptions: exception: {ex}")
        return jsonify(ok=False, error="Internal error"), 500

@app.route('/signout', methods=['GET'])
def sign_out():
    """
    Clear all user-related session data and return to the landing page.
    """
    try:
        session.clear()
    except Exception as ex:
        app.logger.error(f"sign_out: failed to clear session: {ex}", exc_info=True)
    return redirect(url_for('landing_page'))

if __name__ == '__main__':
    app.run()
