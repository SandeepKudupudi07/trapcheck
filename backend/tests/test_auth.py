import io
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

with patch.dict(os.environ, {
    "DATABASE_URL": "sqlite:///:memory:",
    "JWT_SECRET_KEY": "test-auth-jwt-9d4f18528ec94e7c8c26fcf2eab67eb3",
    "ADMIN_SECRET": "test-auth-admin-9d4f18528ec94e7c8c26fcf2eab67eb3",
    "SMTP_EMAIL": "",
    "SMTP_PASSWORD": "",
}):
    import bcrypt
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient
    from jose import jwt
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from auth import auth, email_service, routes
    from auth.database import Base, User, get_db
    from rate_limit import limiter


class SecretConfigurationTests(unittest.TestCase):
    def test_import_fails_closed_for_invalid_secrets(self):
        for secret in (
            "", "short", "x" * 31, " " * 40,
            "trapcheck-change-this-in-production-please",
            "change-this-to-a-long-random-string-in-production",
            "replace-with-a-secure-random-secret-at-least-32-characters",
        ):
            with self.subTest(secret=secret), patch.dict(os.environ, {"JWT_SECRET_KEY": secret}):
                with self.assertRaisesRegex(RuntimeError, "JWT_SECRET_KEY.*32 characters"):
                    runpy.run_path(str(Path(auth.__file__).resolve()))
        with patch.dict(os.environ):
            os.environ.pop("JWT_SECRET_KEY", None)
            with self.assertRaisesRegex(RuntimeError, "JWT_SECRET_KEY"):
                runpy.run_path(str(Path(auth.__file__).resolve()))

    def test_accepts_a_non_placeholder_secret(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "8bd109213725bf48fc76a39569ecda80"}):
            self.assertEqual(auth._load_secret_key(), os.environ["JWT_SECRET_KEY"])


class PasswordTests(unittest.TestCase):
    def test_password_boundaries_use_utf8_bytes(self):
        for password in ("a" * 8, "a" * 72, "é" * 36):
            with self.subTest(length=len(password.encode("utf-8"))):
                hashed = auth.hash_password(password)
                self.assertTrue(auth.verify_password(password, hashed))
                self.assertFalse(auth.verify_password("wrong-password", hashed))
                self.assertFalse(auth.verify_password(password + "a" * 73, hashed))
        for password in ("a" * 7, "é" * 7, "a" * 73, "é" * 37):
            with self.subTest(password=password), self.assertRaises(ValueError):
                auth.hash_password(password)

    def test_existing_bcrypt_hash_formats_remain_usable(self):
        hashed = bcrypt.hashpw(b"legacy-password", bcrypt.gensalt(rounds=4)).decode("ascii")
        for prefix in ("$2a$", "$2b$", "$2y$"):
            with self.subTest(prefix=prefix):
                self.assertTrue(auth.verify_password("legacy-password", prefix + hashed[4:]))
        self.assertFalse(auth.verify_password("legacy-password", "not-a-bcrypt-hash"))


class AuthRouteTests(unittest.TestCase):
    email = "member@example.com"
    password = "initial-password"

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="trapcheck-auth-tests-")
        cls.addClassCleanup(cls.temp_dir.cleanup)
        database_path = Path(cls.temp_dir.name) / "auth.sqlite"
        cls.engine = create_engine(
            "sqlite:///" + database_path.as_posix(),
            connect_args={"check_same_thread": False},
        )
        cls.addClassCleanup(cls.engine.dispose)
        cls.session_factory = sessionmaker(bind=cls.engine)
        cls.password_hash = bcrypt.hashpw(
            cls.password.encode("utf-8"), bcrypt.gensalt(rounds=4)
        ).decode("ascii")

    def setUp(self):
        Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)
        self.db = self.session_factory()
        self.addCleanup(self.db.close)
        self.user = User(email=self.email, hashed_password=self.password_hash)
        self.db.add(self.user)
        self.db.commit()
        limiter.reset()
        self.addCleanup(limiter.reset)
        email_service._reset_tokens.clear()
        self.addCleanup(email_service._reset_tokens.clear)
        self.smtp_patch = patch.object(email_service.smtplib, "SMTP_SSL", autospec=True)
        self.smtp = self.smtp_patch.start()
        self.addCleanup(self.smtp_patch.stop)
        self.settings_patch = patch.multiple(
            email_service, SMTP_EMAIL="sender@example.com", SMTP_PASSWORD="test-smtp-password"
        )
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)
        app = FastAPI()
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.include_router(routes.router)

        def test_db():
            yield self.db

        @app.get("/optional")
        async def optional_user(user=Depends(auth.get_optional_user)):
            return {"email": user.email if user else None}

        app.dependency_overrides[get_db] = test_db
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def headers(self, token=None):
        if token is None:
            token = auth.create_access_token(self.user.email, self.user.hashed_password)
        return {"Authorization": "Bearer " + token}

    def login(self, password=None):
        return self.client.post("/auth/login", data={
            "username": self.email,
            "password": self.password if password is None else password,
        })

    def test_register_login_and_authenticated_profile(self):
        response = self.client.post("/auth/register", json={
            "email": "new@example.com", "password": "é" * 36,
        })
        self.assertEqual(response.status_code, 201)
        stored = self.db.query(User).filter_by(email="new@example.com").one()
        self.assertTrue(auth.verify_password("é" * 36, stored.hashed_password))
        login = self.login()
        self.assertEqual(login.status_code, 200)
        token = login.json()["access_token"]
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        self.assertEqual(payload["sub"], self.email)
        self.assertEqual(len(payload["pwd"]), 64)
        self.assertNotEqual(payload["pwd"], self.user.hashed_password)
        self.assertEqual(self.client.get("/auth/me", headers=self.headers(token)).status_code, 200)
        self.assertEqual(
            self.client.get("/optional", headers=self.headers(token)).json(), {"email": self.email}
        )

    def test_register_and_reset_validate_password_and_email(self):
        for path in ("/auth/register", "/auth/reset-password"):
            for password in ("short", "é" * 7, "a" * 73, "é" * 37):
                with self.subTest(path=path, password=password):
                    response = self.client.post(path, json={
                        "email": "new@example.com", "password": password, "otp": "123456",
                    })
                    self.assertEqual(response.status_code, 422)
            self.assertEqual(self.client.post(path, json={
                "email": "invalid", "password": "valid-password", "otp": "123456",
            }).status_code, 422)
        self.assertEqual(self.db.query(User).count(), 1)

    def test_reset_otp_requires_exactly_six_ascii_digits(self):
        for otp in ("12345", "1234567", "abcdef", "１２３４５６", "12345\n", " 123456", 123456, None):
            with self.subTest(otp=otp):
                response = self.client.post("/auth/reset-password", json={
                    "email": self.email, "password": "replacement-password", "otp": otp,
                })
                self.assertEqual(response.status_code, 422)

    def test_duplicate_registration_rolls_back_after_concurrent_insert(self):
        with patch.object(routes, "get_user_by_email", return_value=None), patch.object(
            self.db, "rollback", wraps=self.db.rollback
        ) as rollback:
            response = self.client.post("/auth/register", json={
                "email": self.email, "password": self.password,
            })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Email already registered")
        rollback.assert_called_once()
        self.assertTrue(self.db.is_active)
        self.assertEqual(self.db.query(User).count(), 1)

    def test_inactive_accounts_cannot_login_or_use_tokens(self):
        headers = self.headers()
        self.user.is_active = False
        self.db.commit()
        self.assertEqual(self.login().status_code, 401)
        for path in ("/auth/me", "/optional"):
            self.assertEqual(self.client.get(path, headers=headers).status_code, 401)

    def test_overlimit_login_is_rejected_without_truncation(self):
        for password in ("a" * 72, "é" * 36):
            self.user.hashed_password = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt(rounds=4)
            ).decode("ascii")
            self.db.commit()
            self.assertEqual(self.login(password).status_code, 200)
            self.assertEqual(self.login(password + "a").status_code, 401)

    def test_optional_auth_allows_only_absent_credentials(self):
        self.assertEqual(self.client.get("/optional").json(), {"email": None})
        self.assertEqual(self.client.get("/auth/me").status_code, 401)
        for authorization in ("Bearer invalid", "Bearer", "", "Basic invalid"):
            with self.subTest(authorization=authorization):
                response = self.client.get("/optional", headers={"Authorization": authorization})
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers["www-authenticate"], "Bearer")

    def test_invalid_expired_and_legacy_tokens_are_rejected(self):
        payload = jwt.decode(self.headers()["Authorization"][7:], auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        invalid_payloads = [
            {key: value for key, value in payload.items() if key != "pwd"},
            {key: value for key, value in payload.items() if key != "exp"},
            {**payload, "exp": datetime.utcnow() - timedelta(minutes=1)},
            {**payload, "pwd": "0" * 64},
            {**payload, "pwd": ["invalid"]},
            {**payload, "pwd": "é" * 64},
            {**payload, "sub": "unknown@example.com"},
        ]
        tokens = [jwt.encode(value, auth.SECRET_KEY, algorithm=auth.ALGORITHM) for value in invalid_payloads]
        tokens.append(jwt.encode(payload, "different-signing-key-" * 3, algorithm=auth.ALGORITHM))
        for token in tokens:
            for path in ("/auth/me", "/optional"):
                with self.subTest(path=path, token=token):
                    self.assertEqual(self.client.get(path, headers=self.headers(token)).status_code, 401)

    def test_deleted_user_token_is_rejected(self):
        headers = self.headers()
        self.db.delete(self.user)
        self.db.commit()
        for path in ("/auth/me", "/optional"):
            self.assertEqual(self.client.get(path, headers=headers).status_code, 401)

    def test_history_limit_bounds(self):
        for limit in ("0", "-1", "101", "invalid"):
            self.assertEqual(self.client.get(
                "/auth/history", params={"limit": limit}, headers=self.headers()
            ).status_code, 422)
        for limit in ("1", "100"):
            self.assertEqual(self.client.get(
                "/auth/history", params={"limit": limit}, headers=self.headers()
            ).status_code, 200)

    def test_reset_consumes_otp_and_revokes_previous_jwts(self):
        old_token = self.login().json()["access_token"]
        otp = email_service.generate_reset_token(self.email)
        body = {"email": self.email, "otp": otp, "password": "é" * 36}
        response = self.client.post("/auth/reset-password", json=body)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.email, email_service._reset_tokens)
        self.assertEqual(self.client.post("/auth/reset-password", json=body).status_code, 400)
        for path in ("/auth/me", "/optional"):
            self.assertEqual(self.client.get(path, headers=self.headers(old_token)).status_code, 401)
        self.assertEqual(self.login().status_code, 401)
        new_login = self.login(body["password"])
        self.assertEqual(new_login.status_code, 200)
        for path in ("/auth/me", "/optional"):
            self.assertEqual(self.client.get(
                path, headers=self.headers(new_login.json()["access_token"])
            ).status_code, 200)

    def test_missing_smtp_returns_same_503_before_account_lookup(self):
        with patch.multiple(email_service, SMTP_EMAIL="", SMTP_PASSWORD=""), patch.object(
            routes, "get_user_by_email"
        ) as lookup:
            existing = self.client.post("/auth/forgot-password", json={"email": self.email})
            unknown = self.client.post("/auth/forgot-password", json={"email": "unknown@example.com"})
        self.assertEqual(existing.status_code, 503)
        self.assertEqual(unknown.status_code, 503)
        self.assertEqual(existing.json(), unknown.json())
        lookup.assert_not_called()
        self.smtp.assert_not_called()

    def test_smtp_failure_does_not_reveal_accounts_or_leave_tokens(self):
        self.smtp.side_effect = OSError("sensitive-smtp-error-with-address-and-otp")
        with self.assertLogs(email_service.logger, level="ERROR") as logs:
            existing = self.client.post("/auth/forgot-password", json={"email": self.email})
        unknown = self.client.post("/auth/forgot-password", json={"email": "unknown@example.com"})
        self.assertEqual(existing.status_code, 200)
        self.assertEqual(unknown.status_code, 200)
        self.assertEqual(existing.json(), unknown.json())
        self.assertNotIn(self.email, email_service._reset_tokens)
        self.assertNotIn("sensitive-smtp-error", " ".join(logs.output))
        self.assertNotIn(self.email, " ".join(logs.output))
        self.assertNotIn("has been sent", existing.json()["message"])

    def test_configured_smtp_uses_timeout_and_preserves_delivered_token(self):
        with patch("builtins.print") as output:
            response = self.client.post("/auth/forgot-password", json={"email": self.email})
        self.assertEqual(response.status_code, 200)
        self.smtp.assert_called_once_with("smtp.gmail.com", 465, timeout=15)
        self.smtp.return_value.__enter__.return_value.sendmail.assert_called_once()
        self.assertIn(self.email, email_service._reset_tokens)
        output.assert_not_called()

    def test_auth_endpoints_limit_requests_to_five_per_minute(self):
        cases = (
            ("/auth/login", {"data": {"username": self.email, "password": "wrong-password"}}, 401),
            ("/auth/register", {"json": {"email": self.email, "password": self.password}}, 400),
            ("/auth/forgot-password", {"json": {"email": "unknown@example.com"}}, 200),
            ("/auth/reset-password", {"json": {
                "email": self.email, "otp": "000000", "password": "replacement-password",
            }}, 400),
        )
        for path, kwargs, expected in cases:
            with self.subTest(path=path):
                limiter.reset()
                for _ in range(5):
                    self.assertEqual(self.client.post(path, **kwargs).status_code, expected)
                self.assertEqual(self.client.post(path, **kwargs).status_code, 429)


class ResetTokenTests(unittest.TestCase):
    email = "reset@example.com"

    def setUp(self):
        email_service._reset_tokens.clear()
        self.addCleanup(email_service._reset_tokens.clear)
        self.smtp_patch = patch.object(email_service.smtplib, "SMTP_SSL", autospec=True)
        self.smtp = self.smtp_patch.start()
        self.addCleanup(self.smtp_patch.stop)

    def test_expiration_is_checked_before_token_comparison(self):
        otp = email_service.generate_reset_token(self.email)
        now = datetime.utcnow()
        email_service._reset_tokens[self.email]["expires_at"] = now
        with patch.object(email_service, "datetime") as clock, patch.object(
            email_service.hmac, "compare_digest", wraps=email_service.hmac.compare_digest
        ) as compare:
            clock.utcnow.return_value = now
            self.assertFalse(email_service.verify_reset_token(self.email, otp))
        compare.assert_not_called()
        self.assertNotIn(self.email, email_service._reset_tokens)

    def test_five_wrong_attempts_invalidate_token(self):
        otp = email_service.generate_reset_token(self.email)
        with patch.object(
            email_service.hmac, "compare_digest", wraps=email_service.hmac.compare_digest
        ) as compare:
            for attempt in range(4):
                self.assertFalse(email_service.verify_reset_token(self.email, "000000"))
                self.assertEqual(email_service._reset_tokens[self.email]["attempts"], attempt + 1)
            self.assertTrue(email_service.verify_reset_token(self.email, otp))
            self.assertFalse(email_service.verify_reset_token(self.email, "000000"))
            self.assertEqual(compare.call_count, 6)
        self.assertNotIn(self.email, email_service._reset_tokens)
        self.assertFalse(email_service.verify_reset_token(self.email, otp))

    def test_new_token_replaces_previous_and_resets_attempt_count(self):
        with patch.object(email_service.secrets, "randbelow", side_effect=[0, 1]):
            old = email_service.generate_reset_token(self.email)
            email_service.verify_reset_token(self.email, "000000")
            new = email_service.generate_reset_token(self.email)
        self.assertEqual(email_service._reset_tokens[self.email]["attempts"], 0)
        self.assertFalse(email_service.verify_reset_token(self.email, old))
        self.assertTrue(email_service.verify_reset_token(self.email, new))
        email_service.consume_reset_token(self.email)
        self.assertFalse(email_service.verify_reset_token(self.email, new))

    def test_unconfigured_smtp_never_claims_success_or_prints_secrets(self):
        output = io.StringIO()
        with patch.multiple(email_service, SMTP_EMAIL="", SMTP_PASSWORD=""), redirect_stdout(output):
            with self.assertLogs(email_service.logger, level="ERROR") as logs:
                self.assertFalse(email_service.send_reset_email(self.email, "123456"))
        self.smtp.assert_not_called()
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(self.email, " ".join(logs.output))
        self.assertNotIn("123456", " ".join(logs.output))


if __name__ == "__main__":
    unittest.main()
