import contextlib
import copy
import io
import json
import logging
import pickle
import unittest

from app.core.config import load_settings
from app.core.errors import ConfigError
from app.core.logging_setup import ROOT_LOGGER, configure_logging
from app.core.redaction import redact_text
from app.core.secret import Secret
from tests.fakes import captured_logs

SYNTHETIC_TOKEN = "synthetic-okta-token-value-0001"


class SecretRenderingTests(unittest.TestCase):
    def test_diagnostics_hold_no_credential_field(self):
        diagnostics = load_settings({}).diagnostics()
        self.assertFalse([k for k in diagnostics if any(w in k for w in ("token", "secret", "password", "okta", "aap"))])
        self.assertEqual(diagnostics["live_integrations"], "unavailable")

    def test_secret_renders_as_placeholder(self):
        secret = Secret("synthetic-placeholder-check-1")
        for rendered in (str(secret), repr(secret), f"{secret}", f"{secret!s:>40}", "%s" % secret):
            self.assertNotIn("synthetic-placeholder-check-1", rendered)
        self.assertEqual(secret.reveal(), "synthetic-placeholder-check-1")

    def test_secret_refuses_serialization_and_copying(self):
        secret = Secret("synthetic-serialize-check-2")
        with self.assertRaises(TypeError):
            pickle.dumps(secret)
        with self.assertRaises(TypeError):
            copy.deepcopy(secret)
        with self.assertRaises(TypeError):
            json.dumps(secret)

    def test_registered_secret_is_scrubbed_from_free_text_logs(self):
        secret = Secret("synthetic-free-text-secret-3")
        with captured_logs() as logs:
            logging.getLogger("ogwa.test").error("careless message containing %s", secret.reveal())
        self.assertNotIn("synthetic-free-text-secret-3", logs.getvalue())
        self.assertIn("***", logs.getvalue())

    def test_sensitive_structured_fields_are_redacted(self):
        with captured_logs() as logs:
            logging.getLogger("ogwa.test").info(
                "event", extra={"ogwa": {"api_token": "synthetic-field-value-4", "client_secret": Secret("synthetic-field-value-5")}}
            )
        output = logs.getvalue()
        self.assertNotIn("synthetic-field-value-4", output)
        self.assertNotIn("synthetic-field-value-5", output)

    def test_redact_text_patterns(self):
        cases = {
            "Authorization: SSWS abcDEF0123456789": "abcDEF0123456789",
            "header Bearer eyJhbGciOi.payload.sig": "eyJhbGciOi.payload.sig",
            "https://svc:hunter2pass@db.synthetic.example/x": "hunter2pass",
            "password=hunter2pass&user=x": "hunter2pass",
            '{"client_secret": "abc123xyz"}': "abc123xyz",
        }
        for text, leaked in cases.items():
            with self.subTest(text=text):
                self.assertNotIn(leaked, redact_text(text))


class LogRedactionFailClosedTests(unittest.TestCase):
    """A sensitive field of any shape, and any logging failure, never reaches a sink raw."""

    def setUp(self):
        logger = logging.getLogger(ROOT_LOGGER)
        saved = (list(logger.handlers), logger.level, logger.propagate)

        def restore():
            logger.handlers[:] = saved[0]
            logger.setLevel(saved[1])
            logger.propagate = saved[2]
        self.addCleanup(restore)

    def log_once(self, stream, *args, **kwargs) -> str:
        """Logs one record through the production handler; returns what reached stderr."""
        stderr = io.StringIO()
        configure_logging("DEBUG", stream=stream)
        with contextlib.redirect_stderr(stderr):
            logging.getLogger("ogwa.test").info(*args, **kwargs)
        return stderr.getvalue()

    def test_sensitive_fields_of_every_shape_are_redacted(self):
        marker = "synthetic-shaped-value-6"
        shapes = {
            "scalar": marker,
            "number": 61234567,
            "list": [marker],
            "tuple": (marker,),
            "set": {marker},
            "dict": {"inner": marker},
            "nested": ({"inner": [marker]},),
        }
        for shape, value in shapes.items():
            with self.subTest(shape=shape):
                out = io.StringIO()
                err = self.log_once(out, "event", extra={"ogwa": {"api_token": value}})
                self.assertEqual(err, "")
                self.assertEqual(json.loads(out.getvalue())["fields"]["api_token"], "***")
                self.assertNotIn(marker, out.getvalue())

    def test_sensitive_keys_nested_under_ordinary_fields_are_scrubbed(self):
        marker = "synthetic-nested-value-7"
        for value in ({"api_token": marker}, {"tokens": [marker]}, [{"password": marker}]):
            with self.subTest(value=type(value).__name__):
                out = io.StringIO()
                err = self.log_once(out, "event", extra={"ogwa": {"request": value}})
                self.assertEqual(err, "")
                self.assertNotIn(marker, out.getvalue())

    def test_format_arguments_are_redacted_beside_a_sensitive_container(self):
        secret = Secret("synthetic-format-arg-8").reveal()
        out = io.StringIO()
        err = self.log_once(out, "calling %s", secret, extra={"ogwa": {"tokens": ["a"]}})
        self.assertEqual(err, "")
        self.assertNotIn(secret, out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["fields"]["tokens"], "***")

    def test_logging_failures_never_print_record_content(self):
        secret = Secret("synthetic-fallback-secret-9").reveal()

        class UnwritableStream(io.StringIO):
            def write(self, text):
                raise OSError("synthetic: stream closed")

        cases = {
            "bad format arguments": (io.StringIO(), "value %d", TypeError),
            "unwritable stream": (UnwritableStream(), "value %s", OSError),
        }
        for name, (stream, message, error) in cases.items():
            with self.subTest(case=name):
                err = self.log_once(stream, message, secret)
                self.assertNotIn(secret, err)
                self.assertNotIn(message, err)
                self.assertIn(error.__name__, err, "the failure stays visible, without content")


class FailClosedConfigTests(unittest.TestCase):
    def test_unsafe_configuration_is_rejected(self):
        unsafe = {
            "an outbound HTTP setting": {"OGWA_HTTP_MAX_CONCURRENCY": "2"},
            "an Okta URL": {"OGWA_OKTA_ORG_URL": "https://okta.synthetic.example"},
            "an AAP URL with credentials": {"OGWA_AAP_URL": "https://user:pw@aap.synthetic.example"},
            "an in-memory store": {"OGWA_DATABASE_URL": "sqlite:///:memory:"},
            "a PostgreSQL store": {"OGWA_DATABASE_URL": "postgresql://db.synthetic.example/ogwa"},
            "unknown log level": {"OGWA_LOG_LEVEL": "TRACE"},
            "typo in key": {"OGWA_EXECUTON_MODE": "LOCAL_SYNTHETIC"},
        }
        for name, environ in unsafe.items():
            with self.subTest(name), self.assertRaises(ConfigError):
                load_settings(environ)

    def test_keys_that_differ_only_in_case_are_refused_in_either_order(self):
        pairs = (("OGWA_LOG_LEVEL", "INFO"), ("ogwa_log_level", "DEBUG"))
        for environ in (dict(pairs), dict(reversed(pairs))):
            with self.subTest(first=next(iter(environ))):
                with self.assertRaisesRegex(ConfigError, "OGWA_LOG_LEVEL"):
                    load_settings(environ)
        self.assertEqual(load_settings({"ogwa_log_level": "DEBUG"}).log_level, "DEBUG")  # one spelling, any case

    def test_config_errors_do_not_echo_secret_values(self):
        for key in ("OGWA_OKTA_API_TOKEN", "OGWA_AAP_TOKEN", "OKTA_CLIENT_SECRET", "OGWA_UNKNOWN_TOKEN"):
            with self.subTest(key=key), self.assertRaises(ConfigError) as caught:
                load_settings({key: SYNTHETIC_TOKEN})
            self.assertNotIn(SYNTHETIC_TOKEN, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
