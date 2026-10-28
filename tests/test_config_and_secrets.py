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
from tests.fakes import (
    SYNTHETIC_AAP_TOKEN,
    SYNTHETIC_OKTA_HOST,
    SYNTHETIC_OKTA_TOKEN,
    captured_logs,
    read_only_env,
)


class SecretRenderingTests(unittest.TestCase):
    def test_diagnostics_report_presence_not_values(self):
        diagnostics = load_settings(read_only_env()).diagnostics()
        rendered = json.dumps(diagnostics)
        self.assertNotIn(SYNTHETIC_OKTA_TOKEN, rendered)
        self.assertNotIn(SYNTHETIC_AAP_TOKEN, rendered)
        self.assertEqual(diagnostics["okta.api_token"], "<set>")
        self.assertEqual(diagnostics["aap.token"], "<set>")
        self.assertEqual(diagnostics["okta.org_host"], SYNTHETIC_OKTA_HOST)

    def test_unset_secrets_report_unset(self):
        diagnostics = load_settings({}).diagnostics()
        self.assertEqual(diagnostics["okta.api_token"], "<unset>")

    def test_settings_repr_and_str_hide_secrets(self):
        settings = load_settings(read_only_env())
        for rendered in (repr(settings), str(settings), f"{settings}"):
            self.assertNotIn(SYNTHETIC_OKTA_TOKEN, rendered)
            self.assertNotIn(SYNTHETIC_AAP_TOKEN, rendered)

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
            "concurrency above ceiling": {"OGWA_HTTP_MAX_CONCURRENCY": "50"},
            "zero concurrency": {"OGWA_HTTP_MAX_CONCURRENCY": "0"},
            "zero read timeout": {"OGWA_HTTP_READ_TIMEOUT_SECONDS": "0"},
            "unbounded read timeout": {"OGWA_HTTP_READ_TIMEOUT_SECONDS": "9999"},
            "nan timeout": {"OGWA_HTTP_CONNECT_TIMEOUT_SECONDS": "nan"},
            "non-numeric timeout": {"OGWA_HTTP_CONNECT_TIMEOUT_SECONDS": "fast"},
            "negative retries": {"OGWA_HTTP_MAX_RETRIES": "-1"},
            "excessive retries": {"OGWA_HTTP_MAX_RETRIES": "100"},
            "fractional retries": {"OGWA_HTTP_MAX_RETRIES": "2.5"},
            "plain http okta": {"OGWA_OKTA_ORG_URL": "http://okta.synthetic.example"},
            "credentials in url": {"OGWA_AAP_URL": "https://user:pw@aap.synthetic.example"},
            "query in url": {"OGWA_OKTA_ORG_URL": "https://okta.synthetic.example/?x=1"},
            "relative url": {"OGWA_OKTA_ORG_URL": "okta.synthetic.example"},
            "unknown log level": {"OGWA_LOG_LEVEL": "TRACE"},
            "typo in key": {"OGWA_EXECUTON_MODE": "READ_ONLY_PRODUCTION"},
        }
        for name, overrides in unsafe.items():
            with self.subTest(name), self.assertRaises(ConfigError):
                load_settings(read_only_env(**overrides))

    def test_keys_that_differ_only_in_case_are_refused_in_either_order(self):
        pairs = (("OGWA_EXECUTION_MODE", "LOCAL_SYNTHETIC"), ("ogwa_execution_mode", "READ_ONLY_PRODUCTION"))
        for environ in (dict(pairs), dict(reversed(pairs))):
            with self.subTest(first=next(iter(environ))):
                with self.assertRaisesRegex(ConfigError, "OGWA_EXECUTION_MODE"):
                    load_settings(environ)
        with self.assertRaises(ConfigError) as caught:
            load_settings({"OGWA_AAP_TOKEN": SYNTHETIC_AAP_TOKEN, "ogwa_aap_token": SYNTHETIC_OKTA_TOKEN})
        self.assertNotIn(SYNTHETIC_AAP_TOKEN, str(caught.exception))
        self.assertNotIn(SYNTHETIC_OKTA_TOKEN, str(caught.exception))
        self.assertEqual(load_settings({"ogwa_log_level": "DEBUG"}).log_level, "DEBUG")  # one spelling, any case

    def test_synthetic_mode_rejects_live_credentials(self):
        for key, value in (("OGWA_OKTA_API_TOKEN", SYNTHETIC_OKTA_TOKEN), ("OGWA_AAP_TOKEN", SYNTHETIC_AAP_TOKEN)):
            with self.subTest(key=key), self.assertRaises(ConfigError):
                load_settings({key: value})

    def test_synthetic_mode_rejects_non_loopback_service_urls(self):
        with self.assertRaises(ConfigError):
            load_settings({"OGWA_OKTA_ORG_URL": "https://okta.synthetic.example"})

    def test_synthetic_mode_accepts_loopback_service_urls(self):
        settings = load_settings({"OGWA_OKTA_ORG_URL": "http://127.0.0.1:8080/"})
        self.assertEqual(settings.okta_org_url, "http://127.0.0.1:8080")

    def test_config_errors_do_not_echo_secret_values(self):
        with self.assertRaises(ConfigError) as caught:
            load_settings({"OGWA_OKTA_API_TOKEN": SYNTHETIC_OKTA_TOKEN})
        self.assertNotIn(SYNTHETIC_OKTA_TOKEN, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
