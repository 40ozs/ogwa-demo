import unittest
from pathlib import Path

from app.core.config import load_settings
from app.core.database_url import DEFAULT_DATABASE_URL, PROJECT_ROOT, parse_database_url
from app.core.errors import ConfigError


class DatabaseUrlTests(unittest.TestCase):
    def test_default_is_the_git_ignored_demo_store(self):
        target = parse_database_url(None)
        self.assertEqual(DEFAULT_DATABASE_URL, "sqlite:///var/ogwa-demo.sqlite3")
        self.assertEqual(target.path, (PROJECT_ROOT / "var" / "ogwa-demo.sqlite3").resolve())
        self.assertEqual(parse_database_url("   "), target)

    def test_relative_paths_resolve_against_the_project_not_the_cwd(self):
        self.assertEqual(parse_database_url("sqlite:///var/x.sqlite3").path, (PROJECT_ROOT / "var" / "x.sqlite3").resolve())

    def test_absolute_paths_and_memory(self):
        absolute = (Path(PROJECT_ROOT) / "var" / "abs.sqlite3").resolve()
        self.assertEqual(parse_database_url(f"sqlite:///{absolute.as_posix()}").path, absolute)
        memory = parse_database_url("sqlite:///:memory:")
        self.assertTrue(memory.in_memory)
        self.assertEqual(memory.location, ":memory:")

    def test_unsafe_or_unsupported_urls_fail_closed(self):
        cases = {
            "postgresql://db.synthetic.example/ogwa": "PostgreSQL",
            "postgresql+psycopg://svc@db.synthetic.example/ogwa": "PostgreSQL",
            "mysql://db.synthetic.example/ogwa": "sqlite:///",
            "sqlite://db.synthetic.example/x": "sqlite:///",
            "sqlite:///var/x.sqlite3?mode=memory": "query",
            "sqlite:///user:secret@var/x.sqlite3": "credentials",
            "sqlite:///": "name a database file",
        }
        for url, message in cases.items():
            with self.subTest(url=url), self.assertRaisesRegex(ConfigError, message):
                parse_database_url(url)

    def test_settings_expose_the_database_without_secrets(self):
        settings = load_settings({"OGWA_DATABASE_URL": "sqlite:///var/x.sqlite3"})
        self.assertEqual(settings.diagnostics()["database.location"], str((PROJECT_ROOT / "var" / "x.sqlite3").resolve()))
        self.assertEqual(settings.diagnostics()["database.backend"], "sqlite")

    def test_bad_database_url_refuses_startup(self):
        with self.assertRaises(ConfigError):
            load_settings({"OGWA_DATABASE_URL": "postgres://db.synthetic.example/ogwa"})


if __name__ == "__main__":
    unittest.main()
