"""Parsing of ``OGWA_DATABASE_URL``.

The URL follows SQLAlchemy's conventions so it stays valid when an ORM is adopted:
``sqlite:///relative/path.sqlite3``, ``sqlite:////absolute/path``,
``sqlite:///C:/absolute/path`` and ``sqlite:///:memory:``. Relative paths resolve against
the project root, not the working directory.

Only SQLite is supported by this build. PostgreSQL is the intended deployment target, but
no approved driver is installed (decision D5), so a PostgreSQL URL fails closed instead
of silently falling back to something else.
"""

from dataclasses import dataclass
from pathlib import Path

from app.core.errors import ConfigError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_URL_ENV_VAR = "OGWA_DATABASE_URL"
DEFAULT_DATABASE_URL = "sqlite:///var/ogwa-local.sqlite3"
_SQLITE_PREFIX = "sqlite:///"
_POSTGRES_SCHEMES = ("postgresql", "postgres", "postgresql+psycopg", "postgresql+psycopg2", "postgresql+asyncpg")


@dataclass(frozen=True)
class DatabaseTarget:
    backend: str  # "sqlite"
    path: Path | None  # None for an in-memory database

    @property
    def in_memory(self) -> bool:
        return self.path is None

    @property
    def location(self) -> str:
        return ":memory:" if self.path is None else str(self.path)


def parse_database_url(raw: str | None) -> DatabaseTarget:
    text = (raw or "").strip() or DEFAULT_DATABASE_URL
    scheme = text.split(":", 1)[0].lower() if ":" in text else ""
    if scheme in _POSTGRES_SCHEMES:
        raise ConfigError(
            f"{DATABASE_URL_ENV_VAR}: PostgreSQL is the planned deployment target, but this build has no "
            "approved PostgreSQL driver (decision D5). Use a local sqlite:/// URL."
        )
    if not text.lower().startswith(_SQLITE_PREFIX):
        raise ConfigError(f"{DATABASE_URL_ENV_VAR} must be a sqlite:/// URL in this build")
    rest = text[len(_SQLITE_PREFIX):]
    if any(ch in rest for ch in "?#"):
        raise ConfigError(f"{DATABASE_URL_ENV_VAR} must not carry query parameters or a fragment")
    if "@" in rest:
        raise ConfigError(f"{DATABASE_URL_ENV_VAR} must not embed credentials")
    if rest == ":memory:":
        return DatabaseTarget(backend="sqlite", path=None)
    if not rest.strip():
        raise ConfigError(f"{DATABASE_URL_ENV_VAR} must name a database file")
    path = Path(rest)
    if not path.is_absolute() and not rest.startswith("/"):
        path = PROJECT_ROOT / path
    return DatabaseTarget(backend="sqlite", path=path.resolve())
