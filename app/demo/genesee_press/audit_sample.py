"""The sanitized reviewer audit sample of the Genesee Press demo, generated from the application itself.

``python -m app.demo.genesee_press.audit_sample --write`` (or ``--check``) seeds a fresh, in-memory
Genesee Press store, serves the real API over it in-process, and records what the API answers for
the two walkthrough scenarios (GP-C10, GP-C11), exactly as ``app.demo.null_meridian.audit_sample``
does for Null Meridian: same requests, same rules, same determinism.
"""

from pathlib import Path

from app.demo.genesee_press.world import edition
from app.demo.null_meridian import audit_sample as shared

DEFAULT_PATH = Path(__file__).resolve().parents[3] / "docs" / "demo" / "samples" / "genesee-press-audit-sample.json"
GENERATED_BY = ("python -m app.demo.genesee_press.audit_sample --write "
                "docs/demo/samples/genesee-press-audit-sample.json")
NOTES = (
    "Synthetic and sanitized: every identity, group, application, policy, approval, provider state, and audit event "
    "below belongs to the fictional company Genesee Press, the core of the shared synthetic world "
    "(synthetic-enterprise), as OGWA's vendored projection states it. 'geneseepress.example' is a reserved domain "
    "name; OGWA never resolves or contacts it.",
    *shared.NOTES[1:],
)


def build_audit_sample() -> dict:
    return shared.build_audit_sample(edition(), NOTES, GENERATED_BY)


def main(argv: list[str] | None = None) -> int:
    return shared.main(argv, default_path=DEFAULT_PATH, build=build_audit_sample)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["DEFAULT_PATH", "NOTES", "build_audit_sample", "main"]
