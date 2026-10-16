"""OGWA domain model: entities, evidence, identity mapping, approvals, and the lifecycle.

Everything in this package is pure: no I/O, no network, no clock reads. Callers pass
``now`` explicitly so every rule is deterministic and testable with synthetic data.
Nothing here can change an external system; see docs/security/safety-invariants.md.
"""
