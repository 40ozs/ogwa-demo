"""OGWA operator API (P08). See docs/architecture/api.md and docs/security/authorization.md.

A WSGI application over the store, the lifecycle, the classifier, and the mapping-review
service. Standard library only (D4, D5). It serves only in ``LOCAL_SYNTHETIC`` with the
synthetic identity adapter (D50, D51). Read, review, approval, and execution operations are
separate permissions; execution is dry-run planning only, and ``PRODUCTION_MUTATION`` is
refused outright.
"""
