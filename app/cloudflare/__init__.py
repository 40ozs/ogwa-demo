"""Hosting the demo on Cloudflare: a Python Worker over D1 (docs/deployment/cloudflare-demo.md).

Infrastructure glue only. The Worker serves the real demo application
(``app.runtime.api.build_demo_application``) over an in-memory, read-only copy of the
validated demo store; D1 holds the canonical copy, written only by the operator bootstrap,
and the Worker answers only while D1 holds exactly the store it serves.

- ``identity``: what makes two copies of a demo store the same store, read by one SQL
  statement that runs unchanged on SQLite and on D1;
- ``export``: the demo store as SQL for D1, split into import phases that each stay under
  D1 Free's daily write quota;
- ``hosted``: the demo application as the Worker runs it, and the request adapter;
- ``python -m app.cloudflare``: build the Worker and its D1 import, and verify an export of
  the hosted D1 with the demo runtime's own validation.

Nothing here imports a Cloudflare module, so all of it is tested outside Cloudflare; the
Worker's entry module (``cloudflare/worker/src/entry.py``) is the only Cloudflare-specific code.
"""
