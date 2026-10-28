"""Human-readable names for the ids the UI shows (OGWA-UI-IA-01): ``GET /identities``.

The stable identifier is the identity and the name is only its presentation:

    stable id -> the record it names -> its common name -> its canonical page

Every lookup goes by a stable id (or an AD objectSid) through the store's own digest-verifying
loaders and the directory snapshot. Nothing is ever looked up by name, so two objects that share
a name are never confused, and a renamed group still resolves: the store serves its latest
observation, with the new name, under the same id. Nothing here creates a mapping. An Okta
group's AD counterpart is reported only from an exact identity mapping, never from the
directory SID Okta reports (D37).

An id that resolves to nothing comes back ``resolved: false``, so the UI shows the raw id and
says it could not be resolved, rather than hiding it.
"""

import re
from typing import Any

from app.api.directory import SID_RE
from app.domain.model import ADGroup, OktaApplication, OktaGroup

ID_RE = re.compile(r"^[a-z]{2,6}_[0-9a-f]{32}$")
MAX_IDS = 50  # what fits the API's 2,048-character query limit

# The canonical detail page of each kind, as a UI route prefix.
ROUTE = {"AD_GROUP": "directory-groups", "DIRECTORY_GROUP": "directory-groups", "OKTA_GROUP": "groups",
         "OKTA_APPLICATION": "applications", "PERSON": "people", "CANDIDATE": "candidates"}


def unresolved(kind: str | None = None) -> dict[str, Any]:
    return {"kind": kind, "resolved": False}


class IdentityResolver:
    def __init__(self, api) -> None:
        self._store = api.store
        self._read = api.read
        self._directory = api.directory

    def resolve_many(self, refs: list[str]) -> dict[str, dict[str, Any]]:
        return {ref: self.resolve(ref) for ref in refs}

    def resolve(self, ref: str) -> dict[str, Any]:
        if SID_RE.match(ref):
            return self._snapshot_group(ref) or unresolved("AD_GROUP")
        prefix = ref.split("_", 1)[0]
        if prefix == "adg":
            return self._ad_group(ref)
        if prefix == "dgrp":
            return self._snapshot_group(ref) or unresolved("DIRECTORY_GROUP")
        if prefix == "ogrp":
            return self._okta_group(ref)
        if prefix == "oapp":
            app = self._store.latest(OktaApplication, ref)
            return self._entry("OKTA_APPLICATION", ref, app.label, app.okta_app_id) if app else unresolved(
                "OKTA_APPLICATION")
        if prefix == "psn":
            person = self._directory.person_ref_for(ref)
            if person is None:
                return unresolved("PERSON")
            return {**self._entry("PERSON", ref, person["displayName"], None), "status": person["status"]}
        if prefix == "cand":
            return self._candidate(ref)
        return unresolved()

    @staticmethod
    def _entry(kind: str, ref: str, name: str | None, qualifier: str | None, *, ambiguous: bool | None = None,
               route_id: str | None = None) -> dict[str, Any]:
        if not name:
            return unresolved(kind)
        return {"kind": kind, "resolved": True, "name": name, "qualifier": qualifier, "ambiguous": ambiguous,
                "route": ROUTE[kind], "routeId": route_id or ref}

    def _snapshot_group(self, ref: str) -> dict[str, Any] | None:
        """A group of the directory snapshot, by its directory id, AD evidence id, or objectSid."""
        g = self._directory.group_ref_for(ref)
        if g is None:
            return None
        kind = "AD_GROUP" if g["source"] == "AD" else "DIRECTORY_GROUP"
        return {**self._entry(kind, ref, g["name"], g["qualifier"], ambiguous=g["ambiguous"], route_id=g["id"]),
                "source": g["source"], "status": g["status"]}

    def _ad_group(self, ref: str) -> dict[str, Any]:
        found = self._snapshot_group(ref)
        if found is not None:
            return found
        ad = self._store.latest(ADGroup, ref)
        if ad is None or not ad.sam_account_name:
            return unresolved("AD_GROUP")
        # Without a directory snapshot there is no AD group page, and nothing to tell whether
        # the name is shared, so the qualifier is always shown (ambiguous unknown).
        entry = self._entry("AD_GROUP", ref, ad.sam_account_name, ad.distinguished_name or ad.object_guid)
        return {**entry, "route": None, "routeId": None, "source": "AD", "sid": ad.sid}

    def _okta_group(self, ref: str) -> dict[str, Any]:
        group = self._store.latest(OktaGroup, ref)
        if group is None:
            return unresolved("OKTA_GROUP")
        snapshot = self._directory.group_ref_for(ref)
        entry = self._entry("OKTA_GROUP", ref, group.name, group.okta_group_id,
                            ambiguous=snapshot["ambiguous"] if snapshot else None)
        mapping = self._read.mapping_for_group(ref)
        if mapping is not None and mapping.is_exact and mapping.ad_group_id:
            entry["mappedAdGroup"] = {"id": mapping.ad_group_id, **self._ad_group(mapping.ad_group_id)}
        return entry

    def _candidate(self, ref: str) -> dict[str, Any]:
        row = self._store.connection.execute("SELECT group_id FROM candidates WHERE id = ?", (ref,)).fetchone()
        if row is None:
            return unresolved("CANDIDATE")
        group = self._store.latest(OktaGroup, row["group_id"])
        return self._entry("CANDIDATE", ref, group.name if group else None, group.okta_group_id if group else None)
