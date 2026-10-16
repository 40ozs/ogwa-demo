"""Effective membership and access paths over a directory snapshot.

Groups nest (AD), and a person's effective membership of a group is direct membership of it
or of any group nested below it. Okta imports AD groups with their nested members
flattened, so an application assigned an AD group reaches everyone below it. Okta's
built-in ``Everyone`` group reaches every person with an active Okta account.

Pure and read-only: nothing here writes, and every result is computed from the inputs.
Nesting is required to be acyclic (the dataset checks this when it is built).
"""

from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property

EVERYONE_KIND = "BUILT_IN"
DIRECT = "DIRECT"


@dataclass(frozen=True)
class Route:
    """One way a person reaches an application: a direct assignment, or a chain of groups from
    the assigned group (first) down to a group the person is a direct member of (last)."""

    application: str
    chain: tuple[str, ...]  # empty for a direct assignment

    @property
    def direct(self) -> bool:
        return not self.chain


class DirectoryIndex:
    def __init__(self, *, group_kinds: dict[str, str], nesting: Iterable[tuple[str, str]],
                 memberships: Iterable[tuple[str, str]], active_people: Iterable[str], okta_people: Iterable[str],
                 assignments: Iterable[tuple[str, str | None, str | None, str | None]]) -> None:
        """``assignments``: present assignments only, as (application, group key or None, person or None, tier)."""
        self.group_kinds = dict(group_kinds)
        self.active = frozenset(active_people)
        self.okta_people = frozenset(okta_people) & self.active
        self._children: dict[str, list[str]] = {}
        self._parents: dict[str, list[str]] = {}
        for parent, child in sorted(nesting):
            self._children.setdefault(parent, []).append(child)
            self._parents.setdefault(child, []).append(parent)
        self._direct: dict[str, set[str]] = {}
        self._groups_of: dict[str, list[str]] = {}
        for group, person in sorted(memberships):
            self._direct.setdefault(group, set()).add(person)
            self._groups_of.setdefault(person, []).append(group)
        self.assignments = tuple(sorted(assignments, key=lambda a: (a[0], a[1] or "", a[2] or "", a[3] or "")))
        self._effective: dict[str, frozenset[str]] = {}
        self._depth: dict[str, int] = {}

    # --- structure ------------------------------------------------------------------------

    def children(self, key: str) -> list[str]:
        return list(self._children.get(key, ()))

    def parents(self, key: str) -> list[str]:
        return list(self._parents.get(key, ()))

    def direct_members(self, key: str) -> frozenset[str]:
        return frozenset(self._direct.get(key, ()))

    def direct_groups(self, person: str) -> list[str]:
        return list(self._groups_of.get(person, ()))

    def ancestors(self, key: str) -> list[str]:
        seen: list[str] = []
        stack = list(self.parents(key))
        while stack:
            g = stack.pop()
            if g not in seen:
                seen.append(g)
                stack += self.parents(g)
        return sorted(seen)

    def descendants(self, key: str) -> list[str]:
        seen: list[str] = []
        stack = list(self.children(key))
        while stack:
            g = stack.pop()
            if g not in seen:
                seen.append(g)
                stack += self.children(g)
        return sorted(seen)

    def depth(self, key: str) -> int:
        """Levels of nested groups below ``key`` (0: no nested groups)."""
        if key not in self._depth:
            kids = self.children(key)
            self._depth[key] = 0 if not kids else 1 + max(self.depth(c) for c in kids)
        return self._depth[key]

    # --- membership -------------------------------------------------------------------------

    def effective(self, key: str) -> frozenset[str]:
        """Active people who are members of ``key`` directly or through nested groups."""
        if key not in self._effective:
            if self.group_kinds.get(key) == EVERYONE_KIND:
                result = self.okta_people
            else:
                members = set(self._direct.get(key, ())) & self.active
                for child in self.children(key):
                    members |= self.effective(child)
                result = frozenset(members)
            self._effective[key] = result
        return self._effective[key]

    @cached_property
    def assigned_groups(self) -> dict[str, list[str]]:
        """Application -> groups assigned to it (present assignments)."""
        out: dict[str, list[str]] = {}
        for app, group, _, _ in self.assignments:
            if group is not None:
                out.setdefault(app, []).append(group)
        return out

    @cached_property
    def direct_users(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for app, _, person, _ in self.assignments:
            if person is not None:
                out.setdefault(app, set()).add(person)
        return out

    def users_of(self, app: str) -> frozenset[str]:
        people = set(self.direct_users.get(app, set())) & self.active
        for g in self.assigned_groups.get(app, ()):
            people |= self.effective(g)
        return frozenset(people)

    def route_counts(self, app: str) -> dict[str, int]:
        """Active person -> the most distinct assignments that reach them for one tier of ``app``.

        Two routes to different tiers (user and admin) are not redundant; two routes to the
        same tier are. A tierless assignment (Okta's Everyone) counts toward every tier."""
        per_tier: dict[tuple[str, str | None], int] = {}
        for a, group, person, tier in self.assignments:
            if a != app:
                continue
            reached = self.effective(group) if group is not None else frozenset({person}) & self.active
            for p in reached:
                per_tier[(p, tier)] = per_tier.get((p, tier), 0) + 1
        counts: dict[str, int] = {}
        for (p, tier), n in per_tier.items():
            if tier is not None:
                n += per_tier.get((p, None), 0)
            counts[p] = max(counts.get(p, 0), n)
        return counts

    # --- paths ------------------------------------------------------------------------------------

    def chains(self, group: str, person: str, limit: int = 20) -> list[tuple[str, ...]]:
        """Group chains from ``group`` down to a group that has ``person`` as a direct member."""
        out: list[tuple[str, ...]] = []

        def walk(node: str, chain: tuple[str, ...]) -> None:
            if len(out) >= limit:
                return
            chain = chain + (node,)
            if self.group_kinds.get(node) == EVERYONE_KIND:
                if person in self.okta_people:
                    out.append(chain)
                return
            if person in self._direct.get(node, ()):
                out.append(chain)
            for child in self.children(node):
                if person in self.effective(child):
                    walk(child, chain)

        if person in self.effective(group):
            walk(group, ())
        return out

    def routes(self, person: str) -> list[Route]:
        """Every way ``person`` reaches every application, in a stable order."""
        out: list[Route] = []
        for app, group, direct, _ in self.assignments:
            if direct is not None and direct == person and person in self.active:
                out.append(Route(app, ()))
            elif group is not None:
                out += [Route(app, chain) for chain in self.chains(group, person)]
        return sorted(out, key=lambda r: (r.application, r.chain))
