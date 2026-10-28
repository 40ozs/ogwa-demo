"""Static safety and accessibility properties of the UI's files (app/ui/static).

These are checks on the source text. The behaviour itself is covered by the JavaScript
unit tests (tests/test_ui_assess.py) and the opt-in browser tests (tests/browser).
"""

import colorsys
import re
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "app" / "ui" / "static"
JS_FILES = sorted((STATIC / "js").rglob("*.js"))
CSS = (STATIC / "css" / "ogwa.css").read_text(encoding="utf-8")
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")


def js(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def without_comments(text: str) -> str:
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", text, flags=re.S))


ALL_JS = {p.relative_to(STATIC).as_posix(): without_comments(js(p)) for p in JS_FILES}


class NoInjectionSinkTests(unittest.TestCase):
    SINKS = (r"\binnerHTML\b", r"\bouterHTML\b", r"\binsertAdjacentHTML\b", r"\bdocument\.write", r"\beval\s*\(",
             r"\bnew\s+Function\b", r"\bsetTimeout\s*\(\s*['\"`]", r"\bsetInterval\s*\(", r"\bDOMParser\b",
             r"createContextualFragment", r"\bsrcdoc\b", r"\.style\b", r"setAttribute\(\s*['\"]style",
             r"setAttribute\(\s*['\"]on", r"javascript:", r"\bimport\s*\(")

    def test_no_html_string_sinks_or_dynamic_code(self):
        for name, text in ALL_JS.items():
            for sink in self.SINKS:
                with self.subTest(file=name, sink=sink):
                    self.assertIsNone(re.search(sink, text))

    def test_nothing_is_stored_in_the_browser(self):
        for name, text in ALL_JS.items():
            for store in (r"\blocalStorage\b", r"\bsessionStorage\b", r"\bindexedDB\b", r"\bdocument\.cookie\b",
                          r"\bcaches\b", r"serviceWorker"):
                with self.subTest(file=name, store=store):
                    self.assertIsNone(re.search(store, text))

    def test_no_external_url_anywhere(self):
        for path in sorted(p for p in STATIC.rglob("*") if p.is_file()):
            text = path.read_text(encoding="utf-8")
            urls = [u for u in re.findall(r"(?:https?:)?//[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s\"')]*", text)
                    if u != "http://www.w3.org/2000/svg"]
            with self.subTest(file=path.name):
                self.assertEqual(urls, [])

    def test_only_the_api_module_talks_to_the_network(self):
        for name, text in ALL_JS.items():
            uses = re.search(r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon", text)
            with self.subTest(file=name):
                if name == "js/api.js":
                    self.assertIsNotNone(uses)
                    self.assertIn('const BASE = "/api/v1";', text)
                    self.assertIn('credentials: "same-origin"', text)
                else:
                    self.assertIsNone(uses)


class NoMutationSurfaceTests(unittest.TestCase):
    def test_the_ui_writes_to_exactly_six_paths(self):
        api = ALL_JS["js/api.js"]
        block = re.search(r"WRITE_PATHS = Object\.freeze\(\[(.*?)\]\)", api, re.S).group(1)
        # OGWA-DEMO-03 added the synthetic remediation drill, which records nothing: it changes
        # only an in-memory provider fixture the server discards (NON_PERSISTING in demo).
        self.assertEqual(re.findall(r'"([^"]+)"', block), [
            "/session", "/session/logout", "/candidates/{candidateId}/transitions",
            "/candidates/{candidateId}/approvals", "/candidates/{candidateId}/execution-jobs",
            "/candidates/{candidateId}/remediation-drills"])
        drill = re.search(r"export function runRemediationDrill\(candidateId, body\) \{(.*?)\n\}", api, re.S).group(1)
        self.assertNotIn("executionMode", drill.split("return", 1)[1], "the drill call adds no execution mode")
        self.assertNotIn("dryRun", drill.split("return", 1)[1], "the drill call adds no dry-run flag")
        self.assertEqual(len(re.findall(r'\brequest\("POST"', api)), 1, "POSTs go through post(), which checks WRITE_PATHS")

    def test_the_execute_route_and_production_mutation_are_unreachable(self):
        for name, text in ALL_JS.items():
            with self.subTest(file=name):
                self.assertNotIn("/execute", text)
                self.assertIsNone(re.search(r"dryRun:\s*false", text))
                self.assertIsNone(re.search(r"executionMode:\s*\"PRODUCTION_MUTATION\"", text))
                self.assertIsNone(re.search(r"EXECUTION_EXECUTE", text))
        api = ALL_JS["js/api.js"]
        self.assertIn('{ ...body, dryRun: true, executionMode: "DRY_RUN_MUTATION" }', api)

    def test_no_delete_unassign_or_execute_control(self):
        for name, text in ALL_JS.items():
            labels = re.findall(r"[\"'`](Delete|Unassign|Execute|Remove|Disable|Retire)\b", text)
            with self.subTest(file=name):
                self.assertEqual(labels, [])
        self.assertIsNone(re.search(r">\s*(Delete|Unassign|Execute|Remove|Retire)\b", INDEX))

    def test_lifecycle_targets_are_only_the_p09_actions(self):
        assess = ALL_JS["js/assess.js"]
        block = re.search(r"UI_TRANSITIONS = Object\.freeze\(\{(.*?)\}\)", assess, re.S).group(1)
        self.assertEqual(dict(re.findall(r"(\w+): \"(\w+)\"", block)), {
            "BLOCKED": "hold", "EXCLUDED": "exclude", "REJECTED": "reject", "REVALIDATION_REQUIRED": "revalidate",
            # P10B: revalidation after the post-quarantine hold, the deletion proposal, and the AD
            # stages' dry-run records. The legacy RETIREMENT_DRY_RUN is never offered (D148).
            "DELETION_REVALIDATION_REQUIRED": "revalidate", "DELETION_PROPOSED": "proposeDeletion",
            "OKTA_UNASSIGN_DRY_RUN": "recordDryRun", "QUARANTINE_DRY_RUN": "recordDryRun",
            "DELETION_DRY_RUN": "recordDryRun"})
        candidate = ALL_JS["js/views/candidate.js"]
        self.assertEqual(sorted(set(re.findall(r'^  (\w+): \{\n    label:', js(STATIC / "js" / "views" / "candidate.js"), re.M))),
                         ["exclude", "hold", "proposeDeletion", "reject", "revalidate"])
        self.assertIn("Approval alone does not mutate production.", candidate)

    def test_the_approval_limit_is_never_written_into_the_browser(self):
        # Owner decision after P09: the UI derives the limit from the server's policy field.
        for name, text in ALL_JS.items():
            with self.subTest(file=name):
                self.assertIsNone(re.search(r"\b(168|336|7 \* 24|14 \* 24)\b", text))
                self.assertNotIn("MAX_VALID_HOURS", text)
        self.assertIn("detail.policy.approvalMaxValidHours", ALL_JS["js/views/candidate.js"])

    def test_every_lifecycle_state_has_plain_words(self):
        from app.domain.lifecycle import LifecycleState

        block = re.search(r"STATE_INFO = Object\.freeze\(\{(.*?)\n\}\);", ALL_JS["js/assess.js"], re.S).group(1)
        self.assertEqual(set(re.findall(r"^  ([A-Z_]+): \{", block, re.M)), {s.value for s in LifecycleState})

    def test_no_reassuring_tone_exists(self):
        for name, text in ALL_JS.items():
            literals = set(re.findall(r"\"(success|ok|good|safe|green|pass|passed|clear|cleared)\"", text, re.I))
            with self.subTest(file=name):
                self.assertEqual(literals, set())
            for tone in re.findall(r'"data-tone":\s*"(\w+)"', text):
                self.assertIn(tone, {"blocked", "caution", "info", "neutral", "terminal"})


class ModuleGraphTests(unittest.TestCase):
    def test_every_import_resolves_to_an_exported_name(self):
        exports = {}
        for path in JS_FILES:
            text = without_comments(js(path))
            names = set(re.findall(r"export (?:async )?(?:function|const|class|let) (\w+)", text))
            exports[path.resolve()] = names
        for path in JS_FILES:
            text = without_comments(js(path))
            for clause, target in re.findall(r"import\s+(.+?)\s+from\s+\"(\.[^\"]+)\"", text, re.S):
                resolved = (path.parent / target).resolve()
                with self.subTest(file=path.name, target=target):
                    self.assertIn(resolved, exports, f"{target} does not exist")
                    if clause.startswith("*"):
                        continue
                    for name in re.findall(r"\w+", clause.strip("{} \n")):
                        self.assertIn(name, exports[resolved])


class MarkupAndStyleTests(unittest.TestCase):
    def test_index_has_landmarks_skip_link_and_no_inline_code(self):
        self.assertRegex(INDEX, r'<html lang="en">')
        self.assertIn('<meta name="viewport" content="width=device-width, initial-scale=1">', INDEX)
        self.assertIn('<a class="skip-link" href="#main">', INDEX)
        self.assertIn('<main id="main" tabindex="-1">', INDEX)
        self.assertIn('<nav id="primary-nav" aria-label="Primary"', INDEX)
        self.assertIn('role="status" aria-live="polite"', INDEX)
        self.assertRegex(INDEX, r"<title>[^<]+</title>")
        for script in re.findall(r"<script[^>]*>(.*?)</script>", INDEX, re.S):
            self.assertEqual(script.strip(), "", "no inline script")
        self.assertIsNone(re.search(r"\sstyle=|\son[a-z]+=|<style", INDEX))
        for ref in re.findall(r'(?:src|href)="(/ui/[^"]+)"', INDEX):
            self.assertTrue((STATIC / ref[len("/ui/"):]).is_file(), ref)

    def test_focus_is_always_visible(self):
        self.assertIn(":focus-visible {\n  outline: 3px solid var(--focus);", CSS)
        for rule in re.findall(r"([^{}]+)\{[^}]*outline:\s*(?:none|0)[^}]*\}", CSS):
            self.assertIn(rule.strip(), {"main:focus", "h1:focus"}, "outline removed only where :focus-visible restores it")
        self.assertIn("h1:focus-visible", CSS)

    def test_reduced_motion_and_forced_colors_are_honoured(self):
        block = re.search(r"@media \(prefers-reduced-motion: reduce\) \{(.*?)\n\}", CSS, re.S).group(1)
        self.assertIn("transition-duration: 0s !important", block)
        self.assertIn("animation-duration: 0s !important", block)
        self.assertIn("@media (forced-colors: active)", CSS)
        self.assertNotIn("@keyframes", CSS)

    def test_no_green_in_the_palette(self):
        for value in re.findall(r"#([0-9a-fA-F]{6})\b", CSS):
            r, g, b = (int(value[i:i + 2], 16) / 255 for i in (0, 2, 4))
            hue, lightness, saturation = colorsys.rgb_to_hls(r, g, b)
            with self.subTest(colour=value):
                self.assertFalse(70 / 360 <= hue <= 170 / 360 and saturation > 0.2,
                                 f"#{value} reads as green; no tone may look reassuring")
        rules = re.sub(r"/\*.*?\*/", "", CSS, flags=re.S)
        self.assertIsNone(re.search(r"\b(green|lime|seagreen|forestgreen|success)\b", rules, re.I))

    def test_text_contrast_meets_wcag_aa_in_both_schemes(self):
        light = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6});", CSS.split("@media (prefers-color-scheme: dark)")[0]))
        dark_block = re.search(r"@media \(prefers-color-scheme: dark\) \{\s*:root \{(.*?)\}", CSS, re.S).group(1)
        dark = {**light, **dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6});", dark_block))}

        def luminance(hex_colour):
            channels = [int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
            linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
            return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

        def ratio(a, b):
            la, lb = sorted((luminance(a), luminance(b)), reverse=True)
            return (la + 0.05) / (lb + 0.05)

        pairs = [("text", "bg"), ("text", "surface"), ("text", "surface-2"), ("muted", "surface"), ("muted", "bg"),
                 ("link", "surface"), ("link", "bg"), ("surface", "info-fg")]
        pairs += [(f"{tone}-fg", f"{tone}-bg") for tone in ("blocked", "caution", "info", "neutral", "terminal")]
        for scheme, palette in (("light", light), ("dark", dark)):
            for fg, bg in pairs:
                with self.subTest(scheme=scheme, fg=fg, bg=bg):
                    self.assertGreaterEqual(ratio(palette[fg], palette[bg]), 4.5)
            for tone in ("blocked", "caution", "info", "neutral"):  # borders and focus ring: non-text contrast
                with self.subTest(scheme=scheme, border=tone):
                    self.assertGreaterEqual(ratio(palette[f"{tone}-border"], palette["surface"]), 3.0)
            with self.subTest(scheme=scheme, focus=True):
                self.assertGreaterEqual(ratio(palette["focus"], palette["bg"]), 3.0)

    def test_layout_avoids_fixed_widths_that_overflow_phones(self):
        for width in re.findall(r"(?<![-\w])(?:min-)?width:\s*(\d+)px", CSS):
            self.assertLessEqual(int(width), 1, "no fixed pixel widths")
        self.assertIn("overflow-x: auto", CSS)


if __name__ == "__main__":
    unittest.main()
