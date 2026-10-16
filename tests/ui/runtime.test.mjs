// Unit tests for the runtime indicator (app/ui/static/js/runtime.js). Run by
// tests/test_ui_runtime.py, which writes the /health bodies the real demo and standard
// runtimes return (UI_RUNTIME_FIXTURES). Synthetic data only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { DEMO_LABEL, DEMO_SUBLABEL, demoIndicator, PUBLIC_SUBLABEL } from "../../app/ui/static/js/runtime.js";

const fixturePath = process.env.UI_RUNTIME_FIXTURES;
const fx = fixturePath ? JSON.parse(readFileSync(fixturePath, "utf8")) : null;
const withFixtures = { skip: fx ? false : "UI_RUNTIME_FIXTURES is not set (run tests/test_ui_runtime.py)" };

test("the demo runtime's /health shows DEMO ENVIRONMENT with its synthetic organization", withFixtures, () => {
  const indicator = demoIndicator(fx.demo);
  assert.equal(indicator.label, "DEMO ENVIRONMENT");
  assert.equal(indicator.sublabel, "Synthetic data");
  assert.match(indicator.detail[0], new RegExp(`synthetic data for ${fx.demo.organization.replace(/[()]/g, "\\$&")}`));
  assert.match(indicator.detail[0], /No production Okta tenant is connected\./);
  assert.match(indicator.detail[1], /application is real; the organization and its identities are fictional/);
  assert.match(indicator.detail[2], new RegExp(fx.demo.dataset.seed));
});

test("the standard runtime's /health shows no indicator", withFixtures, () => {
  assert.equal(demoIndicator(fx.production), null);
});

test("anything that is not the demo runtime shows no indicator", () => {
  for (const health of [null, undefined, {}, { status: "ok" }, { runtimeMode: "production" }, { runtimeMode: "DEMO" }]) {
    assert.equal(demoIndicator(health), null);
  }
});

test("the organization comes only from the server", () => {
  const indicator = demoIndicator({ runtimeMode: "demo", organization: "Example Org", dataset: {} });
  assert.match(indicator.detail[0], /synthetic data for Example Org\./);
  assert.equal(indicator.detail.length, 2);
  assert.equal(DEMO_LABEL, "DEMO ENVIRONMENT");
  assert.equal(DEMO_SUBLABEL, "Synthetic data");
  assert.match(demoIndicator({ runtimeMode: "demo" }).detail[0], /a fictional organization/);
});

test("the public demo says so: public, synthetic, no live integrations, no sign-in, nothing recorded", () => {
  const indicator = demoIndicator({ runtimeMode: "demo", organization: "Example Org", dataset: {}, publicDemo: true });
  assert.equal(indicator.public, true);
  assert.equal(indicator.label, "DEMO ENVIRONMENT");
  assert.equal(indicator.sublabel, PUBLIC_SUBLABEL);
  assert.equal(PUBLIC_SUBLABEL, "Public synthetic demo · no live integrations");
  assert.match(indicator.detail[2], /without signing in\. It is read-only: nothing a visitor does is recorded\./);
  assert.equal(demoIndicator({ runtimeMode: "demo", publicDemo: false }).public, false);
});
