// The runtime indicator: what GET /health says about the environment, in words.
//
// Only the demo runtime describes itself there (app/runtime/api.py). The standard runtime's
// /health answers {"status": "ok"} alone, so no indicator is shown. Pure functions only:
// main.js does the fetching and the DOM, tests/ui/runtime.test.mjs tests this module.

export const DEMO_LABEL = "DEMO ENVIRONMENT";
export const DEMO_SUBLABEL = "Synthetic data";
export const PUBLIC_SUBLABEL = "Public synthetic demo · no live integrations";

/** The demo indicator for a /health body, or null when this is not the demo runtime. */
export function demoIndicator(health) {
  if (!health || health.runtimeMode !== "demo") return null;
  const dataset = health.dataset || {};
  const organization = typeof health.organization === "string" && health.organization
    ? health.organization : "a fictional organization";
  const facts = [];
  if (dataset.primaryDomain) facts.push(`Domain ${dataset.primaryDomain}`);
  if (dataset.snapshotDate) facts.push(`snapshot ${dataset.snapshotDate}`);
  if (dataset.seed) facts.push(`seed ${dataset.seed}`);
  return {
    public: Boolean(health.publicDemo),
    label: DEMO_LABEL,
    sublabel: health.publicDemo ? PUBLIC_SUBLABEL : DEMO_SUBLABEL,
    detail: [
      `This environment uses deterministic synthetic data for ${organization}. No production Okta tenant is connected.`,
      "The OGWA application is real; the organization and its identities are fictional.",
      health.publicDemo ? "Anyone may explore it without signing in. It is read-only: nothing a visitor does is recorded." : "",
      facts.length ? `${facts.join(", ")}.` : "",
    ].filter(Boolean),
  };
}
