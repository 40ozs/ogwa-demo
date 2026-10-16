import { signIn } from "../api.js";
import { banner, h, uid } from "../dom.js";
import { errorBox } from "./common.js";

export function signin(ctx, onSignedIn) {
  ctx.setTitle("Sign in");
  const id = uid("subject");
  const hint = uid("hint");
  const input = h("input", { type: "text", id, name: "subject", required: true, autocomplete: "off", spellcheck: "false",
    maxlength: "200", "aria-describedby": hint });
  const errors = h("div", { "aria-live": "assertive" });
  const submit = h("button", { type: "submit", class: "primary" }, "Sign in");
  const form = h("form", { class: "signin", novalidate: true },
    h("div", { class: "field" },
      h("label", { for: id }, "Synthetic subject"),
      h("span", { class: "hint", id: hint }, "A principal from config/synthetic-idp.json, for example synthetic.viewer.one. No password: this is synthetic sign-in for the local demo only."),
      input),
    errors,
    h("div", { class: "form-buttons" }, submit));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errors.replaceChildren();
    if (!input.value.trim()) {
      errors.append(h("div", { class: "banner", "data-tone": "blocked", role: "alert" }, h("strong", null, "Enter a synthetic subject.")));
      input.focus();
      return;
    }
    submit.disabled = true;
    try {
      await signIn(input.value.trim());
      onSignedIn();
    } catch (error) {
      submit.disabled = false;
      errors.append(errorBox(error));
      input.focus();
    }
  });
  ctx.view.append(
    banner("caution", "Synthetic sign-in — local demonstration only.",
      "This build signs in synthetic principals only, against a SYNTHETIC store. It holds no real identity and no credential."),
    form);
  return input;
}
