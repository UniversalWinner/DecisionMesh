"use strict";
// Clear capability/history before the first network request; never log the fragment.
const fragment = window.location.hash;
if (fragment) window.history.replaceState(null, "", window.location.pathname);
const bootStatus = document.getElementById("bootstrap-status");
if (fragment && bootStatus) {
  const params = new URLSearchParams(fragment.slice(1));
  const nonce = params.get("nonce");
  const reference = params.get("reference");
  if (nonce && /^[A-Za-z0-9_-]{43}$/.test(nonce) &&
      (!reference || /^[A-HJ-NP-Z2-9]{8}$/.test(reference))) {
    bootStatus.textContent = "Signing in to the local inbox…";
    fetch("/auth/exchange", {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({nonce, reference: reference || null})
    }).then(async response => {
      if (!response.ok) throw new Error("Sign-in unavailable");
      const result = await response.json();
      if (result.location !== "/inbox" && !/^\/records\/[A-HJ-NP-Z2-9]{8}$/.test(result.location)) {
        throw new Error("Invalid navigation");
      }
      window.location.replace(result.location);
    }).catch(() => {
      bootStatus.textContent = "This sign-in link is expired or unavailable. Run decision-mesh open again.";
    });
  } else bootStatus.textContent = "Invalid sign-in link. Run decision-mesh open again.";
}
document.querySelectorAll(".chat-reference").forEach(input => {
  input.addEventListener("focus", () => input.select());
});
document.querySelectorAll(".custom-snooze").forEach(form => {
  const input = form.querySelector("[name=until]");
  const hint = form.querySelector(".snooze-hint");
  input.addEventListener("input", () => {
    const until = Date.parse(input.value), aging = Date.parse(form.dataset.aging);
    hint.textContent = Number.isFinite(until) && Number.isFinite(aging) && until >= aging
      ? "Hide (no reminder): this time is at or after observation aging." : "";
  });
});
