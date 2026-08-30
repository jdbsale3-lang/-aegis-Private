// ZEUS/NHS BID PITCH DECK — ZEUSTA · 30 Aug 2026
import pptxgen from "/home/user/zeus-export/node_modules/pptxgenjs/dist/pptxgen.cjs.js";
const p = new pptxgen();
p.layout = "LAYOUT_16x9";
p.author = "ZEUSTRUSTAEGISSECURITY LTD";
p.title = "ZEUS NHS Digital Identity — Bid Pitch";

// ZEUSTA palette
const OBS = "10131B", PANEL = "1B2030", CYAN = "4FCEE4", CYDEEP = "2FA8C3",
      ACID = "D9F24B", WHITE = "FFFFFF", MUTED = "9AA0AC", NHS = "005EB8", OK = "3DD66E";
const titleFont = "Arial", bodyFont = "Arial";

function footer(slide, n) {
  slide.addText("ZEUSTA · ZEUS DOC · AEGIS — All IP belongs to JDB Sales", { x: 0.4, y: 5.32, w: 8, h: 0.3, fontSize: 8, color: MUTED });
  slide.addText(String(n), { x: 9.3, y: 5.32, w: 0.4, h: 0.3, fontSize: 8, color: MUTED, align: "right" });
}

// ── 1 Title ──
let s = p.addSlide();
s.background = { color: OBS };
s.addShape(p.ShapeType.rect, { x: 0, y: 0, w: 10, h: 0.12, fill: { color: CYAN } });
s.addShape(p.ShapeType.rect, { x: 0, y: 5.5, w: 10, h: 0.12, fill: { color: ACID } });
s.addText("NHS DIGITAL IDENTITY", { x: 0.6, y: 1.2, w: 8.8, h: 0.5, fontSize: 15, color: ACID, bold: true, charSpacing: 4 });
s.addText("ZEUS ID CARD SYSTEM", { x: 0.6, y: 1.75, w: 8.8, h: 1.1, fontSize: 40, color: WHITE, bold: true });
s.addText("One sovereign platform: ZEUS DOC threshold identity · AEGIS AI security · 50M-patient scale", { x: 0.6, y: 3.0, w: 8.4, h: 0.8, fontSize: 17, color: CYAN });
s.addText("Bid proposition for NHS England", { x: 0.6, y: 4.1, w: 6, h: 0.4, fontSize: 14, color: MUTED });
s.addText("ZEUSTRUSTAEGISSECURITY LTD · CH 17391549 · 66 Paul St, London EC2A 4NA", { x: 0.6, y: 4.6, w: 8.8, h: 0.4, fontSize: 11, color: MUTED });
footer(s, 1);

// ── 2 The two lessons we have learned ──
s = p.addSlide(); s.background = { color: OBS };
s.addText("LESSON 1 — THE ESTONIA PROOF", { x: 0.6, y: 0.5, w: 8.8, h: 0.5, fontSize: 20, color: CYAN, bold: true });
s.addText("• Estonia runs a national eID: physical PKI card + PINs, Mobile-ID/Smart-ID carriers", { x: 0.6, y: 1.15, w: 8.8, h: 0.4, fontSize: 14, color: WHITE });
s.addText("• Consequence: eID is used for identification, e-signing and secure data transfer by 1.3M citizens", { x: 0.6, y: 1.6, w: 8.8, h: 0.4, fontSize: 14, color: WHITE });
s.addText("LESSON 2 — THE SPLITKEY REFERENCE", { x: 0.6, y: 2.3, w: 8.8, h: 0.5, fontSize: 20, color: ACID, bold: true });
s.addText("• Threshold cryptography: the private key is SPLIT across the user's devices — never whole, anywhere", { x: 0.6, y: 2.95, w: 8.8, h: 0.4, fontSize: 14, color: WHITE });
s.addText("• Tokenless + passwordless + hardware-grade security in software (eIDAS/PSD2, EAL4+ reference)", { x: 0.6, y: 3.4, w: 8.8, h: 0.4, fontSize: 14, color: WHITE });
s.addShape(p.ShapeType.rect, { x: 0.6, y: 4.15, w: 8.8, h: 0.02, fill: { color: CYAN } });
s.addText("ZEUS delivers BOTH — plus an AI security layer and full UK sovereignty, built for NHS England", { x: 0.6, y: 4.4, w: 8.8, h: 0.5, fontSize: 16, color: ACID, bold: true });
footer(s, 2);

// ── 3 ZEUS DOC ──
s = p.addSlide(); s.background = { color: OBS };
s.addText("INTRODUCING ZEUS DOC", { x: 0.6, y: 0.45, w: 8.8, h: 0.5, fontSize: 22, color: CYAN, bold: true });
s.addText("Digital Operations & Certificates — our own tokenless, passwordless identity + signing software", { x: 0.6, y: 1.0, w: 8.8, h: 0.4, fontSize: 15, color: MUTED });
const feats = [
  ["Zero passwords", "No OTP, no tokens — challenge/response co-signature (5-min TTL, constant-time compare)"],
  ["Split-key security", "Shamir t-of-n: the master key never exists whole; losing a device changes nothing"],
  ["Non-repudiation", "Every consent record digitally signed and verified — legally strong signatures"],
  ["Audit ledger", "HMAC-verified, idempotent receipts — every authentication and signing event traceable"],
];
feats.forEach((f, i) => {
  const y = 1.6 + i * 0.85;
  s.addShape(p.ShapeType.roundRect, { x: 0.6, y, w: 8.8, h: 0.72, rectRadius: 0.08, fill: { color: PANEL }, line: { color: CYAN, width: 0.5 } });
  s.addText(f[0], { x: 0.85, y: y + 0.08, w: 3.2, h: 0.55, fontSize: 15, color: CYAN, bold: true });
  s.addText(f[1], { x: 4.2, y: y + 0.08, w: 5.0, h: 0.55, fontSize: 12.5, color: WHITE, valign: "middle" });
});
s.addShape(p.ShapeType.roundRect, { x: 0.6, y: 5.0, w: 8.8, h: 0.55, rectRadius: 0.08, fill: { color: ACID } });
s.addText("LIVE TODAY — production E2E passed: create identity · 2-of-3 authenticate · sign · verify · tamper rejected (apiaegissecurity.tech/zeusdoc)", { x: 0.7, y: 5.08, w: 8.6, h: 0.4, fontSize: 12.5, color: OBS, bold: true });
footer(s, 3);

// ── 4 NHS ID Card System ──
s = p.addSlide(); s.background = { color: OBS };
s.addText("THE NHS ID CARD SYSTEM — 50M SCALE", { x: 0.6, y: 0.45, w: 8.8, h: 0.5, fontSize: 22, color: CYAN, bold: true });
s.addText("Bureau-certified manufacture + ZEUS DOC software spine + AEGIS security — a single UK-sovereign programme", { x: 0.6, y: 1.0, w: 8.8, h: 0.4, fontSize: 14, color: MUTED });
const rows = [
  ["Smart cards", "50M NHS ID smart cards (bureau model: Certus / G+D / Thales / Entrust — RFIs sent)"],
  ["Digital identity", "ZEUS DOC tokenless identity on every patient's devices, passwordless"],
  ["Consent & audit", "Signed consent records, verify-able receipt ledger — compliance by design"],
  ["Security", "AEGIS AI platform: 8 modules, 37 endpoints, 24 layers — prompt-injection defense, watermarking"],
  ["Compliance", "DTAC · DSPT · UK GDPR · DPIA · NHS T&Cs IP clauses — drafted, ready"],
];
rows.forEach((r, i) => {
  const y = 1.55 + i * 0.76;
  s.addText(r[0], { x: 0.6, y, w: 2.9, h: 0.6, fontSize: 14, color: ACID, bold: true, valign: "middle" });
  s.addText(r[1], { x: 3.7, y, w: 5.7, h: 0.6, fontSize: 12.5, color: WHITE, valign: "middle" });
});
footer(s, 4);

// ── 5 Why ZEUS beats the reference ──
s = p.addSlide(); s.background = { color: OBS };
s.addText("WHY ZEUS — AND WHY NOT THE REFERENCE", { x: 0.6, y: 0.45, w: 8.8, h: 0.5, fontSize: 22, color: CYAN, bold: true });
const comp = [
  ["", "ZEUS", "SplitKey/Estonia"],
  ["UK sovereignty", "Yes — JDB Sales IP, UK holding co", "Foreign vendor"],
  ["AI threat layer", "AEGIS: 8 modules, injection defense", "None advertised"],
  ["NHS compliance", "DTAC / DSPT / UK GDPR / DPIA", "EU eIDAS"],
  ["Scale", "50M patients", "1.3M (EE) / enterprise"],
  ["Consent ledger", "Signed, idempotent receipts", "Generic signing logs"],
];
s.addTable(comp, { x: 0.6, y: 1.2, w: 8.8, colW: [2.2, 3.6, 3.0], border: { type: "solid", color: "2A3550", pt: 0.5 },
  fill: { color: PANEL }, fontSize: 12, color: WHITE, rowH: 0.6, valign: "middle" });
s.addText("Honest note: reference holds EAL4+ Common Criteria — ZEUS scopes this as a follow-on workstream while leading on AI security + NHS-native compliance.", { x: 0.6, y: 4.85, w: 8.8, h: 0.5, fontSize: 12, color: MUTED });
footer(s, 5);

// ── 6 Demo / live evidence ──
s = p.addSlide(); s.background = { color: OBS };
s.addText("LIVE EVIDENCE — NOT A SLIDE", { x: 0.6, y: 0.45, w: 8.8, h: 0.5, fontSize: 22, color: ACID, bold: true });
const ev = [
  ["AEGIS live", "8 modules · 37 endpoints · /nhs-compliance 200 · prompt-injection blocked (DAN 0.8)"],
  ["ZEUS DOC live", "apiaegissecurity.tech/zeusdoc — E2E passed: create → challenge → 2-of-3 auth → sign → verify"],
  ["Integrity", "113/113 tests · AIDE nightly tamper-detection · S3 + local backups"],
  ["Frontend", "NHS ID card UI (patient portal) ready — passwordless sign-in flow"],
];
ev.forEach((r, i) => {
  const y = 1.3 + i * 0.8;
  s.addShape(p.ShapeType.roundRect, { x: 0.6, y, w: 8.8, h: 0.66, rectRadius: 0.08, fill: { color: PANEL }, line: { color: OK, width: 0.5 } });
  s.addText("✔ " + r[0], { x: 0.85, y: y + 0.1, w: 2.6, h: 0.45, fontSize: 14, color: OK, bold: true });
  s.addText(r[1], { x: 3.6, y: y + 0.1, w: 5.6, h: 0.45, fontSize: 12, color: WHITE });
});
s.addText("Demo script on request — live calls, no canned screenshots.", { x: 0.6, y: 4.9, w: 8.8, h: 0.4, fontSize: 14, color: CYAN, bold: true });
footer(s, 6);

// ── 7 Commercial model — tiers ──
s = p.addSlide(); s.background = { color: OBS };
s.addText("COMMERCIAL MODEL — TIERS", { x: 0.6, y: 0.45, w: 8.8, h: 0.5, fontSize: 22, color: CYAN, bold: true });
s.addText("Anchored to the programme business case: £24.4B value · 28.2x ROI · 10yr NHS England. Indicative, negotiable.", { x: 0.6, y: 1.0, w: 8.8, h: 0.4, fontSize: 13, color: MUTED });
const tiers = [
  ["Pilot", "One ICB / trust region — ZEUS DOC + AEGIS + 100k cards", "£1.0M / yr", "Proof, live in 90 days"],
  ["Regional", "ICS cluster — identity + consent ledger + data adapter", "£8M / yr", "Scaled evidence"],
  ["National 50M", "NHS England full rollout — cards + ZEUS DOC + AEGIS + registries", "£86M / yr (10yr £865M)", "£24.4B · 28.2x ROI"],
  ["White-label", "Licence / export — other public sectors, international", "Bespoke", "Recurring licence"],
];
tiers.forEach((r, i) => {
  const y = 1.6 + i * 0.8;
  s.addShape(p.ShapeType.roundRect, { x: 0.6, y, w: 8.8, h: 0.68, rectRadius: 0.07, fill: { color: PANEL }, line: { color: CYAN, width: 0.5 } });
  s.addText(r[0], { x: 0.8, y: y + 0.1, w: 1.8, h: 0.45, fontSize: 13, color: ACID, bold: true });
  s.addText(r[1], { x: 2.6, y: y + 0.1, w: 3.4, h: 0.45, fontSize: 10.5, color: WHITE });
  s.addText(r[2], { x: 6.1, y: y + 0.1, w: 1.7, h: 0.45, fontSize: 11.5, color: CYAN, bold: true });
  s.addText(r[3], { x: 7.9, y: y + 0.1, w: 1.5, h: 0.45, fontSize: 10, color: MUTED });
});
s.addText("Break-even at each tier covered by efficiency gains: signatures, consent automation, fraud reduction.", { x: 0.6, y: 4.95, w: 8.8, h: 0.4, fontSize: 12.5, color: ACID, bold: true });
footer(s, 7);

// ── 8 Commercial & next steps ──
s = p.addSlide(); s.background = { color: OBS };
s.addText("COMMERCIAL & NEXT STEPS", { x: 0.6, y: 0.45, w: 8.8, h: 0.5, fontSize: 22, color: CYAN, bold: true });
const nxt = [
  ["IP & ownership", "All IP belongs to JDB Sales, licensed to ZEUSTA (holding co) — UK economic retention"],
  ["Model", "Certified-bureau manufacture + ZEUS DOC software + AEGIS security — single programme"],
  ["EAL4+ readiness", "Crypto core isolated → scoped Common Criteria workstream if procurement requires"],
  ["Pilot", "One trust/region pilot → 50M rollout roadmap"],
  ["Next milestone", "NHS England meeting Thu 1 Oct 16:00 — live demo ready"],
];
nxt.forEach((r, i) => {
  const y = 1.2 + i * 0.78;
  s.addText(r[0], { x: 0.6, y, w: 3.0, h: 0.6, fontSize: 14, color: ACID, bold: true });
  s.addText(r[1], { x: 3.8, y, w: 5.6, h: 0.6, fontSize: 12.5, color: WHITE });
});
s.addShape(p.ShapeType.rect, { x: 0, y: 5.5, w: 10, h: 0.12, fill: { color: ACID } });
footer(s, 8);

p.writeFile({ fileName: "/home/user/projects/zeus-doc/docs/NHS-Bid-Pitch-Deck-ZEUSTA.pptx" }).then(f => console.log("deck written:", f));