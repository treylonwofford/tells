// Run: node tests/run.js
const Tells = require("../engine.js");
const samples = require("../samples.js");

const extra = [
  { label: "Prize bait", expect: "Critical", text: "Congratulations! You've won a $1,000 Walmart gift card. Claim now at bit.ly/claim-prize-now before it expires today." },
  { label: "Scammer asks for code back", expect: "High+", text: "Hi, this is the Chase fraud department. We just sent you a verification code to secure your account. Please read me the code so we can stop the charge." },
  { label: "Normal invoice", expect: "Low/Caution", text: "Hi Sam, attached is invoice #2210 for October. Same payment details as always. Let me know if you have any questions. Thanks, Priya" },
  { label: "Plain chat", expect: "Low", text: "Want to grab lunch tomorrow? Thinking tacos around noon." },
  { label: "Official link", expect: "Low/Caution", text: "Your Amazon order has shipped. Track it at https://www.amazon.com/your-orders" },
  { label: "Toll smish", expect: "Critical", text: "E-ZPass: You have an unpaid toll balance of $6.99. Pay by end of day to avoid a $50 late fee: https://ezpass-tollservices.icu/pay" },
];

const ok = (expect, rating) => {
  if (expect === "High+") return rating === "High" || rating === "Critical";
  return expect.split("/").includes(rating);
};

let fail = 0;
for (const s of [...samples, ...extra]) {
  const r = Tells.analyze(s.text);
  const pass = ok(s.expect, r.rating);
  if (!pass) fail++;
  console.log(`${pass ? "PASS" : "FAIL"}  ${s.label.padEnd(26)} ${String(r.score).padStart(3)} ${r.rating.padEnd(8)} (want ${s.expect})  ${r.archetype || ""}`);
  if (!pass) console.log("      flags:", r.flags.map((f) => `${f.id}:${f.points}`).join(" "), "|", r.adjustments.map((a) => a.text.slice(0, 50)).join(" | "));
}
console.log(fail ? `\n${fail} failing` : "\nAll passing");
process.exit(fail ? 1 : 0);
