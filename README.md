# Tells: scam message triage

Paste a suspicious text, email or DM. Tells gives you a **risk rating**, the **red flags** it found (with the exact words that triggered each one), and a **plain-English explanation** of what the message is trying to get you to do.

Everything runs in the browser. No message ever leaves the page.

## Run it

Open `index.html` in a browser. That's it. No build step, no API keys.

- `index.html` + `engine.js` + `samples.js`: the app as separate files
- `tells-standalone.html`: the same app in one file, for dropping into a website or iframe
- `node tests/run.js`: runs the 13-message regression suite (scams and look-alike legit messages)

## How it decides

Every signal falls into one of two kinds:

| Kind | Signals |
|---|---|
| **Ask**: wants something from you | codes/passwords/personal info · payment to new account details · gift card/crypto/cash app payment · suspicious link (domain graded for look-alikes, shorteners, risky endings) |
| **Pressure**: pushes you or builds a pretext | urgency · threats · impersonation · too-good-to-be-true · rapport with a stranger · secrecy/channel shift |

Then three rules shape the score:

1. **Ask + pressure = risk.** Pairing a request with pressure adds a combination bonus, because that's the shape of almost every scam.
2. **Pressure alone is capped at 30.** "ASAP" and "urgent" show up in normal messages all the time.
3. **Known patterns get a floor.** Invoice redirects, gift card requests, one-time code theft, delivery/toll texts, prize bait and "wrong number" (pig butchering) openers are recognized as patterns, so they're never under-rated.

## Judgment calls

**False positives.** A real 2FA text says "verification code" and names a bank, the same words a phish uses. Tells looks for *protective* language ("don't share this code", "we will never call") with no link and no request to send the code back, and caps those at Low. A "running late, come ASAP" text from a friend scores Low because nothing is being asked for. Links to a brand's real domain aren't flagged. The test suite includes these look-alikes on purpose.

**Explain, don't just score.** A bare number teaches nothing and can't be challenged. Each point traces to a flag, each flag quotes its evidence and says why it matters, the message is highlighted in place (hover a flag to isolate its highlights), and score adjustments are shown, including when the score was capped *down*. An analyst can disagree with a specific flag, and a regular person learns the pattern for next time.

**AI-written scams.** "Look for typos" is outdated advice now that scams are written by language models. Tells ignores spelling and grammar entirely and scores *intent*: what the message asks for and how it applies pressure. The "AI-polished phish" sample is grammatically perfect and still scores 99.

**Scams with no ask yet.** Pig butchering openers ask for nothing on day one. That's the tactic. A rapport + investment + off-platform pattern sets a floor of High even with no link or payment request, and the explanation says why.

## Limits

This is a rules engine, so it's transparent and fast but can be evaded by phrasing it hasn't seen. A natural next step is a hybrid: keep these explainable rules as the evidence layer and add an LLM classifier that must cite the same kind of evidence, with disagreements between the two routed to a human. It's a triage aid, not a verdict.

All sample messages are fictional. Names, numbers and domains are made up.
