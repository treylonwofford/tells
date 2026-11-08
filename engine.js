/*!
 * Tells — explainable scam message triage engine
 * Works in the browser (window.Tells) and in Node (module.exports).
 *
 * Design principles
 *  1. Score intent, not grammar. Nothing here looks at spelling or typos,
 *     so a perfectly written AI scam is judged the same as a sloppy one.
 *  2. Risk comes from combinations. Pressure language alone ("ASAP",
 *     "urgent") is everywhere in normal life. It only becomes risky when it
 *     is paired with an ASK: send money, share info, or click a link.
 *  3. Every point of score is traceable to a flag, and every flag shows the
 *     exact words that triggered it plus a plain-English reason.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Tells = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // kind: "ask"      = the message wants something from you
  //       "pressure" = the message is pushing you or building a pretext
  const SIGNALS = [
    {
      id: "credentials",
      label: "Asks for codes, passwords or personal info",
      kind: "ask",
      weight: 26,
      why: "Real banks, employers and delivery services don't ask you to confirm passwords, one-time codes, card numbers or your SSN over text or email.",
      patterns: [
        /\b(verify|confirm|validate|update|re-?activate)\s+(your\s+)?(account|identity|information|details|payment(\s+method)?|login|card)\b/gi,
        /\b(password|passcode|PIN|CVV|security\s+code|social\s+security(\s+number)?|SSN|date\s+of\s+birth|card\s+number|login\s+details|credentials)\b/gi,
        /\b(send|reply\s+with|read|tell|give)\s+(me\s+|us\s+)?(back\s+)?(the\s+|that\s+|your\s+)?(\d-digit\s+)?(code|verification\s+code|one[- ]time\s+code|OTP)\b/gi,
        /\b(verification|one[- ]time|OTP)\s+code\b/gi,
      ],
    },
    {
      id: "payment_redirect",
      label: "Redirects a payment to new account details",
      kind: "ask",
      weight: 28,
      why: "Changing where money should go — especially by email or text — is the core move of invoice and business email compromise fraud. Always confirm bank changes by calling a number you already have.",
      patterns: [
        /\b(our|the|my)\s+(bank(ing)?\s+(details|information|account)?|account\s+details|payment\s+details)\s+(has|have)\s+(changed|been\s+updated)\b/gi,
        /\b(bank|banking)\s+has\s+changed\b/gi,
        /\b(new|updated|different)\s+(bank(ing)?\s+)?(account|bank\s+details|payment\s+details|routing|wire\s+instructions)\b/gi,
        /\b(routing(\s+number)?|account\s*(no\.?|number|#)?|IBAN|SWIFT|sort\s+code)\s*[:#]?\s*\d{4,}/gi,
        /\b(wire|transfer|remit|send)\s+(the\s+)?(payment|funds|money|invoice|balance)\b/gi,
      ],
    },
    {
      id: "odd_payment",
      label: "Wants payment by gift card, crypto or cash app",
      kind: "ask",
      weight: 24,
      why: "Gift cards, crypto and peer-to-peer apps are nearly impossible to reverse. That's why scammers ask for them and legitimate businesses and agencies almost never do.",
      patterns: [
        /\b(gift\s*cards?|apple\s+cards?|google\s+play\s+cards?|itunes|steam\s+cards?|amazon\s+cards?)\b/gi,
        /\b(send|pay|deposit|transfer|buy)\b[^.]{0,40}\b(bitcoin|BTC|USDT|tether|crypto(currency)?|ethereum|ETH)\b/gi,
        /\b(wallet\s+address|crypto\s+ATM|bitcoin\s+ATM)\b/gi,
        /\b(zelle|cash\s*app|venmo|western\s+union|moneygram)\b/gi,
        /\bphotos?\s+of\s+the\s+(codes?|cards?|back)\b/gi,
      ],
    },
    {
      id: "link",
      label: "Pushes you to a suspicious link",
      kind: "ask",
      weight: 18,
      why: "The link is where the theft happens. Look-alike domains, link shorteners and odd endings like .top or .info are common in phishing. Go to the company's site yourself instead.",
      // Links are handled specially in analyze() so we can grade the domain.
      patterns: [],
    },
    {
      id: "urgency",
      label: "Creates urgency or a deadline",
      kind: "pressure",
      weight: 14,
      why: "A ticking clock is designed to stop you from pausing to check. On its own it's common, but paired with an ask it's a classic pressure tactic.",
      patterns: [
        /\b(urgent(ly)?|immediately|right\s+away|asap|act\s+now|final\s+notice|last\s+chance|expires?\s+(today|soon|tonight)|time[- ]sensitive|today\s+only|before\s+it'?s\s+too\s+late)\b/gi,
        /\bwithin\s+\d+\s*(hours?|hrs?|minutes?|mins?|days?)\b/gi,
        /\b(by\s+)?(end\s+of\s+(the\s+)?day|EOD|today)\b(?=[^.]*\b(pay|send|verify|confirm|update|process|wire|transfer|click)\b)/gi,
      ],
    },
    {
      id: "threat",
      label: "Threatens a consequence",
      kind: "pressure",
      weight: 14,
      why: "Fear of losing access, money or freedom (suspension, fines, arrest) is used to rush you into acting before you think.",
      patterns: [
        /\b(suspend(ed|sion)?|lock(ed)?|frozen|deactivat(ed|ion)|terminat(ed|ion)|closed|disabled|restricted)\b/gi,
        /\b(legal\s+action|arrest|warrant|lawsuit|penalt(y|ies)|fines?|late\s+fees?|collections)\b/gi,
        /\b(will\s+be\s+returned|returned\s+to\s+sender)\b/gi,
        /\b(failure\s+to|if\s+you\s+(do\s+not|don'?t))\s+\w+/gi,
      ],
    },
    {
      id: "impersonation",
      label: "Claims to be a trusted company or authority",
      kind: "pressure",
      weight: 12,
      why: "Scammers borrow the trust of banks, government agencies, delivery companies and your own executives. The name in a message proves nothing; verify through a channel you already know.",
      patterns: [
        /\b(IRS|social\s+security\s+administration|SSA|medicare|USPS|UPS|FedEx|DHL|amazon|paypal|apple\s+support|microsoft|netflix|chase|wells\s+fargo|bank\s+of\s+america|citi(bank)?|capital\s+one|toll\s+(services?|authority)|E-?ZPass|DMV)\b/gi,
        /\b(fraud\s+(prevention|department|team)|security\s+(team|department)|account\s+services|customer\s+support\s+team)\b/gi,
        /\b(dear\s+(customer|user|valued\s+(customer|member)|account\s+holder))\b/gi,
        /\b(CEO|CFO|COO|president|director|your\s+manager)\b/gi,
      ],
    },
    {
      id: "too_good",
      label: "Offers something too good to be true",
      kind: "pressure",
      weight: 14,
      why: "Prizes, refunds you didn't expect and guaranteed returns are bait. Nobody gives away money to strangers by text.",
      patterns: [
        /\b(you('ve|\s+have)\s+won|winner|prize|congratulations|selected|unclaimed|reward)\b/gi,
        /\b(guaranteed\s+(returns?|profits?|income)|risk[- ]free|double\s+your|passive\s+income|\d+%\s+(daily|weekly|returns?|profit))\b/gi,
        /\b(i|we)\s+made\s+\$?[\d,]+/gi,
        /\brefund\s+of\s+\$?[\d,]+/gi,
      ],
    },
    {
      id: "rapport",
      label: "Builds rapport with a stranger",
      kind: "pressure",
      weight: 16,
      why: "\"Wrong number\" openers and friendly strangers who bring up investing are how long-con romance and investment scams (often called pig butchering) begin. The ask comes weeks later.",
      patterns: [
        /\b(wrong\s+number|is\s+this\s+[A-Z][a-z]+\?|sorry,?\s+(i\s+)?(think\s+)?(i\s+)?(have|got)\s+the\s+wrong)\b/gi,
        /\b(you\s+seem\s+(nice|kind|sweet)|nice\s+to\s+meet\s+you|it'?s\s+fate|meant\s+to\s+be)\b/gi,
        /\b(my\s+(uncle|aunt|mentor|cousin|friend)\s+(taught|showed|introduced)\s+me)\b/gi,
        /\b(crypto(currency)?\s+(trading|investing|investment)|bitcoin\s+trading)\b/gi,
        /\b(trading\s+(strategy|platform|app|signals?)|investment\s+(platform|opportunity|app)|(i\s+)?can\s+(show|teach)\s+you)\b/gi,
      ],
    },
    {
      id: "secrecy",
      label: "Asks for secrecy or moves you off-channel",
      kind: "pressure",
      weight: 16,
      why: "Keeping it secret and moving to WhatsApp, Telegram or a personal number cuts you off from the people and systems that would catch the scam.",
      patterns: [
        /\b(keep\s+(this|it)\s+(between\s+us|quiet|confidential|private)|don'?t\s+tell|it'?s\s+a\s+surprise|confidential)\b/gi,
        /\b(whats\s*app|telegram|signal\s+app|text\s+me\s+(at|on)|my\s+personal\s+(number|email))\b/gi,
        /\b(i'?m\s+in\s+(a\s+)?meetings?|can'?t\s+talk|email\s+is\s+best|don'?t\s+call)\b/gi,
        /\b(are\s+you\s+(available|free|at\s+your\s+desk)\??)\b/gi,
      ],
    },
  ];

  // Language that real services use to PROTECT you. Used to reduce false
  // positives on genuine two-factor and security messages.
  const PROTECTIVE = [
    /\b(don'?t|do\s+not|never)\s+share\s+(this|the|your)\s+code\b/gi,
    /\bwe\s+(will\s+)?never\s+(call|text|email|ask)\b/gi,
    /\bif\s+you\s+didn'?t\s+request\s+this,?\s+(you\s+can\s+)?(ignore|disregard)\b/gi,
  ];

  const SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|rb\.gy|cutt\.ly|shorturl\.at|tiny\.cc)$/i;
  const RISKY_TLDS = /\.(top|xyz|info|click|link|live|shop|online|site|icu|cyou|buzz|rest|support|help|vip|cc|tk|ml|ga|cf|gq)$/i;
  const BRANDS = /(usps|ups|fedex|dhl|amazon|paypal|apple|icloud|microsoft|netflix|chase|wellsfargo|bankofamerica|citi|irs|ezpass|toll|coinbase|venmo|zelle)/i;
  const OFFICIAL = /(^|\.)(usps\.com|ups\.com|fedex\.com|dhl\.com|amazon\.com|paypal\.com|apple\.com|microsoft\.com|netflix\.com|chase\.com|wellsfargo\.com|bankofamerica\.com|citi\.com|irs\.gov|e-zpassny\.com|coinbase\.com|venmo\.com|zellepay\.com)$/i;
  const URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"')]+|(?:[a-z0-9-]+\.)+(?:com|net|org|gov|top|xyz|info|click|link|live|shop|online|site|icu|support|help|vip|cc|ly|co|io)(?:\/[^\s<>"')]*)?)/gi;

  const ARCHETYPES = [
    {
      id: "codetheft",
      name: "One-time code theft",
      test: (h, ctx) => ctx.asksForCodeBack && (h.impersonation || h.urgency || h.threat),
      floor: 85,
      story: "someone posing as a trusted company asks you to read back or send a security code. That code is the key to your account, and no real company will ever ask for it",
    },
    {
      id: "smish",
      name: "Delivery / toll text scam",
      test: (h, ctx) => h.link && ctx.brandLink && (h.urgency || h.threat),
      floor: 76,
      story: "it uses a fake delivery or toll problem with a deadline to get you onto a look-alike website",
    },
    {
      id: "pig",
      name: "Pig butchering opener (romance / investment long con)",
      test: (h, ctx) => h.rapport && ctx.counts.rapport >= 2 && (h.odd_payment || h.too_good || h.secrecy),
      floor: 66,
      story: "a stranger starts a friendly chat, brings up investing or crypto profits, and tries to move you to another app. There's no ask yet — that's the point. The money request comes after weeks of trust-building",
    },
    {
      id: "prize",
      name: "Prize / refund bait",
      test: (h) => h.too_good && (h.link || h.credentials || h.odd_payment),
      floor: 70,
      story: "it offers money or a prize you didn't expect and asks you to click, pay a fee or share details to claim it",
    },
    {
      id: "bec",
      name: "Invoice / payment redirect (business email compromise)",
      test: (h) => h.payment_redirect && (h.urgency || h.secrecy || h.impersonation),
      floor: 80,
      story: "it asks you to send a payment to new account details and uses pressure or an authority figure to keep you from double-checking",
    },
    {
      id: "giftcard",
      name: "Gift card / boss impersonation",
      test: (h) => h.odd_payment && (h.secrecy || h.impersonation || h.urgency),
      floor: 82,
      story: "it wants untraceable payment (gift cards, crypto or a cash app) and pairs it with secrecy or urgency",
    },
    {
      id: "phish",
      name: "Account phishing",
      test: (h) => (h.credentials || h.link) && (h.threat || h.urgency) && (h.impersonation || h.link),
      floor: 78,
      story: "it claims to come from a trusted company, warns of a problem with a deadline, and asks you to log in or confirm details",
    },
  ];

  function gradeDomain(raw) {
    let host = raw.replace(/^https?:\/\//i, "").replace(/^www\./i, "").split(/[\/?#:]/)[0].toLowerCase();
    const reasons = [];
    let bonus = 0;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { reasons.push("raw IP address instead of a name"); bonus += 10; }
    if (SHORTENERS.test(host)) { reasons.push("link shortener hides the real destination"); bonus += 8; }
    if (RISKY_TLDS.test(host)) { reasons.push(`unusual ending (.${host.split(".").pop()})`); bonus += 8; }
    const brandHit = BRANDS.test(host) && !OFFICIAL.test(host);
    if (brandHit) { reasons.push("uses a brand name but isn't the brand's real domain"); bonus += 12; }
    if (/[0-9]/.test(host.replace(/\.[a-z]+$/, "")) && BRANDS.test(host.replace(/0/g, "o").replace(/1/g, "l"))) {
      reasons.push("swaps letters for look-alike numbers"); bonus += 10;
    }
    if ((host.match(/-/g) || []).length >= 2) { reasons.push("long hyphenated domain"); bonus += 4; }
    const official = OFFICIAL.test(host);
    return { host, reasons, bonus: official ? 0 : bonus, official, brandHit };
  }

  function collect(text, re) {
    const out = [];
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      if (m[0].trim().length) out.push({ start: m.index, end: m.index + m[0].length, text: m[0] });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
    return out;
  }

  function analyze(input) {
    const text = String(input || "");
    const hits = {};          // id -> true
    const counts = {};        // id -> number of distinct matches
    const flags = [];
    const spans = [];
    const asksForCodeBack = /\b(send|reply|read|tell|give)\b[^.]{0,30}\bcode\b/i.test(text) && !/\bphotos?\s+of\s+the\s+codes?\b/i.test(text);
    const ctx = { counts, brandLink: false, links: [], asksForCodeBack };

    for (const s of SIGNALS) {
      let matches = [];
      if (s.id === "link") {
        for (const m of collect(text, URL_RE)) {
          const g = gradeDomain(m.text);
          ctx.links.push(g);
          if (g.official) continue;
          if (g.brandHit) ctx.brandLink = true;
          matches.push({ ...m, note: g.reasons.length ? g.reasons.join("; ") : "unverified link", bonus: g.bonus });
        }
      } else {
        for (const re of s.patterns) matches.push(...collect(text, re));
      }
      // de-duplicate overlapping matches within a signal
      matches.sort((a, b) => a.start - b.start || b.end - a.end);
      const uniq = [];
      for (const m of matches) {
        const last = uniq[uniq.length - 1];
        if (last && m.start < last.end) continue;
        uniq.push(m);
      }
      if (!uniq.length) continue;
      hits[s.id] = true;
      counts[s.id] = uniq.length;
      const extra = Math.min(8, (uniq.length - 1) * 3) + Math.max(0, ...uniq.map((m) => m.bonus || 0));
      const points = s.weight + extra;
      flags.push({
        id: s.id, label: s.label, kind: s.kind, why: s.why, points,
        evidence: uniq.map((m) => m.text.trim()),
        notes: uniq.map((m) => m.note).filter(Boolean),
      });
      for (const m of uniq) spans.push({ start: m.start, end: m.end, id: s.id });
    }

    const protective = PROTECTIVE.some((re) => collect(text, re).length > 0);
    const askFlags = flags.filter((f) => f.kind === "ask");
    const pressureFlags = flags.filter((f) => f.kind === "pressure");
    const hasAsk = askFlags.length > 0;

    let score = flags.reduce((a, f) => a + f.points, 0);
    const adjustments = [];

    // Combination bonus: an ask + pressure is the shape of almost every scam.
    if (hasAsk && pressureFlags.length) {
      const b = 8 + 4 * Math.min(3, pressureFlags.length - 1);
      score += b;
      adjustments.push({ type: "up", text: `Pairs a request with pressure (+${b}). That combination is the shape of most scams.` });
    }

    // Archetype detection (sets a floor so known patterns are never under-rated).
    const archetype = ARCHETYPES.find((a) => a.test(hits, ctx)) || null;
    if (archetype && score < archetype.floor) {
      adjustments.push({ type: "up", text: `Matches a known scam pattern, so the score is raised to at least ${archetype.floor}.` });
      score = archetype.floor;
    }

    // False-positive guard 1: no ask => cap.
    if (!hasAsk && !archetype && score > 30) {
      adjustments.push({ type: "down", text: "No request for money, information or clicks, so the score is capped at 30. Urgent or official-sounding language alone is normal in everyday messages." });
      score = 30;
    }

    // False-positive guard 2: protective security language, no link, no ask to reply with code.
    if (protective && !hits.link && !asksForCodeBack && !hits.payment_redirect && !hits.odd_payment) {
      adjustments.push({ type: "down", text: "Contains protective wording (\"don't share this code\") with no link and no request to send the code back, which is how genuine security texts look. Score capped at 15." });
      score = Math.min(score, 15);
    }

    score = Math.max(0, Math.min(99, Math.round(score)));
    const rating = score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 25 ? "Caution" : "Low";

    // Plain-English explanation
    let summary;
    if (archetype) {
      summary = `This matches the ${archetype.name.split(" (")[0].toLowerCase()} pattern: ${archetype.story}.`;
    } else if (!flags.length) {
      summary = "Nothing in this message matches common scam tactics. That's a good sign, but not a guarantee. If it asks you to do something unusual, verify with the sender through a channel you already trust.";
    } else if (score < 25) {
      summary = protective
        ? "This reads like a genuine security message. It tells you not to share the code and doesn't ask you to click anything or reply with information."
        : "There's some pressure language here, but no request for money, personal information or a click. On its own, that's ordinary everyday writing.";
    } else {
      const askTxt = askFlags.map((f) => f.label.toLowerCase()).join(" and ");
      const prTxt = pressureFlags.map((f) => f.label.toLowerCase()).join(", ");
      summary = hasAsk
        ? `This message ${askTxt}${prTxt ? ` while it also ${prTxt}` : ""}. Treat it as suspicious until you verify it another way.`
        : `This message ${prTxt}. There's no direct request yet, so stay alert if a follow-up asks for money or details.`;
    }

    const missing = [];
    if (!hits.link) missing.push("no link");
    if (!hits.credentials) missing.push("no request for codes or personal info");
    if (!hits.payment_redirect && !hits.odd_payment) missing.push("no payment request");

    const steps = nextSteps(rating, archetype, hits);

    return {
      score, rating, archetype: archetype ? archetype.name : null, summary,
      flags: flags.sort((a, b) => b.points - a.points),
      adjustments, spans, protective, missing, steps,
      grammarNote: "Spelling and grammar are ignored on purpose. AI-written scams are fluent, so this engine scores what a message wants from you, not how well it's written.",
    };
  }

  function nextSteps(rating, archetype, h) {
    if (rating === "Low") return [
      "No action needed if you were expecting this message.",
      "If something still feels off, contact the sender using a number or address you already have.",
    ];
    const s = ["Don't reply, click links or call numbers in the message."];
    if (h.payment_redirect) s.push("Call the vendor or colleague on a number you already have on file to confirm any bank change before paying.");
    if (h.odd_payment) s.push("Never pay anyone with gift cards or crypto because they asked by message. No legitimate employer or agency requires it.");
    if (h.credentials) s.push("Never share passwords, one-time codes or card numbers. If you already did, change your password and call your bank.");
    if (h.link) s.push("Type the company's real website into your browser yourself, or use its official app, to check your account.");
    if (archetype && archetype.id === "pig") s.push("Don't move the chat to another app, and be wary of any \"platform\" a new contact recommends.");
    s.push("Report it: forward scam texts to 7726 (SPAM), and report fraud at reportfraud.ftc.gov. For business payment fraud or crypto losses, also file at ic3.gov.");
    return s;
  }

  // Render the message with highlighted evidence. Returns safe HTML.
  function highlight(text, spans) {
    const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
    let out = "", pos = 0;
    for (const sp of sorted) {
      if (sp.start < pos) continue; // skip overlaps; first (longest) wins
      out += esc(text.slice(pos, sp.start));
      out += `<mark class="hl hl-${sp.id}" data-flag="${sp.id}">${esc(text.slice(sp.start, sp.end))}</mark>`;
      pos = sp.end;
    }
    return out + esc(text.slice(pos));
  }

  return { analyze, highlight, SIGNALS };
});
