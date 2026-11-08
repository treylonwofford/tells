/* Sample messages. All fictional: names, numbers and domains are made up. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.TellsSamples = factory();
})(typeof self !== "undefined" ? self : this, function () {
  return [
    {
      id: "invoice", label: "Fake invoice", expect: "Critical",
      text: "Hi Dana, quick heads-up: our bank has changed, so please send payment for invoice #4471 ($18,450) to the new account below today.\n\nRouting: 021000089\nAccount: 7730021145\n\nI'm in meetings all afternoon so email is best.\nThanks,\nMark Ellison, CFO",
    },
    {
      id: "polished", label: "AI-polished phish", expect: "Critical",
      text: "Dear Customer,\n\nWe detected an unusual sign-in attempt on your account from a new device. To protect your funds, please confirm your identity within 24 hours using the secure link below. Failure to verify will result in a temporary suspension of online access.\n\nhttps://secure-account-review.info/verify\n\nThank you for banking with us.\nFraud Prevention Team",
    },
    {
      id: "delivery", label: "Delivery text", expect: "Critical",
      text: "USPS: Your package is on hold due to an incomplete address. Update within 12 hours or it will be returned to sender: https://usps-redeliver-help.top/track",
    },
    {
      id: "pig", label: "\"Wrong number\" opener", expect: "High",
      text: "Hi, is this Jessica? Sorry, I think I have the wrong number! You seem nice though 😊 I'm Lena, I work in finance in Seattle. My uncle taught me a crypto trading strategy and I made $8,200 last month. I can show you if you're curious. Easier to chat on WhatsApp.",
    },
    {
      id: "giftcard", label: "Boss gift cards", expect: "Critical",
      text: "Are you available? I need you to pick up 5 Apple gift cards ($200 each) for a client today. Keep this between us for now, it's a surprise. Send me photos of the codes when you have them. - Rob (CEO)",
    },
    {
      id: "real2fa", label: "Real 2FA code", expect: "Low",
      text: "Chase: Your verification code is 482913. Don't share this code with anyone. We will never call or text you asking for it.",
    },
    {
      id: "friend", label: "Urgent friend", expect: "Low",
      text: "Hey! Running late, the meeting got moved up. Can you grab the printed slides and head over ASAP? Thanks!!",
    },
  ];
});
