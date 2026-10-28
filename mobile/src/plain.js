// Turns the forensic engine's analyst wording into words a normal phone user understands.
// The original wording stays visible under "Technical evidence".
const RULES = [
  [/^RandomForest Phishing Classifier:\s*([\d.]+)%/i, m => [`AI model: ${Math.round(+m[1])}% likely phishing`,
    'A machine-learning model trained on real phishing links examined how this link is built.']],
  [/^High-Risk TLD:\s*(.+)/i, m => [`Scam-prone web address: ${m[1]}`,
    'Its ending (like .top or .xyz) is cheap to register and widely used for fake sites.']],
  [/^Credential Keywords/i, () => ['Login-bait words in the link',
    'Words like login, verify or update are added to make a fake link look official.']],
  [/^High Shannon Entropy/i, () => ['Jumbled, random-looking address',
    'Scam sites are often created in bulk with machine-generated names.']],
  [/^Unencrypted Transport/i, () => ['Not a secure (https) link',
    'Anything you type on this page can be read by others on the network.']],
  [/^Host IP Address/i, () => ['Link uses a raw number address',
    'Real companies use names, not bare IP numbers, for their websites.']],
  [/^VirusTotal Positives:\s*(\d+)/i, m => [`Flagged by ${m[1]} security vendors`,
    'Antivirus companies have already reported this link as malicious.']],
  [/^Domain Mismatch/i, () => ['Sender address looks faked',
    'The email claims one sender, but replies would go somewhere else.']],
  [/^SPF Authentication:\s*(FAIL|SOFTFAIL)/i, () => ['Email not sent by the real company',
    'The sending server is not authorised to send mail for this address (SPF failed).']],
  [/^SPF Authentication:\s*PASS/i, () => ['Sending server is authorised',
    'The email came from a server allowed to send for this address (SPF passed).']],
  [/^DKIM .*FAIL/i, () => ['Email may have been forged or altered',
    'Its digital signature does not check out (DKIM failed).']],
  [/^DKIM .*PASS/i, () => ['Email signature is valid',
    'Its digital signature checks out (DKIM passed).']],
  [/^High Urgency Coercion/i, () => ['Uses fear and urgency',
    'The wording rushes you so you act before thinking.']],
  [/^Risky Executable/i, () => ['Contains a dangerous attachment',
    'It carries or links to a program file that could take over your device.']],
  [/^Embedded HTML Credential Form/i, () => ['Has a login form inside the email',
    'Real companies never ask you to type your password inside an email.']],
  [/^Embedded URLs Discovered/i, () => ['Contains links',
    'Each link in the message was checked separately.']],
];

export function plainFinding(indicator, info) {
  for (const [re, fn] of RULES) {
    const m = String(indicator || '').match(re);
    if (m) { const [title, body] = fn(m); return { title, body }; }
  }
  return { title: indicator, body: info };
}
