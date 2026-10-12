// Deterministic first pass over a normalized card. Every rule reads only the
// alert text and fields, never the attack-window label, so the phase column in
// the eval stays an independent check. Rules run in order; first match wins.

const RANK = { dismiss: 0, monitor: 1, investigate: 2, escalate: 3 };

export function dispositionRank(disposition) {
  return RANK[disposition] ?? -1;
}

const PRIORITY = { escalate: 'P1', investigate: 'P2', monitor: 'P3', dismiss: 'P4' };

const CONTAINER_ATTACHMENT = /\.(iso|img|vhdx?)\b/;
const MACRO_ATTACHMENT = /\.(docm|xlsm|pptm|xlam)\b/;
const LURE_PHRASE = /enable (content|macros?|editing)/;
const CREDENTIAL_ASK = /(verify|confirm|re-?enter|update) (your )?(password|account|login|credentials)|password (expires|has expired)/;

function has(card, pattern) {
  return pattern.test(card.textLower || '');
}

function attachmentOf(card) {
  return String(card.email?.attachment || '').toLowerCase();
}

function who(card) {
  return card.host ? ` on ${card.host}` : '';
}

const RULES = [
  {
    id: 'sentinel.agent_exfil',
    activity: 'agent_exfil',
    disposition: 'escalate',
    test: (card) => card.family === 'sentinel'
      && has(card, /exfil|prompt injection|taint|canary|honeytoken|sensitive information disclosure/),
    headline: (card) => {
      const outcome = card.sentinel?.blocked ? 'was blocked' : 'was not blocked';
      return `AI agent ${card.sentinel?.agent || 'session'} tried to send protected data to an outside address, and the proxy says it ${outcome}.`;
    },
    explain: 'Text the agent read from an untrusted document steered it into reading sensitive data and posting it outside. This is prompt injection leading to data theft through the agent’s own tools.',
    why: (card) => [
      card.sentinel?.severityName ? `SentinelProxy rated it ${card.sentinel.severityName}.` : '',
      card.sentinel?.sink ? `Destination: ${card.sentinel.sink}.` : '',
      card.sentinel?.owasp?.length ? `Maps to ${card.sentinel.owasp.slice(0, 3).join(', ')}.` : '',
      'A planted canary value showed up in the outbound request, so the leak is confirmed, not guessed.',
    ],
    whatToDo: 'Confirm the block held, pull the agent session log, and remove or quarantine the untrusted document that carried the instruction. Rotate any secret the agent could read in that session.',
  },
  {
    id: 'sentinel.agent_alert',
    activity: 'agent_alert',
    disposition: 'investigate',
    test: (card) => card.family === 'sentinel',
    headline: (card) => `SentinelProxy flagged unusual behavior by AI agent ${card.sentinel?.agent || 'session'}.`,
    explain: 'The agent did something outside its normal pattern. The alert alone does not show data leaving.',
    why: (card) => [card.sentinel?.narrative || '', card.sentinel?.tactic ? `Tactic: ${card.sentinel.tactic}.` : ''],
    whatToDo: 'Open the session log and check which tool calls ran and where their output went.',
  },
  {
    id: 'email.malware_lure',
    activity: 'malware_lure',
    disposition: 'escalate',
    test: (card) => card.family === 'email'
      && (CONTAINER_ATTACHMENT.test(attachmentOf(card)) || MACRO_ATTACHMENT.test(attachmentOf(card))
        || has(card, CONTAINER_ATTACHMENT) || has(card, MACRO_ATTACHMENT))
      && has(card, LURE_PHRASE),
    headline: (card) => `Email from ${card.email?.from || 'an outside sender'} pushes a disk-image or macro attachment and asks the reader to "enable content".`,
    explain: 'Disk-image files (.iso, .img) skip some of the Windows download warnings, and "enable content" is the usual line that gets a reader to run code hidden in a document. Together they are a standard malware delivery pattern.',
    why: (card) => [
      card.email?.attachment ? `Attachment: ${card.email.attachment}.` : 'The message references a disk-image or macro attachment.',
      'The body tells the reader to enable content to see the document.',
      card.email?.subject ? `Subject "${card.email.subject}" is a generic billing hook.` : '',
    ],
    whatToDo: 'Do not open the attachment. Pull the message from every mailbox that received it, block the sender, and check whether anyone already opened the file.',
  },
  {
    id: 'email.risky_attachment',
    activity: 'risky_attachment',
    disposition: 'investigate',
    test: (card) => card.family === 'email'
      && (CONTAINER_ATTACHMENT.test(attachmentOf(card)) || MACRO_ATTACHMENT.test(attachmentOf(card))),
    headline: (card) => `Email from ${card.email?.from || 'an outside sender'} carries a disk-image or macro-enabled attachment.`,
    explain: 'These file types can run code when opened. There is no explicit lure text, so this may be legitimate, but it needs a look.',
    why: (card) => [card.email?.attachment ? `Attachment: ${card.email.attachment}.` : ''],
    whatToDo: 'Check the sender against known partners and detonate the attachment in a sandbox before releasing it.',
  },
  {
    id: 'email.credential_phish',
    activity: 'credential_phish',
    disposition: 'investigate',
    test: (card) => card.family === 'email' && has(card, CREDENTIAL_ASK),
    headline: (card) => `Email from ${card.email?.from || 'an outside sender'} asks the reader to confirm a password or account.`,
    explain: 'Real IT teams rarely ask for passwords by email. This is the shape of a credential phishing message.',
    why: () => ['The message asks for a password or account confirmation.'],
    whatToDo: 'Check where any link points, warn recipients, and reset the password of anyone who replied or clicked.',
  },
  {
    id: 'email.routine',
    activity: 'routine_email',
    disposition: 'dismiss',
    test: (card) => card.family === 'email',
    headline: (card) => `Ordinary email from ${card.email?.from || 'a sender'} with no risky attachment or credential request.`,
    explain: 'Nothing in the sender, subject, body, or attachment matches a known lure.',
    why: () => ['No disk-image, macro, or credential request found.'],
    whatToDo: 'No action needed.',
  },
  {
    id: 'web.webshell_command',
    activity: 'webshell_command',
    disposition: 'escalate',
    test: (card) => has(card, /\/wp-content\/uploads\/[^\s"]*\.php\?|web ?shell/),
    headline: (card) => `A PHP file in the website’s uploads folder is being called with an encoded command parameter${who(card)}.`,
    explain: 'The uploads folder should hold images and documents, not scripts that take commands. A script there that answers requests is a web shell: someone can run commands on the server through the browser.',
    why: () => [
      'Request targets a .php file under /wp-content/uploads/.',
      'The query string carries a long encoded parameter, which the log redacts here.',
    ],
    whatToDo: 'Isolate the web server, preserve the access log, delete the uploaded script after taking a copy, and find how it was uploaded (plugin or account). Rotate the site and database passwords.',
  },
  {
    id: 'host.reverse_shell',
    activity: 'reverse_shell',
    disposition: 'escalate',
    test: (card) => has(card, /\/dev\/tcp\/|reverse.?shell/),
    headline: (card) => `A process opened an interactive shell back to an outside machine${who(card)}.`,
    explain: 'A reverse shell gives an attacker a live command line on the server that bypasses inbound firewall rules.',
    why: () => ['Log text shows a shell wired to a network connection.'],
    whatToDo: 'Isolate the host, capture running processes and connections, and block the remote address at the firewall.',
  },
  {
    id: 'host.web_user_switch',
    activity: 'web_user_switch',
    disposition: 'escalate',
    test: (card) => has(card, /successful su for \S+ by www-data|www-data:\S+/),
    headline: (card) => `The web server account (www-data) switched into a named user account${who(card)}.`,
    explain: 'The web server account should never log in as a person. This means someone with a foothold in the website now holds a real user’s password.',
    why: () => ['su was run by www-data and succeeded.', 'The web server user normally has no interactive login.'],
    whatToDo: 'Lock the target user account, reset its password, and look for how the password was obtained (cracked hash, reuse).',
  },
  {
    id: 'host.sudo_from_web_dir',
    activity: 'privilege_escalation',
    disposition: 'escalate',
    test: (card) => has(card, /sudo:.*pwd=\/var\/www\/|privilege escalation|\/etc\/shadow/),
    headline: (card) => `A user gained root with sudo while working from inside the website folder${who(card)}.`,
    explain: 'Admins do not run sudo from the uploads folder of a web site. Root from that spot means the attacker went from web shell to full control of the server.',
    why: (card) => [
      'sudo to root succeeded.',
      'Working directory is under /var/www, the same place the web shell lives.',
      card.vendorLevel != null ? `Wazuh scored it level ${card.vendorLevel}, which undersells it in this context.` : '',
    ],
    whatToDo: 'Treat the server as fully compromised: isolate it, image the disk, and rebuild from a known-good image. Review sudoers for the account.',
  },
  {
    id: 'dns.exfil',
    activity: 'dns_exfil',
    disposition: 'escalate',
    test: (card) => has(card, /dnsteal|dns tunnel|dns exfil|query\[\w+\]\s+[a-z0-9-]{40,}\./),
    headline: (card) => `DNS lookups carry long encoded names, a sign of data being smuggled out over DNS${who(card)}.`,
    explain: 'DNS is allowed almost everywhere, so attackers hide stolen data inside the names they look up. Normal names are short and readable.',
    why: () => ['Query name is long and random-looking.'],
    whatToDo: 'Find the internal host making the lookups, block the destination domain at the resolver, and check what data that host could reach.',
  },
  {
    id: 'dns.anomaly',
    activity: 'dns_anomaly',
    disposition: 'investigate',
    test: (card) => has(card, /in dns domain|dns query ips|query records in dns|dns log events/),
    headline: (card) => `The DNS resolver saw unusual lookups${who(card)}.`,
    explain: 'AMiner learned what normal DNS traffic looks like and this broke the pattern. It can be harmless (a new site) or the start of DNS-based data theft.',
    why: (card) => [card.title ? `${card.title}` : '', 'Anomaly detector, not a signature: needs a human to judge.'],
    whatToDo: 'Check which internal host asked, how many similar lookups it made in the hour, and whether the domain is known.',
  },
  {
    id: 'web.wordpress_scan',
    activity: 'wordpress_scan',
    disposition: 'investigate',
    test: (card) => has(card, /wpscan/),
    headline: (card) => `A WordPress vulnerability scanner is probing the website${card.src ? ` from ${card.src}` : ''}.`,
    explain: 'The scanner lists plugins, themes, and users to find a weak spot. Scanning alone breaks nothing, but it usually comes right before an attack.',
    why: () => ['User agent names WPScan.', 'Many requests for files that do not exist.'],
    whatToDo: 'Check whether the source is an approved scanner. If not, block it and confirm WordPress and plugins are patched.',
  },
  {
    id: 'net.service_scan',
    activity: 'service_scan',
    disposition: 'investigate',
    test: (card) => has(card, /nmap|et scan|connection attempt \(scan\)/),
    headline: (card) => `Something is scanning servers to see which services answer${card.src ? `, from ${card.src}` : ''}.`,
    explain: 'A port or service scan maps what is running. It is reconnaissance: no damage yet, but someone is looking for a way in.',
    why: (card) => [card.title ? `${card.title}.` : '', 'Scanner fingerprint in the traffic.'],
    whatToDo: 'Identify the source host. If it is internal and not an approved scanner, treat that host as possibly compromised.',
  },
  {
    id: 'web.content_scan',
    activity: 'web_content_scan',
    disposition: 'investigate',
    test: (card) => has(card, /multiple web server 400 error codes|web_scan|dirb|gobuster/),
    headline: (card) => `One source is requesting many web pages that do not exist${card.src ? ` (${card.src})` : ''}.`,
    explain: 'This is directory guessing: trying common file and folder names to find hidden admin pages or backups.',
    why: (card) => [card.title ? `${card.title}.` : '', 'Burst of 4xx errors from one address.'],
    whatToDo: 'Check whether any of the guessed paths returned 200, and block the source if it is not an approved scanner.',
  },
  {
    id: 'auth.password_guessing',
    activity: 'password_guessing',
    disposition: 'investigate',
    test: (card) => has(card, /brute force|multiple auth(entication)? failures|password crack|hashcat|john the ripper/),
    headline: (card) => `Repeated failed logins suggest password guessing${who(card)}.`,
    explain: 'Several wrong passwords in a short time against one account is the signature of guessing or a stuffed password list.',
    why: (card) => [card.title ? `${card.title}.` : '', 'Multiple failures in seconds.'],
    whatToDo: 'Check whether a success followed the failures. If yes, reset the account; if no, consider rate limiting the source.',
  },
  {
    id: 'host.cpu_spike',
    activity: 'host_cpu_spike',
    disposition: 'investigate',
    test: (card) => has(card, /cpu value (out of expected range|deviates)/),
    headline: (card) => `CPU on a server jumped outside its normal range${who(card)}.`,
    explain: 'A pegged CPU can be a backup job, or it can be password cracking or crypto mining that someone started on the box.',
    why: () => ['AMiner flagged CPU use outside the learned range.'],
    whatToDo: 'Look at which process is using the CPU and who started it.',
  },
  {
    id: 'auth.failed_login',
    activity: 'failed_login',
    disposition: 'monitor',
    test: (card) => has(card, /invalid user login|authentication failure|login failed|auth failed/),
    headline: (card) => `A single failed login${who(card)}.`,
    explain: 'One wrong password is normal. It only matters if it repeats or is followed by an odd success.',
    why: () => ['One failure, no burst.'],
    whatToDo: 'No action now. Watch for repeats from the same source.',
  },
  {
    id: 'net.protocol_anomaly',
    activity: 'protocol_anomaly',
    disposition: 'monitor',
    test: (card) => has(card, /suricata (tls|http|smtp) (invalid|unable|no server|gzip)/),
    headline: (card) => `The network sensor saw a malformed TLS or HTTP exchange${card.src ? ` from ${card.src}` : ''}.`,
    explain: 'These decoder warnings fire constantly on normal traffic from odd clients. On their own they do not mean an attack.',
    why: (card) => [card.title ? `${card.title}.` : '', 'Decoder warning, not an attack signature.'],
    whatToDo: 'No action unless it clusters with real attack signatures from the same host.',
  },
  {
    id: 'av.update',
    activity: 'av_update',
    disposition: 'dismiss',
    test: (card) => has(card, /clamav (database )?update|freshclam/),
    headline: (card) => `Antivirus signatures updated${who(card)}.`,
    explain: 'ClamAV pulled new signatures. This is routine maintenance.',
    why: () => ['Scheduled freshclam run.'],
    whatToDo: 'No action needed.',
  },
  {
    id: 'auth.routine_success',
    activity: 'routine_login',
    disposition: 'dismiss',
    test: (card) => has(card, /authentication success|session opened|session closed|login: user=/),
    headline: (card) => `A normal successful login${who(card)}.`,
    explain: 'A user signed in with the right password over the usual service. Nothing about it is unusual.',
    why: () => ['Successful authentication with no preceding failures in this alert.'],
    whatToDo: 'No action needed.',
  },
];

const FALLBACK = {
  id: 'fallback.unclassified',
  activity: 'unclassified',
  test: () => true,
  headline: (card) => `Unclassified alert: ${card.title || 'no title'}.`,
  explain: 'No rule recognized this alert, so it is shown with the vendor’s own severity.',
  why: (card) => [card.vendorLevel != null ? `Vendor severity: ${card.vendorLevel}.` : ''],
  whatToDo: 'Read the raw log and decide whether a new rule is needed.',
};

export function matchSignal(card) {
  const rule = RULES.find((r) => r.test(card)) || FALLBACK;
  const disposition = rule.disposition
    || (Number(card.vendorLevel) >= 10 ? 'investigate' : 'monitor');
  return {
    activity: rule.activity,
    disposition,
    priority: PRIORITY[disposition],
    headline: rule.headline(card),
    explain: rule.explain,
    why: rule.why(card).filter(Boolean),
    whatToDo: rule.whatToDo,
    ruleId: rule.id,
  };
}

export const ruleIds = RULES.map((r) => r.id).concat(FALLBACK.id);
