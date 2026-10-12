// Trusted mail domains for the synthetic Russell & Mitchell scenario.
// A team points this at their own domains; it is the only site-specific knob.
export const TRUSTED_EMAIL_DOMAINS = ['smith.russellmitchell.com'];

const RANK = { dismiss: 0, monitor: 1, investigate: 2, escalate: 3 };

export function dispositionRank(disposition) {
  return RANK[disposition] ?? -1;
}

function trustedDomain(domain) {
  if (!domain) return false;
  return TRUSTED_EMAIL_DOMAINS.some((item) => domain === item || domain.endsWith(`.${item}`));
}

// Attachments (and references to them in a pasted text blob) that can run code.
const RISKY_ATTACHMENT = /\.(iso|img|vhdx?|exe|scr|js|vbs|hta|docm|xlsm|pptm|xlam|lnk)\b/;
const LURE_PHRASE = /enable (content|macros?|editing)/;
// A rejected-return / "log back in" account lure. Checked before credential phish.
const ACCOUNT_LURE = /log\s*back\s*in|log in to your|sign in to your|edit my return|identity protection|ip pin|tax return (?:was )?rejected|credit karma/;

function emailFacts(card) {
  const email = card.email;
  if (!email) return null;
  const fromDomain = (email.from.match(/@([a-z0-9.-]+)/i) || [])[1]?.toLowerCase() || '';
  const urls = `${email.subject}\n${email.body}`.match(/https?:\/\/[^\s)]+/gi) || [];
  const linkHosts = urls.map((url) => {
    try { return new URL(url).hostname.toLowerCase(); } catch { return ''; }
  }).filter(Boolean);
  const mismatched = linkHosts.some((host) => fromDomain && host !== fromDomain && !host.endsWith(`.${fromDomain}`));
  const blob = card.textLower;
  const credential = /password|passcode|one-time code|sign in|verify your|credentials/.test(blob);
  const urgent = /immediately|action required|overdue|will be deleted|within \d+ hours|suspend|account (?:will be )?closed|expires? (?:today|soon)/.test(blob);
  const attachment = String(email.attachment || '').toLowerCase();
  // A risky attachment can appear in the attachment field or only in a pasted text blob.
  const riskyExt = RISKY_ATTACHMENT.test(attachment) || RISKY_ATTACHMENT.test(blob);
  const lure = LURE_PHRASE.test(blob);
  const accountLure = ACCOUNT_LURE.test(blob);
  return { fromDomain, linkHosts, mismatched, credential, urgent, riskyExt, lure, accountLure, trusted: trustedDomain(fromDomain) };
}

function hit(fields) {
  return {
    activity: fields.activity,
    disposition: fields.disposition,
    priority: fields.priority,
    headline: fields.headline,
    why: fields.why,
    whatToDo: fields.whatToDo,
    explain: fields.explain,
    ruleId: fields.ruleId,
    caught: fields.caught !== false,
  };
}

function hostOf(card) {
  return card.host || 'the host';
}

export function matchSignal(card) {
  const text = card.textLower;
  const mail = emailFacts(card);

  if (card.source === 'sentinel') {
    const s = card.sentinel || {};
    const high = (s.severity || 0) >= 70 || s.blocked;
    const agent = s.agent || 'an AI agent';
    const tool = s.tool || 'a tool';
    // Agent data theft vs. a plain behavior anomaly. A blocked send, a report-only
    // post-execution alert, a known sink, or exfil/injection wording all mean exfil.
    const exfil = s.blocked || s.reportOnly || Boolean(s.sink)
      || /exfil|prompt injection|inject|canary|honeytoken|sensitive|taint|planted secret|submit_to_index|data theft|outside destination|data.*outside/.test(text);

    if (!exfil) {
      return hit({
        ruleId: 'sentinel-agent-alert',
        activity: 'agent_alert',
        disposition: 'investigate',
        priority: 'P2',
        headline: `Tourniquet flagged unusual behavior by AI agent ${agent}.`,
        why: [
          s.narrative || 'The agent did something outside its normal pattern.',
          s.tactic ? `Tactic: ${s.tactic}.` : 'Tagged as an AI-agent detection.',
        ],
        whatToDo: 'Open the session log and check which tool calls ran and where their output went.',
        explain: 'The agent did something outside its normal pattern. The alert alone does not show data leaving. Open the session and confirm whether any tool call sent data outside before you treat this as benign.',
      });
    }

    const why = [
      s.narrative || 'The alert describes a tool call that left the agent session.',
      s.technique ? `Framework tag: ${s.technique} (${s.techniqueId}).` : 'Tagged as an AI-agent detection.',
      s.owasp?.length ? `OWASP: ${s.owasp.join('; ')}.` : 'Review the MITRE ATLAS technique on the alert.',
    ];
    if (s.reportOnly) {
      // Post-execution, report-only: nothing was stopped. Never tell the analyst the send was blocked.
      return hit({
        ruleId: 'sentinel-agent-report-only',
        activity: 'agent_exfil',
        disposition: high ? 'escalate' : 'investigate',
        priority: high ? 'P1' : 'P2',
        headline: `${agent} sent data toward an outside destination. The guardrail detected it after the tool already ran.`,
        why,
        whatToDo: 'Detected after the tool already ran; treat the data as sent. Rotate exposed secrets and canaries, check the destination for what arrived, and investigate the session that issued the call.',
        explain: `A hidden instruction steered ${agent} into calling ${tool}. The call carried data the agent had just read toward an outside destination. That is the agent version of data theft: untrusted text, private data, and a send button in the same turn. This alert is report-only: the proxy saw it after the tool already ran, so nothing was stopped. Treat the data as sent. This note describes the path; it does not repeat the payload.`,
      });
    }
    return hit({
      ruleId: 'sentinel-agent',
      activity: 'agent_exfil',
      disposition: high ? 'escalate' : 'investigate',
      priority: high ? 'P1' : 'P2',
      headline: `${agent} tried to send data outside the company, and the guardrail ${s.blocked ? 'blocked it' : 'flagged it'}.`,
      why,
      whatToDo: s.blocked
        ? 'Leave the block in place. Confirm the canary or sensitive fields never left the network, then rotate anything the agent was able to read.'
        : 'The guardrail flagged this call but did not block it. Check whether the canary or sensitive fields reached the destination, then rotate anything the agent was able to read.',
      explain: `A hidden instruction steered ${agent} into calling ${tool}. The call tried to carry data the agent had just read toward an outside destination. That is the agent version of data theft: untrusted text, private data, and a send button in the same turn. ${s.blocked ? 'The proxy stopped the send.' : 'The proxy flagged the call but did not block it.'} This note describes the path; it does not repeat the payload.`,
    });
  }

  // --- Email rules, most specific first. Any email that matches none is routine. ---
  if (mail && mail.riskyExt && mail.lure) {
    const file = card.email.attachment || 'the attachment';
    return hit({
      ruleId: 'malware-lure',
      activity: 'malware_lure',
      disposition: 'escalate',
      priority: 'P1',
      headline: `This email asks someone to open ${file}, which can run a program.`,
      why: [
        card.email.attachment ? `Attachment: ${card.email.attachment}.` : 'The message references a disk-image or macro attachment.',
        `Sender: ${card.email.from}.`,
        'Invoices and documents from a real vendor are usually a PDF or a link to a portal, not a disk image or a macro that asks you to enable content.',
      ],
      whatToDo: 'Do not open the attachment. Pull the message from every mailbox that received it, block the sender, and check whether anyone already opened the file.',
      explain: 'A disk image or a document that asks you to "enable content" can launch a program when it is opened. Paired with a lure, that is a standard way malware arrives, because the file looks like paperwork. Nothing here needs to be executed to understand the risk. Quarantine it and let the malware team detonate a copy in a sandbox if they need to know more.',
    });
  }

  if (mail && mail.riskyExt && !mail.lure) {
    return hit({
      ruleId: 'risky-attachment',
      activity: 'risky_attachment',
      disposition: 'investigate',
      priority: 'P2',
      headline: `This email carries ${card.email.attachment || 'a disk-image or macro attachment'}, a file type that can run code.`,
      why: [
        card.email.attachment ? `Attachment: ${card.email.attachment}.` : 'The message references a disk-image or macro attachment.',
        `Sender: ${card.email.from}.`,
        'There is no explicit lure wording, so this may be legitimate, but it needs a look.',
      ],
      whatToDo: 'Check the sender against known partners and detonate the attachment in a sandbox before releasing it.',
      explain: 'Disk-image and macro-enabled files can run code when opened. Without a lure phrase this may be a legitimate installer, but the file type alone is enough to hold it for a sandbox check.',
    });
  }

  if (mail && mail.accountLure) {
    return hit({
      ruleId: 'account-lure',
      activity: 'account_lure',
      disposition: 'escalate',
      priority: 'P1',
      headline: /tax return|ip pin|identity protection/.test(text)
        ? 'This email says a tax return was rejected and asks the reader to log back in and edit it.'
        : 'This email asks the reader to log back in from the message itself.',
      why: [
        'It creates urgency: a rejected return or a locked account that needs attention now.',
        'It tells the reader to log back in and use a button or link inside the message.',
        `Sender: ${card.email.from || 'unknown'}.`,
      ],
      whatToDo: 'Do not click Edit My Return or any login button in the message. Open the service from a bookmark or by typing the address, and check the account there. If the notice is not in the account, treat the email as phishing.',
      explain: 'A rejected-return notice with an Edit My Return button is a common way to steal a login. A genuine notice and a copy look the same in the inbox, so the safe move is to reach the account by a path you already trust, not the button in the mail.',
    });
  }

  if (mail && mail.credential && (mail.mismatched || !mail.trusted) && (mail.linkHosts.length || mail.urgent)) {
    return hit({
      ruleId: 'phishing-credential',
      activity: 'credential_phish',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'This email asks for a password or account confirmation and the sender is not on the company domain.',
      why: [
        `Sender domain: ${mail.fromDomain || 'unknown'}.`,
        mail.linkHosts.length ? `Link host: ${mail.linkHosts.join(', ')}.` : 'The message pressures the reader to act quickly.',
        mail.trusted ? 'The link does not match the sender domain.' : `Trusted domains are ${TRUSTED_EMAIL_DOMAINS.join(', ')}.`,
      ],
      whatToDo: 'Check where any link points and warn recipients. If anyone opened the link or entered a password, reset that account and check sign-in logs. Do not visit the link.',
      explain: 'The message creates a deadline and then asks for a password or account confirmation, often on a site the company does not own. That is credential phishing. The goal is the password itself. Reporting it and resetting any account that touched the link is the whole response.',
    });
  }

  if (mail && /\.(html?|svg)$/.test(String(card.email.attachment || '').toLowerCase())) {
    return hit({
      ruleId: 'html-attachment',
      activity: 'html_lure',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'This email attaches a web page. Opening it can send the reader to a fake login.',
      why: [
        `Attachment: ${card.email.attachment}.`,
        'HTML and SVG files can load a remote page as soon as they are opened.',
        `Sender: ${card.email.from}.`,
      ],
      whatToDo: 'Do not open the attachment. Quarantine the message and check whether anyone already did.',
      explain: 'A webpage attached to mail is a common stand-in for a link. The file itself is the lure. Quarantine it and let the mailbox team see who else received the same file.',
    });
  }

  if (mail && !mail.trusted && /gift cards?|wire transfer|bank details (?:have )?changed|updated payment details/.test(text)) {
    return hit({
      ruleId: 'payment-fraud',
      activity: 'payment_fraud',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'An outside sender is asking for a payment change or a gift card.',
      why: [
        `Sender domain: ${mail.fromDomain || 'unknown'}.`,
        'The message asks for money or a change of bank details.',
        'It does not come from a trusted company domain.',
      ],
      whatToDo: 'Do not pay or change any account. Confirm the request with the person by a channel you already use, not by replying to this message.',
      explain: 'Payment-change and gift-card requests are business email fraud. The safe check is a phone call or a known chat, not the address on this message.',
    });
  }

  if (mail && mail.linkHosts.some((host) => host.startsWith('xn--'))) {
    return hit({
      ruleId: 'lookalike-link',
      activity: 'lookalike_link',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'A link in this email uses an internationalized name that can look like a real domain.',
      why: [
        `Link host: ${mail.linkHosts.join(', ')}.`,
        'Names that start with xn-- are punycode. They can be drawn to resemble a company domain.',
      ],
      whatToDo: 'Do not open the link. Compare the host with the real site by typing the address yourself.',
      explain: 'The visible letters can match a brand while the actual host is different. Treat the link as untrusted until someone checks the host by hand.',
    });
  }

  // Any remaining email matched no threat rule: ordinary mail, dismiss.
  if (mail) {
    return hit({
      ruleId: 'benign-mail',
      activity: 'routine_email',
      disposition: 'dismiss',
      priority: 'P4',
      headline: `Ordinary email from ${card.email.from || 'a sender'} with no risky attachment or credential request.`,
      why: [
        card.email.subject ? `Subject: ${card.email.subject}.` : 'No subject.',
        'Nothing in the sender, subject, body, or attachment matches a known lure.',
        mail.trusted ? `Sender is on a trusted domain (${mail.fromDomain}).` : 'No disk-image, macro, credential, payment, or lookalike-link pattern found.',
      ],
      whatToDo: 'No action needed.',
      explain: 'Most mail is mail. The briefing stays quiet so the password lure and the disk-image invoice are the ones that stay on screen.',
    });
  }

  if (/\/wp-content\/uploads\/[^\s"]+\.php\b/.test(text) || /web ?shell/.test(text)) {
    return hit({
      ruleId: 'webshell-upload',
      activity: 'webshell_command',
      disposition: 'escalate',
      priority: 'P1',
      headline: 'Someone requested a PHP file inside the WordPress uploads folder.',
      why: [
        'Uploads are for images and documents. A PHP file there is a program the web server can run.',
        'The request parameter from the original alert is redacted in this sample.',
        `Source: ${card.src || 'see the log line'}.`,
      ],
      whatToDo: 'Treat the web host as compromised. Preserve the uploads directory, block the source address, and do not run the PHP file.',
      explain: 'A webshell is a small program an attacker has already placed on a site so they can talk to the server over ordinary web requests. The alert shows that conversation starting: a request for a PHP file in a folder that should only hold uploads. You do not need the hidden parameter to act. Isolate the host and let forensics collect the file.',
    });
  }

  if (/successful su for\s+\S+\s+by www-data/.test(text) || /www-data:\S+/.test(text)) {
    return hit({
      ruleId: 'su-www-data',
      activity: 'web_user_switch',
      disposition: 'escalate',
      priority: 'P1',
      headline: 'The web server account switched to a human user.',
      why: [
        'www-data is the account that serves the website. It should not become a person.',
        'The log records a successful switch, not a denied one.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'Treat the host as compromised. Disable the involved accounts, snapshot the machine, and look for the process that started as www-data.',
      explain: 'The website user opened a login as a named account. That means code running in the site got far enough to change identity. Read with the uploads-folder activity around the same minute, this is privilege escalation: the attacker is no longer stuck as the web server.',
    });
  }

  if ((/sudo to root/.test(text) && /wp-content|uploads/.test(text)) || /sudo:.*pwd=\/var\/www\//.test(text) || /privilege escalation|\/etc\/shadow/.test(text)) {
    return hit({
      ruleId: 'sudo-from-webroot',
      activity: 'privilege_escalation',
      disposition: 'escalate',
      priority: 'P1',
      headline: 'A user ran sudo as root from the WordPress uploads directory.',
      why: [
        'The working directory is the WordPress uploads folder, where a planted PHP file would live.',
        'The recorded command asks sudo which commands root will allow.',
        'Wazuh level is only 3, because a successful sudo is often normal. The directory makes this one different.',
      ],
      whatToDo: 'Treat the host as compromised. Disable the involved accounts, snapshot the machine, and look for the process that started as www-data.',
      explain: 'After landing in the uploads folder, the account asked what it is allowed to do as root. That is reconnaissance for a bigger step, not routine administration. The response is to contain the host, not to try the same command.',
    });
  }

  if (/\bwpscan\b/.test(text)) {
    return hit({
      ruleId: 'wpscan',
      activity: 'wordpress_scan',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'WPScan, a WordPress security scanner, requested pages on the intranet.',
      why: [
        'The browser string names WPScan and a version.',
        'A 404 on a random page is normal for this tool: it is probing for themes, plugins, and backups.',
        `Source: ${card.src || 'see the log'}. Target: ${hostOf(card)}.`,
      ],
      whatToDo: 'Confirm this source is not an approved scanner. If it is not, block it and check whether a later alert shows a file landing in uploads.',
      explain: 'WPScan looks for known weak plugins and forgotten files. By itself this line is reconnaissance, not a break-in. It matters because the labeled scenario moves from this scan to a file in the uploads folder.',
    });
  }

  if (/nmap scripting engine|possible nmap|\bnmap\b|et scan/.test(text)) {
    return hit({
      ruleId: 'nmap',
      activity: 'service_scan',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'Nmap probed a web host, and the server refused the request.',
      why: [
        'The client identified itself as the Nmap Scripting Engine.',
        card.vendorLevel != null ? `Vendor level is ${card.vendorLevel}. The user-agent is the useful part, not the level.` : 'Suricata marked the signature informational. The user-agent is still a scanner.',
        `Target: ${hostOf(card)}.`,
      ],
      whatToDo: 'If this address is not your vulnerability scanner, block it and watch for login attempts from the same place.',
      explain: 'Nmap is checking which services and pages exist. A 403 means the probe did not get in. The analyst action is to decide whether the scan was authorized.',
    });
  }

  if (/version\.bind/.test(text)) {
    return hit({
      ruleId: 'version-bind',
      activity: 'service_scan',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'A host asked the DNS server what software version it is running.',
      why: [
        'version.bind is a DNS query used to fingerprint a name server.',
        'AMiner flagged the query because that kind of lookup is rare here.',
        `Source: ${card.src || 'see the log'}.`,
      ],
      whatToDo: 'Check whether that source is an approved scanner. Version probes are usually the start of a scan, not an outage.',
      explain: 'The requester wants the DNS software version so they can match it to a known bug. Answering the question is not the compromise. Seeing the question from an unfamiliar address is.',
    });
  }

  if (/did not receive identification string|insecure connection attempt \(scan\)/.test(text)) {
    return hit({
      ruleId: 'ssh-scan',
      activity: 'service_scan',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'Something connected to SSH and left before identifying itself.',
      why: [
        'sshd logs this when a scanner opens the port and does not start a real login.',
        `Host: ${hostOf(card)}. Source: ${card.src || 'see the log'}.`,
        'The rule group is recon.',
      ],
      whatToDo: 'Block the source if it is not a known monitor, and see whether the same address shows up on web or DNS alerts in the same minute.',
      explain: 'This is a port scan touching SSH, not a stolen password. No login succeeded in this line.',
    });
  }

  if (/\/\.hta\b|\/\.htaccess\b|\/\.htpasswd\b|web_scan|multiple web server 400 error codes|\bdirb\b|gobuster/.test(text)) {
    return hit({
      ruleId: 'dir-bust',
      activity: 'web_content_scan',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'A script is guessing web paths, requesting many pages that do not exist.',
      why: [
        'A burst of 404/400 responses from one source is what directory brute-forcers produce.',
        'The client looks like a very old browser, which is a common default for that kind of tool.',
        `Source: ${card.src || 'see the log'}.`,
      ],
      whatToDo: 'Rate-limit or block the source. Confirm any guessed path still returns 404 or 403.',
      explain: 'The tool is reading the site like a word list, hoping a backup or a private folder is exposed. The 404s in this sample mean the server said no. Keep it that way.',
    });
  }

  if (/service_stop|unit=put|type=service_stop/.test(text)) {
    return hit({
      ruleId: 'service-stop',
      activity: 'service_stop',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'systemd stopped a unit named "put" on this host.',
      why: [
        'The audit event is a successful service stop, not a crash loop.',
        'The unit name is short and unusual. It deserves a human look during the labeled service-stop window.',
        'AMiner had not seen this combination of fields before.',
      ],
      whatToDo: 'Ask whether anyone planned to stop that service. If it is a security or logging service, start it again and find out who changed it.',
      explain: 'Stopping a service can be maintenance, or it can be an attacker switching off something that would record them. The name "put" is not a standard system service in this scenario, so the safe assumption is to verify it with the owner of the host.',
    });
  }

  if (/multiple authentication failures|brute force|password crack|hashcat|john the ripper/.test(text)) {
    return hit({
      ruleId: 'password-guessing',
      activity: 'password_guessing',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'Many failed logins arrived together. That is password guessing, not a typo.',
      why: [
        'The log describes a burst of failures, or names a password-cracking tool.',
        'One mistyped password is a different rule. This one is the repeated kind.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'See whether a success followed the failures. If it did, reset that account. If it did not, block or rate-limit the source.',
      explain: 'A person mistypes once. A guessing run fails many times, quickly, often against more than one account. Check for a success right after the burst before you close it.',
    });
  }

  if (/\/dev\/tcp\/|reverse.?shell/.test(text)) {
    return hit({
      ruleId: 'reverse-shell',
      activity: 'reverse_shell',
      disposition: 'escalate',
      priority: 'P1',
      headline: 'A process on this host opened a shell back to another machine.',
      why: [
        'The log shows a shell tied to a network connection.',
        'That gives someone outside a live command line on the host.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'Isolate the host, record the running processes and connections, and block the remote address.',
      explain: 'A reverse shell is a live command line that calls out, so an inbound firewall does not stop it. Contain the host. Do not re-run the command that showed up in the log.',
    });
  }

  if (/cobalt strike|meterpreter|c2 beacon|beacon activity/.test(text)) {
    return hit({
      ruleId: 'malware-beacon',
      activity: 'malware_beacon',
      disposition: 'escalate',
      priority: 'P1',
      headline: 'The network sensor named a remote-access beacon on this host.',
      why: [
        'The signature names a known remote-control tool, not a generic scan.',
        'A beacon means the host may already be taking instructions from outside.',
        `Source: ${card.src || 'see the log'}.`,
      ],
      whatToDo: 'Isolate the host and preserve memory if the team can. Block the remote address. Do not interact with the beacon.',
      explain: 'A beacon is a program that calls home so someone else can steer the machine. The sensor already named it. The response is containment, not a closer look at the payload.',
    });
  }

  if (/\bunion select\b|sql injection\b|<script\b|path traversal|\.\.\/|\.\.\\/.test(text)) {
    return hit({
      ruleId: 'web-attack',
      activity: 'web_attack',
      disposition: 'escalate',
      priority: 'P1',
      headline: 'A web request tried to make the server do something a normal page view does not.',
      why: [
        'The log matches a database probe, a script tag, or a path that walks out of the web folder.',
        'That is an attack against the site, not a broken link.',
        `Source: ${card.src || 'see the log'}. Target: ${hostOf(card)}.`,
      ],
      whatToDo: 'Block the source, check whether the request got a normal success response, and have the site owner confirm the input was rejected.',
      explain: 'The request is trying to read data or files the page should not return. You do not need to replay it. Check the response code and contain the source address.',
    });
  }

  if (/dnsteal|dns tunnel|dns exfil|query\[\w+\]\s+[a-z0-9-]{40,}\./.test(text)) {
    return hit({
      ruleId: 'dns-exfil',
      activity: 'dns_exfil',
      disposition: 'escalate',
      priority: 'P1',
      headline: 'DNS lookups on this host look like data being smuggled out in the names.',
      why: [
        'The log names a DNS tunnel or DNS exfiltration tool, or a very long encoded lookup name.',
        'DNS is allowed on most networks, so stolen data is sometimes hidden in lookup names.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'Find the internal host making the lookups, block the destination name at the resolver, and see what data that host could read.',
      explain: 'Normal DNS names are short and readable. A tunnel uses the lookup itself to carry data out. Block the destination and find the process that asked.',
    });
  }

  if (/high entropy in dns|entropydetector|value entropy anomaly|in dns domain|dns query ips|query records in dns|dns log events/.test(text)) {
    return hit({
      ruleId: 'dns-anomaly',
      activity: 'dns_anomaly',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'The DNS resolver saw unusual lookups on this host.',
      why: [
        card.title ? `${card.title}.` : 'AMiner flagged the DNS traffic as outside its learned pattern.',
        'This is an anomaly detector, not a signature: it needs a human to judge.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'Check which internal host asked, how many similar lookups it made in the hour, and whether the domain is known.',
      explain: 'AMiner learned what normal DNS traffic looks like and this broke the pattern. It can be harmless (a new site) or the start of DNS-based data theft, so a person decides.',
    });
  }

  if (/encodedcommand|-enc\s+[a-z0-9+/=]{16,}/.test(text)) {
    return hit({
      ruleId: 'encoded-command',
      activity: 'encoded_command',
      disposition: 'escalate',
      priority: 'P1',
      headline: 'A command on this host was hidden inside an encoded blob.',
      why: [
        'The log shows a command launcher with an encoded argument.',
        'Administrators rarely hide routine commands this way.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'Isolate the host and identify the parent process. Do not decode and run the blob on a workstation.',
      explain: 'Encoding is how a launcher hides the real command from a quick reading of the log. Treat the host as suspect. Leave decoding to a malware sandbox, not to the analyst machine.',
    });
  }

  if (/useradd |new user |account created|net user \S+ \/add/.test(text)) {
    return hit({
      ruleId: 'new-account',
      activity: 'new_account',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'A new local account appeared.',
      why: [
        'The log records an account being created.',
        'An unplanned account is a common way to keep access after the first break-in.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'Ask the host owner whether they created it. If they did not, disable the account and look at what created it.',
      explain: 'A new account is not proof of an attack, and it is also how an attacker stays on a machine. Confirm it with the owner before you close the alert.',
    });
  }

  if (/crontab|schtasks|scheduled task/.test(text)) {
    return hit({
      ruleId: 'persistence',
      activity: 'persistence',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'Something added or changed a scheduled task.',
      why: [
        'Scheduled tasks run again after a reboot, which is how a foothold survives cleanup.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'Compare the task with the host’s change record. If nobody planned it, disable the task and see which user created it.',
      explain: 'A scheduled task is ordinary for backups and updates. An unexpected one is a way for a program to start itself later. Verify the owner, then disable it if the owner does not recognize it.',
    });
  }

  if (/cpu value (?:out of expected range|deviates)|valuerangedetector/.test(text)) {
    return hit({
      ruleId: 'cpu-spike',
      activity: 'host_cpu_spike',
      disposition: 'investigate',
      priority: 'P2',
      headline: `CPU on ${hostOf(card)} jumped outside its normal range.`,
      why: [
        'AMiner flagged CPU use outside the range it learned for this host.',
        'A pegged CPU can be a backup job, or it can be password cracking or crypto mining.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'Look at which process is using the CPU and who started it.',
      explain: 'A CPU that runs far outside its learned range is sometimes a scheduled job and sometimes cracking or mining that someone started on the box. The anomaly alone does not say which, so a person checks the running processes.',
    });
  }

  if (/invalid user login|authentication failure|login failed|auth failed/.test(text)) {
    return hit({
      ruleId: 'auth-failure',
      activity: 'failed_login',
      disposition: 'monitor',
      priority: 'P3',
      headline: 'One login failed. That happens to real users, so this stays a watch item.',
      why: [
        'The log shows a single authentication failure, not a burst.',
        'A burst from one address, or the same failure inside a labeled cracking window, would be a different decision.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'No page. If several of these arrive for the same account in a few minutes, escalate that group.',
      explain: 'People mistype passwords. One failure is noise. Password cracking is the same message repeated, fast, often against many accounts. This sample is the single-failure kind.',
    });
  }

  if (/suricata (?:tls|http|smtp) (?:invalid|unable|no server|gzip)|invalid handshake|generic protocol command decode/.test(text)) {
    return hit({
      ruleId: 'protocol-anomaly',
      activity: 'protocol_anomaly',
      disposition: 'monitor',
      priority: 'P3',
      headline: `The network sensor saw a malformed TLS or HTTP exchange${card.src ? ` from ${card.src}` : ''}.`,
      why: [
        card.title ? `${card.title}.` : 'A protocol decoder warning, not an attack signature.',
        'These decoder warnings fire constantly on normal traffic from odd clients.',
        `Source: ${card.src || 'see the log'}.`,
      ],
      whatToDo: 'No action unless it clusters with real attack signatures from the same host.',
      explain: 'A malformed handshake on its own is usually an old client or a flaky connection, not an attack. It only matters when it arrives alongside real attack signatures from the same source.',
    });
  }

  if (/clamav (?:database )?update|freshclam/.test(text)) {
    return hit({
      ruleId: 'clamav-update',
      activity: 'av_update',
      disposition: 'dismiss',
      priority: 'P4',
      headline: 'ClamAV is updating its virus definitions. This is scheduled maintenance.',
      why: [
        'The log says the update process started. It does not say a file was infected.',
        'The rule group includes the word "virus" because that is the product family, not a verdict.',
        `Vendor level ${card.vendorLevel ?? 3} is informational.`,
      ],
      whatToDo: 'No action.',
      explain: 'Antivirus tools phone home for new signatures. That line looks scary in a queue because of the word virus, and it is the most common false alarm in this data set. Nothing was detected.',
    });
  }

  if (/not suspicious traffic|likely related to package management/.test(text)) {
    return hit({
      ruleId: 'policy-noise',
      activity: 'policy_noise',
      disposition: 'dismiss',
      priority: 'P4',
      headline: 'A Linux host checked for package updates, and the IDS called it policy noise.',
      why: [
        'Suricata\'s own classification is "Not Suspicious Traffic".',
        'The signature is the APT package-manager user-agent, which is normal on Debian and Ubuntu.',
        card.vendorLevel != null ? `The Wazuh level is ${card.vendorLevel} only because this signature was seen for the first time.` : 'First-time IDS rules often overstate routine traffic.',
      ],
      whatToDo: 'No action, unless the destination is a host you do not recognize as an Ubuntu mirror.',
      explain: 'The sensor is describing software updates. "First time this IDS alert is generated" raises the level without changing what happened.',
    });
  }

  if (/authentication success|imap-login: login:|login session opened|session opened|session closed|login: user=/.test(text)) {
    return hit({
      ruleId: 'auth-success',
      activity: 'routine_login',
      disposition: 'dismiss',
      priority: 'P4',
      headline: 'A login succeeded. This is normal use.',
      why: [
        'The log records a successful login with no preceding failures in this alert.',
        'Successful logins are the bulk of this data set and are not an attack by themselves.',
        `Host: ${hostOf(card)}.`,
      ],
      whatToDo: 'No action.',
      explain: 'Someone signed in with the right password over the usual service. Keep it in the record so a later failure storm has a baseline, and do not spend triage time on it.',
    });
  }

  // No local rule matched. Fall back on the vendor's own rating: Suricata priority 1, or a Wazuh rule
  // level of 10 or more, is high enough that it should not wait in the monitor pile.
  const suricataP1 = card.vendorPriority === 1;
  const wazuhHigh = typeof card.vendorLevel === 'number' && card.vendorLevel >= 10;
  if (suricataP1 || wazuhHigh) {
    return hit({
      ruleId: 'vendor-severity',
      activity: 'unclassified',
      disposition: 'investigate',
      priority: 'P2',
      headline: 'No local rule matched, but the vendor rated this alert high. A person should look at it today.',
      why: [
        'Reason: vendor severity (no rule matched).',
        suricataP1 ? 'Suricata priority is 1, its highest.' : `Wazuh rule level is ${card.vendorLevel} (10 or more is high).`,
        card.title ? `Vendor title: ${card.title}.` : 'No vendor title was parsed.',
      ],
      whatToDo: 'Read the alert and the hosts involved. If it is real, escalate it; if it is routine, add a local rule so it is classified next time.',
      explain: 'The assistant has no local rule for this alert, so it uses the vendor\'s own rating. A high vendor rating is not proof of an attack, but it is enough to put the alert in front of an analyst instead of the watch list. A model may raise this verdict. It may not lower it.',
      caught: false,
    });
  }

  return hit({
    ruleId: 'unclassified',
    activity: 'unclassified',
    disposition: 'monitor',
    priority: 'P3',
    headline: 'This alert did not match a known pattern. A person should glance at it.',
    why: [
      card.title ? `Vendor title: ${card.title}.` : 'No vendor title was parsed.',
      'Unmatched alerts stay visible so a new pattern is not auto-closed.',
    ],
    whatToDo: 'Read the log line. If it is routine, add a dismiss rule later. Do not ignore a burst of the same unmatched alert.',
    explain: 'The assistant only closes alerts it recognizes. Everything else waits for an analyst, or for the model when one is configured.',
    caught: false,
  });
}

// The full set of rule ids matchSignal can return, for tests and tooling.
export const ruleIds = [
  'sentinel-agent-alert', 'sentinel-agent-report-only', 'sentinel-agent',
  'malware-lure', 'risky-attachment', 'account-lure', 'phishing-credential',
  'html-attachment', 'payment-fraud', 'lookalike-link', 'benign-mail',
  'webshell-upload', 'su-www-data', 'sudo-from-webroot', 'wpscan', 'nmap',
  'version-bind', 'ssh-scan', 'dir-bust', 'service-stop', 'password-guessing',
  'reverse-shell', 'malware-beacon', 'web-attack', 'dns-exfil', 'dns-anomaly',
  'encoded-command', 'new-account', 'persistence', 'cpu-spike', 'auth-failure',
  'protocol-anomaly', 'clamav-update', 'policy-noise', 'auth-success',
  'vendor-severity', 'unclassified',
];

function clip(value) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (!text) return '';
  if (/^[A-Za-z0-9+/=_-]{24,}$/.test(text)) return '[encoded value, not shown]';
  return text.length > 160 ? `${text.slice(0, 157)}…` : text;
}

function around(text, pattern) {
  const raw = String(text || '');
  const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
  const match = re.exec(raw);
  if (!match) return '';
  const token = match[0];
  if (token.length > 40 && /^[A-Za-z0-9+/=_-]+$/.test(token)) {
    const lead = raw.slice(Math.max(0, match.index - 28), match.index).replace(/\s+/g, ' ').trim();
    return clip(`${lead} [encoded value, not shown]`.trim());
  }
  const start = Math.max(0, match.index - 36);
  const end = Math.min(raw.length, match.index + Math.min(token.length, 72) + 36);
  let slice = raw.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) slice = `…${slice}`;
  if (end < raw.length) slice = `${slice}…`;
  return clip(slice);
}

const QUOTES = {
  'sentinel-agent': [
    { field: 'Agent', read: (card) => card.sentinel?.agent },
    { field: 'Tool call', read: (card) => card.sentinel?.tool },
    { field: 'Guardrail outcome', read: (card) => (card.sentinel?.blocked ? 'blocked the send' : 'flagged the call and did not block it') },
    { field: 'Narrative', read: (card) => card.sentinel?.narrative },
  ],
  'sentinel-agent-report-only': [
    { field: 'Agent', read: (card) => card.sentinel?.agent },
    { field: 'Tool call', read: (card) => card.sentinel?.tool },
    { field: 'Guardrail outcome', read: () => 'report-only: the tool already ran' },
    { field: 'Narrative', read: (card) => card.sentinel?.narrative },
  ],
  'sentinel-agent-alert': [
    { field: 'Agent', read: (card) => card.sentinel?.agent },
    { field: 'Narrative', read: (card) => card.sentinel?.narrative },
    { field: 'Tactic', read: (card) => card.sentinel?.tactic },
  ],
  'malware-lure': [
    { field: 'Attachment', read: (card) => card.email?.attachment },
    { field: 'Sender', read: (card) => card.email?.from },
    { field: 'Matched wording', pattern: /enable content|enable macros|\.(?:iso|img|exe|scr|js|vbs|hta|docm|xlsm|lnk)\b/i },
  ],
  'risky-attachment': [
    { field: 'Attachment', read: (card) => card.email?.attachment },
    { field: 'Sender', read: (card) => card.email?.from },
    { field: 'File type', pattern: /\.(?:iso|img|vhdx?|exe|scr|js|vbs|hta|docm|xlsm|pptm|xlam|lnk)\b/i },
  ],
  'account-lure': [
    { field: 'Sender', read: (card) => card.email?.from },
    { field: 'Lure wording', pattern: /log\s*back\s*in|edit my return|identity protection|ip pin|tax return|credit karma/i },
  ],
  'phishing-credential': [
    { field: 'Sender', read: (card) => card.email?.from },
    { field: 'Link', pattern: /https?:\/\/\S+/i },
    { field: 'Ask', pattern: /password|passcode|verify your|sign in|credentials/i },
  ],
  'html-attachment': [
    { field: 'Attachment', read: (card) => card.email?.attachment },
    { field: 'Sender', read: (card) => card.email?.from },
  ],
  'payment-fraud': [
    { field: 'Sender', read: (card) => card.email?.from },
    { field: 'Payment wording', pattern: /gift cards?|wire transfer|bank details|payment details/i },
  ],
  'lookalike-link': [
    { field: 'Link host', pattern: /https?:\/\/\S+/i },
  ],
  'benign-mail': [
    { field: 'Sender', read: (card) => card.email?.from },
    { field: 'Subject', read: (card) => card.email?.subject },
  ],
  'webshell-upload': [
    { field: 'Request path', pattern: /\/wp-content\/uploads\/\S+/i },
    { field: 'Source address', read: (card) => card.src },
  ],
  'su-www-data': [
    { field: 'Identity switch', pattern: /successful su for\s+\S+\s+by www-data|www-data:\S+/i },
    { field: 'Host', read: (card) => card.host },
  ],
  'sudo-from-webroot': [
    { field: 'Working directory', pattern: /wp-content|uploads|\/var\/www/i },
    { field: 'Host', read: (card) => card.host },
  ],
  wpscan: [
    { field: 'Scanner name', pattern: /wpscan\S*/i },
    { field: 'Source address', read: (card) => card.src },
  ],
  nmap: [
    { field: 'Scanner name', pattern: /nmap[^.\n]*/i },
    { field: 'Target', read: (card) => card.host },
  ],
  'version-bind': [
    { field: 'DNS query', pattern: /version\.bind/i },
    { field: 'Source address', read: (card) => card.src },
  ],
  'ssh-scan': [
    { field: 'sshd note', pattern: /did not receive identification string|insecure connection attempt \(scan\)/i },
    { field: 'Source address', read: (card) => card.src },
  ],
  'dir-bust': [
    { field: 'Scan signal', pattern: /multiple web server 400 error codes|web_scan|\/\.hta\b|\/\.htaccess\b|\/\.htpasswd\b|dirb|gobuster/i },
    { field: 'Requested path', pattern: /\b(?:GET|POST)\s+\/\S+/i },
    { field: 'Source address', read: (card) => card.src },
  ],
  'service-stop': [
    { field: 'Service event', pattern: /service_stop|unit=put/i },
    { field: 'Host', read: (card) => card.host },
  ],
  'password-guessing': [
    { field: 'Failure burst', pattern: /multiple authentication failures|brute force|password crack|hashcat|john the ripper/i },
    { field: 'Host', read: (card) => card.host },
  ],
  'reverse-shell': [
    { field: 'Shell wording', pattern: /reverse.?shell|\/dev\/tcp\//i },
    { field: 'Host', read: (card) => card.host },
  ],
  'malware-beacon': [
    { field: 'Signature', pattern: /cobalt strike|meterpreter|c2 beacon|beacon activity/i },
    { field: 'Source address', read: (card) => card.src },
  ],
  'web-attack': [
    { field: 'Request clue', pattern: /union select|sql injection|<script|\.\.\/|\.\.\\/i },
    { field: 'Source address', read: (card) => card.src },
  ],
  'dns-exfil': [
    { field: 'DNS clue', pattern: /dnsteal|dns tunnel|dns exfil|query\[\w+\]\s+[a-z0-9-]{40,}\./i },
    { field: 'Host', read: (card) => card.host },
  ],
  'dns-anomaly': [
    { field: 'Anomaly', pattern: /high entropy in dns|entropydetector|value entropy anomaly|in dns domain/i },
    { field: 'Host', read: (card) => card.host },
  ],
  'encoded-command': [
    { field: 'Launcher', pattern: /encodedcommand|-enc\s+[a-z0-9+/=]{8,}/i },
    { field: 'Host', read: (card) => card.host },
  ],
  'new-account': [
    { field: 'Account event', pattern: /useradd |new user |account created|net user \S+ \/add/i },
    { field: 'Host', read: (card) => card.host },
  ],
  persistence: [
    { field: 'Task event', pattern: /crontab|schtasks|scheduled task/i },
    { field: 'Host', read: (card) => card.host },
  ],
  'cpu-spike': [
    { field: 'Anomaly', pattern: /cpu value (?:out of expected range|deviates)|valuerangedetector/i },
    { field: 'Host', read: (card) => card.host },
  ],
  'auth-failure': [
    { field: 'Login line', pattern: /authentication failure|invalid user login|auth failed|login failed/i },
    { field: 'Host', read: (card) => card.host },
  ],
  'protocol-anomaly': [
    { field: 'Decoder warning', pattern: /suricata (?:tls|http|smtp)[^\n]*|invalid handshake|generic protocol command decode/i },
    { field: 'Source address', read: (card) => card.src },
  ],
  'clamav-update': [
    { field: 'Maintenance line', pattern: /clamav[^\n.]{0,40}|freshclam[^\n.]{0,40}/i },
  ],
  'policy-noise': [
    { field: 'Sensor label', pattern: /not suspicious traffic|package management/i },
  ],
  'auth-success': [
    { field: 'Login line', pattern: /authentication success|imap-login: login:|login session opened|session opened/i },
    { field: 'Host', read: (card) => card.host },
  ],
  'vendor-severity': [
    { field: 'Vendor title', read: (card) => card.title },
    { field: 'Vendor level', read: (card) => (card.vendorLevel == null ? '' : String(card.vendorLevel)) },
    { field: 'Vendor priority', read: (card) => (card.vendorPriority == null ? '' : String(card.vendorPriority)) },
  ],
  unclassified: [
    { field: 'Vendor title', read: (card) => card.title },
    { field: 'Vendor level', read: (card) => (card.vendorLevel == null ? '' : String(card.vendorLevel)) },
  ],
};

export function collectEvidence(card, ruleId) {
  const spec = QUOTES[ruleId] || QUOTES.unclassified;
  const rows = [];
  for (const item of spec) {
    const excerpt = item.read ? clip(item.read(card)) : around(card.text, item.pattern);
    if (!excerpt) continue;
    rows.push({ field: item.field, excerpt });
  }
  if (/REDACTED/i.test(card.text || '') && !rows.some((row) => /REDACTED/i.test(row.excerpt))) {
    const redacted = around(card.text, /\[?REDACTED[^\s\]]*/i);
    if (redacted) rows.push({ field: 'Redacted field', excerpt: redacted });
  }
  return rows.slice(0, 5);
}
