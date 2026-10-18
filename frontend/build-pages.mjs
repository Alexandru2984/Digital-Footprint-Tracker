#!/usr/bin/env node
// Builds the guide pages (/email-lookup/, /sources/, …) from the definitions
// below into <slug>/index.html, plus sitemap.xml. Static, crawlable, no
// JavaScript: each page answers one search intent and links to the scanner.
// Run with `npm run build:pages`; the output is committed and CI checks that
// a rebuild changes nothing.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const frontendDir = dirname(fileURLToPath(import.meta.url));
const origin = 'https://swift.micutu.com';
const siteName = 'Digital Footprint Tracker';
// Bumped by hand when the guides' content changes; drives <lastmod>.
const contentDate = '2026-10-19';

const escapeHTML = text => String(text)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const jsonLD = data => JSON.stringify(data, null, 2).replace(/</g, '\\u003c');

const nav = [
    ['email-lookup', 'Email'], ['username-search', 'Username'], ['domain-osint', 'Domain'],
    ['ip-lookup', 'IP'], ['phone-lookup', 'Phone'], ['data-breach-check', 'Breaches'],
    ['sources', 'Sources'], ['how-it-works', 'How it works'], ['faq', 'FAQ'],
];

const sourceGroups = [
    ['Email', [
        ['Gravatar', 'Profile, display name and the accounts Gravatar verified for the address'],
        ['GitHub commits and profiles', 'The GitHub account and author name behind an address, from its commits or public profile email'],
        ['keys.openpgp.org', 'Other addresses verified on the same OpenPGP key'],
        ['Ubuntu keyserver', 'Names on public PGP keys that mention the address (unverified, weighed accordingly)'],
        ['Holehe', 'Sites whose account recovery recognises the address (verified accounts)'],
        ['XposedOrNot', 'Data breaches the address appears in, what each exposed and when (free)'],
        ['Have I Been Pwned', 'Breaches and pastes (optional, needs an API key)'],
        ['Email intelligence', 'Deliverability, mailbox provider and disposable-address detection'],
        ['Mail security', 'SPF, DMARC, DKIM, MTA-STS, DNSSEC and CAA of the address’s own domain'],
    ]],
    ['Username', [
        ['480+ sites (Sherlock data)', 'Presence across hundreds of platforms, each hit checked against a name nobody has'],
        ['GitHub', 'Profile, organisations, social accounts, and addresses GitHub verified on the account’s GPG keys'],
        ['GitLab, Codeberg', 'Profiles, names, locations and websites'],
        ['SSH keys', 'The same public SSH key on GitHub, GitLab and Codeberg accounts'],
        ['Keybase', 'Signed proofs tying Twitter, Reddit, Hacker News, GitHub and domains together'],
        ['Mastodon, Bluesky', 'Profiles, verified rel=me links and DNS-verified domain handles'],
        ['DEV Community, Lobsters', 'Profiles and the GitHub, Twitter and Mastodon accounts they list'],
        ['Telegram, Hacker News, Steam', 'Public profiles'],
        ['npm, PyPI, crates.io, Docker Hub', 'Published packages and images'],
    ]],
    ['Domain', [
        ['RDAP / WHOIS', 'Registrar, dates and, where not redacted, the registrant’s name, organisation, email and phone'],
        ['DNS', 'A, MX and TXT records, and the services the owner uses (Microsoft 365, Google Workspace, Atlassian, Stripe…)'],
        ['Certificate Transparency', 'Subdomains from issued certificates (crt.sh, with CertSpotter as fallback)'],
        ['Passive DNS', 'Historical resolutions and further subdomains'],
        ['Homepage', 'The owner’s accounts marked rel=me, profile links, contact address, phone and author'],
        ['Web posture', 'TLS, HTTP security headers and server fingerprint'],
        ['Exposed files', 'Content-verified .env, .git, database dumps and backups left public'],
        ['Wayback Machine', 'First and last archive snapshot, and how many'],
        ['Typosquats', 'Lookalike domains that resolve'],
        ['Keybase, Bluesky', 'Accounts that proved control of the domain'],
    ]],
    ['IP address', [
        ['InternetDB (Shodan)', 'Open ports, known CVEs and hostnames (free)'],
        ['RIPEstat', 'Routed prefix, origin AS and network operator'],
        ['RDAP / WHOIS', 'The network the address belongs to'],
        ['Tor Project', 'Whether the address is a current Tor exit relay'],
        ['GreyNoise', 'Whether the address scans the internet, and its classification'],
        ['Shodan, AbuseIPDB, VirusTotal', 'Services, abuse reports and reputation (optional API keys)'],
    ]],
    ['Phone', [
        ['Abstract phone intelligence', 'Validity, carrier, country, line type and, sometimes, the registered name'],
        ['Found on the way', 'Numbers on a target’s website or domain registration become leads of their own'],
    ]],
];

const pages = [
    {
        slug: 'email-lookup',
        title: 'Email OSINT Lookup — Accounts, Breaches & Owner of an Email',
        description: 'Free email OSINT lookup: find the accounts registered to an address, the person behind it, its PGP keys and the data breaches it appears in — each link scored by how certain it is.',
        h1: 'Email OSINT lookup',
        lead: 'Find out what an email address leads to: the accounts registered with it, the name of the person behind it, the keys and profiles tied to it and the breaches it has leaked in.',
        example: 'name@example.com',
        body: `
<h2>What an email address reveals</h2>
<p>An address is the strongest starting point in open-source intelligence, because platforms verify it. The scanner asks the sources that can tie an address to an account and keeps the reason each one gives:</p>
<ul>
<li><strong>GitHub</strong> links commits to an account only through a verified email, so a commit authored with the address names its owner. A public profile email is checked too.</li>
<li><strong>Gravatar</strong> returns the profile behind the address and the social accounts Gravatar verified for it.</li>
<li><strong>OpenPGP keys</strong>: keys.openpgp.org lists only addresses whose owner confirmed them, so the other addresses on the same key belong to the same person.</li>
<li><strong>Account registrations</strong>: Holehe asks sites’ password-recovery flows whether they know the address, revealing accounts on services such as Spotify, Office 365 or Eventbrite.</li>
<li><strong>Data breaches</strong> from XposedOrNot (free) and, optionally, Have I Been Pwned: which breaches, when, and what was exposed.</li>
<li><strong>The address’s own domain</strong>: for a mailbox on a domain of its own (not Gmail or Outlook), the domain is scanned too — its registrant, website and the services it uses.</li>
</ul>
<h2>From one address to a whole footprint</h2>
<p>Every confirmed account is followed further. The local part of the address is searched as a username, a GitHub account leads to its Keybase proofs, its SSH keys and the website it lists, and a domain proven on Keybase is scanned in turn. Each step is a link in a chain, and the chain is what decides how sure the tool is that an account belongs to the person.</p>
<div class="note">Links a platform verified count for 98%, links the person published for 90%, a shared username for 40%. An account found only because it shares a name never takes over the profile. <a href="/how-it-works/">How the scoring works</a>.</div>
<h2>Who it is for</h2>
<p>Checking your own exposure, investigating phishing and fraud, due diligence and authorised security assessments. Read the <a href="/acceptable-use.html">acceptable use policy</a> before scanning anyone else.</p>`,
        faq: [
            ['Can I find who owns an email address?', 'Often. When a platform has verified the address — a GitHub commit, a Gravatar profile, an OpenPGP key — the account and the name on it are attributed with high confidence. Addresses that were never used publicly reveal little.'],
            ['Does the lookup alert the owner?', 'No. Every source is queried passively; nothing is sent to the address. Account-recovery checks never complete a reset.'],
            ['Is the email lookup free?', 'Yes. Account registration checks and the 480-site username sweep need a free, verified account; everything else runs anonymously.'],
        ],
    },
    {
        slug: 'username-search',
        title: 'Username Search Across 480+ Sites — With False Positives Removed',
        description: 'Search a username across 480+ websites and dedicated profile lookups. Every hit is checked against a name nobody has, and accounts are tied together by SSH keys and Keybase proofs.',
        h1: 'Username search across 480+ sites',
        lead: 'See where a username is registered — and which of those accounts actually belong to the same person.',
        example: 'username',
        body: `
<h2>Hundreds of sites, without the noise</h2>
<p>Most username checkers ask each site for a profile URL and report every page that loads. Many sites answer “200 OK” for any name at all — a login wall, a catch-all page — so the result is a long list of accounts that do not exist.</p>
<p>This scanner asks every site that reports a hit about a random name nobody owns as well. A site that “finds” that one too cannot tell real accounts from missing ones, and its hit is dropped. On a typical scan this removes more than half of the raw hits.</p>
<h2>Dedicated profile lookups</h2>
<p>For the platforms that matter most, a profile API is read instead of a status code: GitHub (profile, organisations, social accounts and the addresses GitHub verified on the account’s GPG keys), GitLab, Codeberg, Keybase, Mastodon, Bluesky, Telegram, Hacker News, Steam, DEV Community, Lobsters, npm, PyPI, crates.io and Docker Hub.</p>
<h2>Is it the same person?</h2>
<p>Two accounts with the same name may belong to strangers. The scanner looks for evidence that ties them:</p>
<ul>
<li><strong>The same SSH key</strong> on GitHub, GitLab and Codeberg accounts.</li>
<li><strong>Keybase proofs</strong>: signed statements tying a Keybase identity to Twitter, Reddit, Hacker News, GitHub and domains.</li>
<li><strong>Links the person published</strong>: the Twitter on a GitHub profile, the accounts on a DEV or Lobsters profile, the verified rel=me links on Mastodon.</li>
</ul>
<p>Accounts tied by such evidence are reported as confirmed; the rest are kept apart as found by name alone. <a href="/how-it-works/">How attribution works</a>.</p>`,
        faq: [
            ['How many sites are checked?', 'Around 480 through the Sherlock project’s site data, plus about twenty platforms read through their own profile APIs.'],
            ['Why are some accounts marked unconfirmed?', 'A matching username proves only that the name is taken. Unless something ties the account to the others — a shared SSH key, a signed proof, a published link — it stays unconfirmed.'],
            ['Do I need an account?', 'The 480-site sweep needs a free, verified account. The dedicated profile lookups run anonymously.'],
        ],
    },
    {
        slug: 'domain-osint',
        title: 'Domain OSINT — WHOIS Owner, DNS, Subdomains & Services Used',
        description: 'Domain OSINT in one scan: RDAP/WHOIS registrant, DNS, subdomains from certificate logs, the SaaS services a company uses, exposed files, web security grade and the owner’s accounts.',
        h1: 'Domain OSINT',
        lead: 'Everything public about a domain in one scan: who registered it, what runs on it, what it exposes and which services and accounts its owner uses.',
        example: 'example.com',
        body: `
<h2>Ownership</h2>
<p>The registry’s RDAP record gives the registrar and the registration, update and expiry dates. For thin registries such as .com, the registrar’s own RDAP server is asked as well, where the registrant lives — and where it is not redacted, the name, organisation, email, phone and country are extracted. The registrant’s email and phone then become leads of their own.</p>
<h2>Infrastructure and services</h2>
<ul>
<li><strong>DNS</strong>: addresses, mail servers and TXT records.</li>
<li><strong>Services in use</strong>: ownership tokens in TXT records, SPF senders and MX hosts reveal Microsoft 365, Google Workspace, Atlassian, Stripe, Slack, Zoom, OpenAI and dozens more.</li>
<li><strong>Subdomains</strong> from Certificate Transparency logs and passive DNS.</li>
<li><strong>Every IP</strong> the domain resolves to is checked for open ports, CVEs and its network operator.</li>
</ul>
<h2>Exposure</h2>
<ul>
<li><strong>Exposed files</strong>: .env files, .git directories, database dumps and backups, confirmed by their content, not just a 200.</li>
<li><strong>Web posture</strong>: TLS and HTTP security headers, graded.</li>
<li><strong>Mail security</strong>: whether mail from the domain can be spoofed (SPF, DMARC, DKIM, MTA-STS).</li>
<li><strong>Lookalike domains</strong> that resolve — candidates for phishing.</li>
</ul>
<h2>The people behind it</h2>
<p>The homepage is read for the accounts its owner marks with rel=me, the profiles it links, a contact address and phone. Keybase and Bluesky are asked who proved control of the domain. The Wayback Machine shows how long it has existed.</p>`,
        faq: [
            ['Can I see who owns a domain?', 'When the registration is not redacted, yes — many ccTLDs, organisations and older registrations still name the holder. Otherwise the homepage, Keybase and Bluesky proofs often identify the owner.'],
            ['How are subdomains found?', 'From Certificate Transparency logs, which record every publicly trusted certificate, and from historical DNS.'],
            ['Is the scan intrusive?', 'No. It reads public records and fetches a handful of well-known paths, as a browser would.'],
        ],
    },
    {
        slug: 'ip-lookup',
        title: 'IP Address OSINT — Open Ports, CVEs, Owner & Reputation',
        description: 'Look up an IP address: open ports and known CVEs, the network and AS that announce it, abuse and scanner reputation, and whether it is a Tor exit relay.',
        h1: 'IP address lookup',
        lead: 'What an IP address exposes, who operates it and whether it has a reputation.',
        example: '8.8.8.8',
        body: `
<h2>What is checked</h2>
<ul>
<li><strong>Open ports and known vulnerabilities</strong> from Shodan’s free InternetDB: ports, CVEs, hostnames and tags. A host answering only on web ports is reported as a website, not as an exposure.</li>
<li><strong>Network ownership</strong>: the routed prefix, origin AS and operator from RIPEstat, and the allocation from the regional registry’s RDAP.</li>
<li><strong>Reputation</strong>: whether GreyNoise has seen the address scanning the internet, and optionally Shodan, AbuseIPDB and VirusTotal.</li>
<li><strong>Tor</strong>: whether the address is a current Tor exit relay, checked against the Tor Project’s list.</li>
</ul>
<p>Clean verdicts are reported as clean and add nothing to the risk score; only real findings do.</p>`,
        faq: [
            ['Can I find who is behind an IP address?', 'You can find the network operator and the organisation the block is allocated to. Identifying an individual requires the provider’s records, which are not public.'],
            ['Are internal addresses supported?', 'No. Private, loopback and cloud-metadata addresses are refused, both as input and when discovered during a scan.'],
        ],
    },
    {
        slug: 'phone-lookup',
        title: 'Phone Number Lookup — Carrier, Country, Line Type & Validity',
        description: 'Phone number OSINT: validity, carrier, country, line type and, where available, the registered name — and phone numbers found on a target’s website or domain registration.',
        h1: 'Phone number lookup',
        lead: 'Check a phone number in international format: whether it is valid, which carrier and country it belongs to and what kind of line it is.',
        example: '+14155550123',
        body: `
<h2>What a lookup returns</h2>
<ul>
<li><strong>Validity</strong> and whether the number is assigned.</li>
<li><strong>Carrier, country and region</strong> of the number.</li>
<li><strong>Line type</strong>: mobile, landline, VoIP, toll-free.</li>
<li><strong>Registered name</strong>, where the provider has one.</li>
</ul>
<h2>Numbers found during other scans</h2>
<p>A phone number on a target’s website (a <code>tel:</code> link) or in a domain registration becomes a lead of its own and is looked up too — but only numbers in international form, since a national number would mean guessing the country. A number read off an account that only shares the target’s name is never added to their profile.</p>`,
        faq: [
            ['Which format should I use?', 'International format with the country code, for example +40 721 234 567 or +1 415 555 0123.'],
            ['Can I find the owner of a phone number?', 'Sometimes: the lookup returns a registered name when the provider has one. The number is also matched against what other sources found about a target.'],
        ],
    },
    {
        slug: 'data-breach-check',
        title: 'Free Data Breach Check — Has Your Email Been Leaked?',
        description: 'Check for free which data breaches an email appears in: when each happened, how many accounts it exposed and what leaked — passwords, card details, identity documents — weighed in a risk score.',
        h1: 'Data breach check',
        lead: 'See which breaches an email address has leaked in, what each one exposed and how serious it is.',
        example: 'name@example.com',
        body: `
<h2>What you get</h2>
<ul>
<li><strong>Every breach</strong> the address appears in, newest first, with the year and how many accounts it exposed.</li>
<li><strong>What leaked</strong>: passwords, card details, identity documents, phone numbers, addresses.</li>
<li><strong>Weak password storage</strong>: breaches where passwords were kept in plain text or in an easily cracked form.</li>
<li><strong>A risk score</strong> that weighs breaches by what they hold, not by how many there are: a recent leak of passwords and card numbers counts far more than an old mailing list.</li>
</ul>
<p>Breach data comes from XposedOrNot, free and without a key, and optionally from Have I Been Pwned.</p>
<h2>What to do next</h2>
<ol>
<li>Change the password of every account that shared a leaked password, starting with email and banking.</li>
<li>Turn on two-factor authentication wherever it is offered.</li>
<li>Expect targeted phishing that quotes leaked details, and verify unexpected messages through another channel.</li>
<li>If card or identity data leaked, watch statements and consider a credit freeze.</li>
</ol>`,
        faq: [
            ['Is the breach check free?', 'Yes. It needs no account and no key.'],
            ['Is my email stored?', 'Scans are encrypted at rest and anonymous scans are deleted after 30 days. See the privacy notice.'],
            ['Why does my score rise with breaches that leaked passwords?', 'Because a leaked password is directly usable against you, while a leaked address mostly means more spam.'],
        ],
    },
    {
        slug: 'sources',
        title: 'OSINT Sources — 45+ Data Sources Behind Every Scan',
        description: 'The 45+ OSINT sources the scanner queries for emails, usernames, domains, IP addresses and phone numbers, and what each one reveals.',
        h1: 'OSINT sources',
        lead: 'Every scan queries the sources that fit its input. Most are free and need no key; a few take an optional API key.',
        body: () => sourceGroups.map(([group, rows]) => `
<h2>${escapeHTML(group)}</h2>
<div class="table-wrap"><table>
<thead><tr><th scope="col">Source</th><th scope="col">What it reveals</th></tr></thead>
<tbody>
${rows.map(([name, what]) => `<tr><td>${escapeHTML(name)}</td><td>${escapeHTML(what)}</td></tr>`).join('\n')}
</tbody></table></div>`).join('\n') + `
<p>Each source is checked daily against a known account, and a source that starts failing is reported on the status page and backed off rather than slowing every scan.</p>`,
        faq: [],
    },
    {
        slug: 'how-it-works',
        title: 'How It Works — Attribution Scoring for OSINT Results',
        description: 'How the scanner turns raw OSINT hits into a profile: candidate derivation, pivots, verified, declared, observed and inferred links, attribution scores and a risk score that weighs what leaked.',
        h1: 'How it works',
        lead: 'An OSINT tool that lists every account with the same name is easy to build and hard to trust. This one keeps track of why each finding is connected to the target, and how strongly.',
        body: `
<h2>1. From one input to several</h2>
<p>An email address is also searched by its local part as a username, a username with separators by its variants, and an address on a domain of its own by that domain. Each derived identifier remembers how it was reached.</p>
<h2>2. Following the leads</h2>
<p>Findings name new identifiers: an address on a GitHub key, a domain proven on Keybase, a website on a profile, a phone number on a homepage. Up to two rounds of these leads are scanned, but only from accounts already likely to be the target’s, and never handles under shared platforms such as <code>name.bsky.social</code>.</p>
<h2>3. Links, and how much each is worth</h2>
<div class="table-wrap"><table>
<thead><tr><th scope="col">Kind</th><th scope="col">Example</th><th scope="col">Worth</th></tr></thead>
<tbody>
<tr><td>Verified</td><td>GitHub tied a commit to the account through a verified email; a signed Keybase proof</td><td>98%</td></tr>
<tr><td>Declared</td><td>The person listed the account or website on their profile</td><td>90%</td></tr>
<tr><td>Observed</td><td>The same SSH key on both accounts; a site’s account recovery knows the address</td><td>80%</td></tr>
<tr><td>Inferred</td><td>Same username as the email’s local part / another lead / a spelling variant</td><td>55% / 40% / 35%</td></tr>
</tbody></table></div>
<h2>4. Attribution</h2>
<p>Every identifier gets the score of its strongest chain back to the input — the product of the links along it. An account two verified links away scores 96%; one that only shares a name scores about 40%. Names, places and organisations are weighed by these scores, so a stranger who shares a username cannot take over the profile.</p>
<h2>5. The dossier</h2>
<p>The report opens with the profile at a glance: the likely name, accounts confirmed (80% and up), probable (50–79%) and unconfirmed, the target’s websites and domains, contact details, and what has leaked.</p>
<h2>6. Risk</h2>
<p>The risk score adds up categories — breaches, exposed services, linked identities, contact details, accounts — each saturating so that volume alone cannot max it out. A breach report counts for what it holds: how many breaches, whether passwords, payment or identity data leaked, and how recent. Clean verdicts add nothing.</p>
<h2>Privacy</h2>
<p>Scan inputs and results are encrypted at rest, anonymous scans expire after 30 days, and there are no third-party scripts or analytics on this site. See the <a href="/privacy.html">privacy notice</a>.</p>`,
        faq: [],
    },
    {
        slug: 'faq',
        title: 'FAQ — Digital Footprint Tracker',
        description: 'Answers about the OSINT scanner: what it can find, accuracy, legality, privacy, data retention, cost and API keys.',
        h1: 'Frequently asked questions',
        lead: 'What the scanner does, what it does not, and how it treats the data.',
        body: '',
        faq: [
            ['What can I search for?', 'An email address, a username, a domain, an IP address or a phone number in international format. The scanner recognises which one you typed.'],
            ['Is it free?', 'Yes. Anonymous scans cover most sources; a free, verified account adds the 480-site username sweep, account registration checks, saved scans and monitoring.'],
            ['How accurate are the results?', 'Every finding carries the reason it is connected to the target and an attribution score. Accounts tied by verified or published links are reliable; accounts found by name alone are marked unconfirmed.'],
            ['Is OSINT legal?', 'Collecting public information is legal in most places, but how you use it may not be. Scan yourself, your organisation, or people you are authorised to investigate, and follow the acceptable use policy.'],
            ['Does the person being scanned get notified?', 'No. Sources are queried passively and account recovery checks never send a reset.'],
            ['What happens to my scans?', 'Inputs and results are encrypted at rest. Anonymous scans are deleted after 30 days; account holders choose their own retention.'],
            ['Do I need API keys?', 'No. Shodan, AbuseIPDB, VirusTotal and Have I Been Pwned keys add sources when the operator configures them, but the free sources cover every input type.'],
            ['Can I use it from scripts?', 'Yes, through the REST API with an API key from your account. See the API documentation.'],
            ['Is there tracking on this site?', 'No. There are no third-party scripts, analytics or beacons; every asset is served from this origin.'],
        ],
    },
];

function header(current) {
    return `<header class="site-header"><div class="wrap">
<a class="brand" href="/">OSINT <span>Footprint Tracker</span></a>
<nav class="site-nav" aria-label="Guides">
${nav.map(([slug, label]) => `<a href="/${slug}/"${slug === current ? ' aria-current="page"' : ''}>${escapeHTML(label)}</a>`).join('\n')}
</nav>
</div></header>`;
}

const footer = `<footer class="site-footer"><div class="wrap">
<nav aria-label="Site">
<a href="/">Scanner</a>
${nav.map(([slug, label]) => `<a href="/${slug}/">${escapeHTML(label)}</a>`).join('\n')}
<a href="/privacy.html">Privacy</a>
<a href="/terms.html">Terms</a>
<a href="/acceptable-use.html">Acceptable use</a>
</nav>
<p>${siteName} — privacy-first OSINT, no third-party scripts.</p>
</div></footer>`;

function render(page) {
    const url = `${origin}/${page.slug}/`;
    const body = typeof page.body === 'function' ? page.body() : page.body;
    const graph = [
        { '@type': 'WebPage', '@id': url, url, name: page.title, description: page.description,
          isPartOf: { '@type': 'WebSite', name: siteName, url: `${origin}/` }, dateModified: contentDate },
        { '@type': 'BreadcrumbList', itemListElement: [
            { '@type': 'ListItem', position: 1, name: 'Home', item: `${origin}/` },
            { '@type': 'ListItem', position: 2, name: page.h1, item: url },
        ] },
    ];
    if (page.faq.length) {
        graph.push({ '@type': 'FAQPage', mainEntity: page.faq.map(([q, a]) => ({
            '@type': 'Question', name: q, acceptedAnswer: { '@type': 'Answer', text: a } })) });
    }
    const tryLink = page.example ? `/?q=${encodeURIComponent(page.example)}` : '/';
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHTML(page.title)}</title>
<meta name="description" content="${escapeHTML(page.description)}">
<link rel="canonical" href="${url}">
<meta name="robots" content="index, follow, max-image-preview:large">
<meta name="theme-color" content="#0f172a">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta property="og:type" content="article">
<meta property="og:site_name" content="${siteName}">
<meta property="og:title" content="${escapeHTML(page.title)}">
<meta property="og:description" content="${escapeHTML(page.description)}">
<meta property="og:url" content="${url}">
<meta property="og:image" content="${origin}/og-image.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escapeHTML(page.title)}">
<meta name="twitter:description" content="${escapeHTML(page.description)}">
<meta name="twitter:image" content="${origin}/og-image.png">
<link rel="stylesheet" href="/content.css?v=0">
<script type="application/ld+json">
${jsonLD({ '@context': 'https://schema.org', '@graph': graph })}
</script>
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
${header(page.slug)}
<main id="main" class="wrap">
<nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a> › ${escapeHTML(page.h1)}</nav>
<h1>${escapeHTML(page.h1)}</h1>
<p class="lead">${escapeHTML(page.lead)}</p>
<div class="cta"><a class="button" href="${tryLink}">Run a free scan</a><a class="button secondary" href="/how-it-works/">How it works</a></div>
${body.trim()}
${page.faq.length ? `<h2>Questions</h2>\n${page.faq.map(([q, a]) => `<details><summary>${escapeHTML(q)}</summary><p>${escapeHTML(a)}</p></details>`).join('\n')}` : ''}
<div class="cta"><a class="button" href="${tryLink}">Run a free scan</a></div>
</main>
${footer}
</body>
</html>
`;
}

for (const page of pages) {
    mkdirSync(join(frontendDir, page.slug), { recursive: true });
    writeFileSync(join(frontendDir, page.slug, 'index.html'), render(page));
}

// Served by nginx for any path that is not a page, instead of the scanner
// with a 200 (a "soft 404" search engines index as duplicate content).
writeFileSync(join(frontendDir, '404.html'), `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Page not found — ${siteName}</title>
<meta name="robots" content="noindex, follow">
<meta name="theme-color" content="#0f172a">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/content.css?v=0">
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
${header('')}
<main id="main" class="wrap">
<h1>Page not found</h1>
<p class="lead">There is nothing at this address. The scanner and the guides are below.</p>
<div class="cta"><a class="button" href="/">Open the scanner</a></div>
<div class="cards">
${pages.map(page => `<div class="card"><h3><a href="/${page.slug}/">${escapeHTML(page.h1)}</a></h3><p>${escapeHTML(page.lead)}</p></div>`).join('\n')}
</div>
</main>
${footer}
</body>
</html>
`);

const legal = [['privacy.html', '2026-08-30', 'yearly', '0.3'], ['terms.html', '2026-08-30', 'yearly', '0.3'],
               ['acceptable-use.html', '2026-08-30', 'yearly', '0.3']];
const entries = [[`${origin}/`, contentDate, 'weekly', '1.0'],
                 ...pages.map(page => [`${origin}/${page.slug}/`, contentDate, 'monthly', '0.8']),
                 ...legal.map(([path, date, freq, priority]) => [`${origin}/${path}`, date, freq, priority])];
writeFileSync(join(frontendDir, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${entries.map(([loc, lastmod, freq, priority]) => `  <url>
    <loc>${loc}</loc>
    <lastmod>${lastmod}</lastmod>
    <changefreq>${freq}</changefreq>
    <priority>${priority}</priority>
  </url>`).join('\n')}
</urlset>
`);
console.log(`build-pages: wrote ${pages.length} guide pages and sitemap.xml`);
