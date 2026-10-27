#!/usr/bin/env node
// Builds the guide pages (/email-lookup/, /sources/, …) from the definitions
// below into <slug>/index.html, plus sitemap.xml. Static, crawlable, no
// JavaScript: each page answers one search intent and links to the scanner.
// Run with `npm run build:pages`; the output is committed and CI checks that
// a rebuild changes nothing.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { roHome, roNav, roPages, roSourceGroups } from './guides-ro.mjs';

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
        ['LeakCheck', 'A second breach index, merged with the first: one breach is counted once, whatever each calls it (free)'],
        ['Have I Been Pwned', 'Breaches and pastes (optional, needs an API key)'],
        ['Email intelligence', 'Deliverability, mailbox provider and disposable-address detection'],
        ['Mail security', 'SPF, DMARC, DKIM, MTA-STS, DNSSEC and CAA of the address’s own domain'],
    ]],
    ['Username', [
        ['480+ sites (Sherlock data)', 'Presence across hundreds of platforms, each hit checked against a name nobody has'],
        ['GitHub', 'Profile, organisations, social accounts, and addresses GitHub verified on the account’s GPG keys'],
        ['GitLab, Codeberg', 'Profiles, names, locations and websites'],
        ['SSH keys', 'The same public SSH key on GitHub, GitLab and Codeberg accounts'],
        ['Profile pictures', 'The same photo on two platforms, compared by a perceptual hash that survives resizing; generated avatars are ignored'],
        ['Keybase', 'Signed proofs tying Twitter, Reddit, Hacker News, GitHub and domains together'],
        ['Mastodon, Bluesky', 'Profiles, verified rel=me links and DNS-verified domain handles'],
        ['DEV Community, Lobsters', 'Profiles and the GitHub, Twitter and Mastodon accounts they list'],
        ['Duolingo', 'A profile’s name, join date and languages; and whether an email address has an account'],
        ['Lichess', 'A player’s real name, country, join date and the accounts the profile lists'],
        ['speedrun.com', 'A runner’s region, join date and the Twitch, YouTube and Twitter accounts they link'],
        ['Linktree', 'Every social account a Linktree page lists, its creation date and country'],
        ['Hugging Face', 'The full name, organisations, homepage and GitHub, Twitter, LinkedIn and Bluesky accounts on a profile'],
        ['Gravatar', 'A profile’s name, location, job and company, and the accounts Gravatar verified by having the owner sign in'],
        ['Codeforces, LeetCode', 'The name, city or country, company and school a programmer gives, and the accounts they list'],
        ['Wattpad', 'A writer’s name, location, join date, website and Facebook'],
        ['TikTok', 'The display name, bio and bio link, and when the account was created'],
        ['YouTube', 'A channel’s name, description, country, join date and the links it lists'],
        ['Substack', 'A writer’s name and bio, the accounts they connected by signing in, and their publication’s domain'],
        ['Mixcloud', 'A DJ’s or show’s name, city, country and join date'],
        ['Wikipedia (Wikimedia)', 'The global account’s home wiki, whose language hints at the editor’s, registration date and edits'],
        ['Telegram, Hacker News, Steam', 'Public profiles'],
        ['npm, PyPI, crates.io, Docker Hub', 'Published packages and images'],
    ]],
    ['Domain', [
        ['RDAP / WHOIS', 'Registrar, dates and, where not redacted, the registrant’s name, organisation, email and phone'],
        ['DNS', 'A, MX and TXT records, and the services the owner uses (Microsoft 365, Google Workspace, Atlassian, Stripe…)'],
        ['Certificate Transparency', 'Subdomains from issued certificates, and the other domains the same certificates name (crt.sh, with CertSpotter as fallback)'],
        ['Passive DNS', 'Historical resolutions and further subdomains'],
        ['Homepage', 'The owner’s accounts marked rel=me, profile links, contact address, phone and author'],
        ['Microsoft 365 tenant', 'The organisation’s name, its tenant and identity provider, and the other domains Microsoft verified for the same owner'],
        ['Tracking IDs', 'The Google Analytics, Tag Manager, AdSense and Meta Pixel IDs the site embeds, and the other sites that embed the same ones (HackerTarget)'],
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
        ['proxycheck.io', 'Whether the address is a VPN or proxy and which service runs it, or what kind of line it is (residential, business, hosting)'],
        ['GreyNoise', 'Whether the address scans the internet, and its classification'],
        ['Shodan, AbuseIPDB, VirusTotal', 'Services, abuse reports and reputation (optional API keys)'],
    ]],
    ['Phone', [
        ['Abstract phone intelligence', 'Validity, carrier, country, line type and, sometimes, the registered name'],
        ['libphonenumber (offline)', 'Country, the region of the prefix and the range’s original carrier, with no request'],
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
<li><strong>Data breaches</strong> from XposedOrNot and LeakCheck (both free) and, optionally, Have I Been Pwned: which breaches, when, and what was exposed.</li>
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
<p>For the platforms that matter most, a profile API is read instead of a status code: GitHub (profile, organisations, social accounts and the addresses GitHub verified on the account’s GPG keys), GitLab, Codeberg, Keybase, Mastodon, Bluesky, Telegram, Hacker News, Steam, DEV Community, Lobsters, Duolingo, Lichess, speedrun.com, Linktree, Hugging Face, Gravatar, Codeforces, LeetCode, Wattpad, TikTok, YouTube, Substack, Mixcloud, Wikipedia, npm, PyPI, crates.io and Docker Hub.</p>
<h2>Is it the same person?</h2>
<p>Two accounts with the same name may belong to strangers. The scanner looks for evidence that ties them:</p>
<ul>
<li><strong>The same SSH key</strong> on GitHub, GitLab and Codeberg accounts.</li>
<li><strong>The same profile picture</strong> on two platforms, compared by a perceptual hash; generated avatars and plain placeholders never count.</li>
<li><strong>What a profile says about its owner</strong>: the contact address and other accounts written in a bio or a GitHub profile README.</li>
<li><strong>Keybase proofs</strong>: signed statements tying a Keybase identity to Twitter, Reddit, Hacker News, GitHub and domains.</li>
<li><strong>Links the person published</strong>: the Twitter on a GitHub profile, the accounts on a DEV or Lobsters profile, the verified rel=me links on Mastodon.</li>
</ul>
<p>Accounts tied by such evidence are reported as confirmed; the rest are kept apart as found by name alone. <a href="/how-it-works/">How attribution works</a>.</p>`,
        faq: [
            ['How many sites are checked?', 'Around 480 through the Sherlock project’s site data, plus about twenty platforms read through their own profile APIs.'],
            ['Why are some accounts marked unconfirmed?', 'A matching username proves only that the name is taken. Unless something ties the account to the others — a shared SSH key, a signed proof, a published link, the same profile picture — it stays unconfirmed.'],
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
<p>A site also gives its owner away through the analytics and advertising accounts it embeds: a Google Analytics, Tag Manager or AdSense ID, or a Meta Pixel. The same ID on another site is the same owner’s — AdSense pays one publisher. The scanner reads them from the homepage and asks HackerTarget which other sites embed them; an ID on dozens of sites belongs to an agency or a platform and ties nothing.</p>
<p>A domain that uses Microsoft 365 names its organisation in Microsoft’s sign-in page, along with the identity provider it signs in through. Microsoft also lists every other domain in the same tenant, and a domain joins a tenant only once its owner proves control of its DNS: an old name, a sister brand or an acquisition shows up there.</p>
<p>Certificates tie domains too: each name on a certificate was proved by whoever asked for it, so another domain on a certificate of the scanned one had the same operator. CDN certificates that bundle unrelated customers are left out.</p>
<h2>Infrastructure and services</h2>
<ul>
<li><strong>DNS</strong>: addresses, mail servers and TXT records.</li>
<li><strong>Services in use</strong>: ownership tokens in TXT records, SPF senders and MX hosts reveal Microsoft 365, Google Workspace, Atlassian, Stripe, Slack, Zoom, OpenAI and dozens more.</li>
<li><strong>Subdomains</strong> from Certificate Transparency logs and passive DNS.</li>
<li><strong>DNS history</strong>: the addresses the domain pointed to over the years, from passive DNS. An address it used before moving behind a CDN may still be its origin server.</li>
<li><strong>Every IP</strong> the domain resolves to is checked for open ports, CVEs and its network operator. A CDN’s edge (Cloudflare, Fastly…) is named as such instead of being reported as the domain’s own open ports.</li>
</ul>
<h2>Exposure</h2>
<ul>
<li><strong>Exposed files</strong>: .env files, .git directories, database dumps and backups, confirmed by their content, not just a 200.</li>
<li><strong>Web posture</strong>: TLS and HTTP security headers, graded.</li>
<li><strong>Mail security</strong>: whether mail from the domain can be spoofed (SPF, DMARC, DKIM, MTA-STS).</li>
<li><strong>Lookalike domains</strong> that resolve — candidates for phishing.</li>
<li><strong>Subdomain takeover</strong>: subdomains whose CNAME points at GitHub Pages, S3, Heroku, Azure and other services where nothing is claimed any more — anyone could claim the name and serve content on the subdomain.</li>
</ul>
<h2>The people behind it</h2>
<p>The homepage is read for the accounts its owner marks with rel=me, the profiles it links, a contact address and phone. Keybase and Bluesky are asked who proved control of the domain. The Wayback Machine shows how long it has existed.</p>`,
        faq: [
            ['Can I see who owns a domain?', 'When the registration is not redacted, yes — many ccTLDs, organisations and older registrations still name the holder. Otherwise the homepage, Keybase and Bluesky proofs often identify the owner.'],
            ['How are subdomains found?', 'From Certificate Transparency logs, which record every publicly trusted certificate, and from historical DNS.'],
            ['Is the scan intrusive?', 'No. It reads public records and fetches a handful of well-known paths, as a browser would.'],
            ['How is a subdomain takeover detected?', 'From DNS alone, or one page load: the subdomain’s CNAME target no longer exists, or the service it points at answers with its “nothing here” page. Nothing is claimed or registered.'],
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
<li><strong>Domains it serves</strong>: the host name the address answers to (reverse DNS) and the other domains hosted on it. A meaningful host name is followed as a lead of its own; provider-generated names are not.</li>
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
<li><strong>Carrier, country and region</strong> of the number — the country, the region its prefix was assigned to and the carrier its range was allocated to are answered offline, from Google’s libphonenumber data, even when no provider answers. A ported number may since have moved carrier.</li>
<li><strong>Line type</strong>: mobile, landline, VoIP, toll-free.</li>
<li><strong>Registered name</strong>, where the provider has one.</li>
</ul>
<h2>Numbers found during other scans</h2>
<p>A phone number on a target’s website (a <code>tel:</code> link) or in a domain registration becomes a lead of its own and is looked up too — but only numbers in international form, since a national number would mean guessing the country. A number read off an account that only shares the target’s name is never added to their profile.</p>`,
        faq: [
            ['Which format should I use?', 'International format with the country code, for example +40 721 234 567 or +1 415 555 0123. A national number such as 0721 234 567 names no country, so the scan asks for the code.'],
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
<p>Breach data comes from XposedOrNot and LeakCheck, both free and without a key, and optionally from Have I Been Pwned. The indexes overlap, so a breach both list is counted once, and the risk score weighs an address’s fullest report rather than adding up the copies.</p>
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


const sourceTable = (groups, sourceLabel, revealsLabel) => groups.map(([group, rows]) => `
<h2>${escapeHTML(group)}</h2>
<div class="table-wrap"><table>
<thead><tr><th scope="col">${sourceLabel}</th><th scope="col">${revealsLabel}</th></tr></thead>
<tbody>
${rows.map(([name, what]) => `<tr><td>${escapeHTML(name)}</td><td>${escapeHTML(what)}</td></tr>`).join('\n')}
</tbody></table></div>`).join('\n');

const roByKey = new Map(roPages.map(page => [page.key, page]));
const locales = {
    en: {
        lang: 'en', ogLocale: 'en_US', home: '/', homeLabel: 'Home', nav, navLabel: 'Guides',
        path: key => `/${key}/`, page: key => pages.find(page => page.slug === key),
        cta: 'Run a free scan', how: 'How it works', questions: 'Questions', skip: 'Skip to content',
        scanner: 'Scanner', privacy: 'Privacy', terms: 'Terms', acceptable: 'Acceptable use',
        tagline: 'privacy-first OSINT, no third-party scripts.', other: 'ro', otherLabel: 'Română',
    },
    ro: {
        lang: 'ro', ogLocale: 'ro_RO', home: '/ro/', homeLabel: 'Acasă', nav: roNav, navLabel: 'Ghiduri',
        path: key => `/ro/${roByKey.get(key).slug}/`, page: key => roByKey.get(key),
        cta: 'Scanează gratuit', how: 'Cum funcționează', questions: 'Întrebări', skip: 'Sari la conținut',
        scanner: 'Scaner', privacy: 'Confidențialitate', terms: 'Termeni', acceptable: 'Utilizare acceptabilă',
        tagline: 'OSINT cu respect pentru confidențialitate, fără scripturi terțe.', other: 'en', otherLabel: 'English',
    },
};

function header(l, current, otherPath) {
    return `<header class="site-header"><div class="wrap">
<a class="brand" href="${l.home}">OSINT <span>Footprint Tracker</span></a>
<nav class="site-nav" aria-label="${l.navLabel}">
${l.nav.map(([key, label]) => `<a href="${l.path(key)}"${key === current ? ' aria-current="page"' : ''}>${escapeHTML(label)}</a>`).join('\n')}
<a href="${otherPath}" hreflang="${l.other}" lang="${l.other}">${l.otherLabel}</a>
</nav>
</div></header>`;
}

function footer(l) {
    return `<footer class="site-footer"><div class="wrap">
<nav aria-label="Site">
<a href="/">${l.scanner}</a>
${l.nav.map(([key, label]) => `<a href="${l.path(key)}">${escapeHTML(label)}</a>`).join('\n')}
<a href="/privacy.html">${l.privacy}</a>
<a href="/terms.html">${l.terms}</a>
<a href="/acceptable-use.html">${l.acceptable}</a>
</nav>
<p>${siteName} — ${l.tagline}</p>
</div></footer>`;
}

function head(l, { title, description, url, alternates, type, robots, extra = '' }) {
    return `<!DOCTYPE html>
<html lang="${l.lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHTML(title)}</title>
${description ? `<meta name="description" content="${escapeHTML(description)}">\n` : ''}${url ? `<link rel="canonical" href="${url}">\n` : ''}${(alternates || []).map(([lang, href]) => `<link rel="alternate" hreflang="${lang}" href="${href}">`).join('\n')}
<meta name="robots" content="${robots}">
<meta name="theme-color" content="#0f172a">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
${url ? `<meta property="og:type" content="${type}">
<meta property="og:site_name" content="${siteName}">
<meta property="og:locale" content="${l.ogLocale}">
<meta property="og:title" content="${escapeHTML(title)}">
<meta property="og:description" content="${escapeHTML(description)}">
<meta property="og:url" content="${url}">
<meta property="og:image" content="${origin}/og-image.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escapeHTML(title)}">
<meta name="twitter:description" content="${escapeHTML(description)}">
<meta name="twitter:image" content="${origin}/og-image.png">
` : ''}<link rel="stylesheet" href="/content.css?v=0">
${extra}</head>`;
}

const alternatesFor = key => [
    ['en', `${origin}${locales.en.path(key)}`], ['ro', `${origin}${locales.ro.path(key)}`],
    ['x-default', `${origin}${locales.en.path(key)}`],
];

function renderGuide(lang, key) {
    const l = locales[lang];
    const page = l.page(key);
    const url = `${origin}${l.path(key)}`;
    let body = typeof page.body === 'function' ? page.body() : page.body;
    if (body === 'SOURCES') {
        body = sourceTable(roSourceGroups, 'Sursă', 'Ce dezvăluie')
            + '\n<p>Fiecare sursă e verificată zilnic pe un cont cunoscut, iar o sursă care începe să pice e raportată și ocolită, în loc să încetinească fiecare scanare.</p>';
    }
    const graph = [
        { '@type': 'WebPage', '@id': url, url, name: page.title, description: page.description, inLanguage: l.lang,
          isPartOf: { '@type': 'WebSite', name: siteName, url: `${origin}/` }, dateModified: contentDate },
        { '@type': 'BreadcrumbList', itemListElement: [
            { '@type': 'ListItem', position: 1, name: l.homeLabel, item: `${origin}${l.home}` },
            { '@type': 'ListItem', position: 2, name: page.h1, item: url },
        ] },
    ];
    if (page.faq.length) {
        graph.push({ '@type': 'FAQPage', inLanguage: l.lang, mainEntity: page.faq.map(([q, a]) => ({
            '@type': 'Question', name: q, acceptedAnswer: { '@type': 'Answer', text: a } })) });
    }
    const tryLink = page.example ? `/?q=${encodeURIComponent(page.example)}` : '/';
    const other = locales[l.other];
    return `${head(l, { title: page.title, description: page.description, url, alternates: alternatesFor(key),
                        type: 'article', robots: 'index, follow, max-image-preview:large',
                        extra: `<script type="application/ld+json">\n${jsonLD({ '@context': 'https://schema.org', '@graph': graph })}\n</script>\n` })}
<body>
<a class="skip-link" href="#main">${l.skip}</a>
${header(l, key, other.path(key))}
<main id="main" class="wrap">
<nav class="crumbs" aria-label="Breadcrumb"><a href="${l.home}">${l.homeLabel}</a> › ${escapeHTML(page.h1)}</nav>
<h1>${escapeHTML(page.h1)}</h1>
<p class="lead">${escapeHTML(page.lead)}</p>
<div class="cta"><a class="button" href="${tryLink}">${l.cta}</a><a class="button secondary" href="${l.path('how-it-works')}">${l.how}</a></div>
${body.trim()}
${page.faq.length ? `<h2>${l.questions}</h2>\n${page.faq.map(([q, a]) => `<details><summary>${escapeHTML(q)}</summary><p>${escapeHTML(a)}</p></details>`).join('\n')}` : ''}
<div class="cta"><a class="button" href="${tryLink}">${l.cta}</a></div>
</main>
${footer(l)}
</body>
</html>
`;
}

const write = (path, html) => {
    mkdirSync(dirname(join(frontendDir, path)), { recursive: true });
    writeFileSync(join(frontendDir, path), html);
};

for (const page of pages) {
    write(`${page.slug}/index.html`, renderGuide('en', page.slug));
    write(`ro/${roByKey.get(page.slug).slug}/index.html`, renderGuide('ro', page.slug));
}

// The Romanian home: what the tool does, and the guides. The scanner itself
// is the English home page, which it links to.
{
    const l = locales.ro;
    const url = `${origin}/ro/`;
    const graph = [{ '@type': 'WebPage', '@id': url, url, name: roHome.title, description: roHome.description,
                     inLanguage: 'ro', isPartOf: { '@type': 'WebSite', name: siteName, url: `${origin}/` } }];
    write('ro/index.html', `${head(l, { title: roHome.title, description: roHome.description, url,
                                         alternates: [['en', `${origin}/`], ['ro', url], ['x-default', `${origin}/`]],
                                         type: 'website', robots: 'index, follow, max-image-preview:large',
                                         extra: `<script type="application/ld+json">\n${jsonLD({ '@context': 'https://schema.org', '@graph': graph })}\n</script>\n` })}
<body>
<a class="skip-link" href="#main">${l.skip}</a>
${header(l, '', '/')}
<main id="main" class="wrap">
<h1>${escapeHTML(roHome.h1)}</h1>
<p class="lead">${escapeHTML(roHome.lead)}</p>
<div class="cta"><a class="button" href="/">${l.cta}</a><a class="button secondary" href="${l.path('how-it-works')}">${l.how}</a></div>
<h2>Ce poți căuta</h2>
<div class="cards">
${roPages.filter(page => page.example).map(page => `<div class="card"><h3><a href="${l.path(page.key)}">${escapeHTML(page.h1)}</a></h3><p>${escapeHTML(page.lead)}</p></div>`).join('\n')}
</div>
<h2>Mai multe</h2>
<div class="cards">
${roPages.filter(page => !page.example).map(page => `<div class="card"><h3><a href="${l.path(page.key)}">${escapeHTML(page.h1)}</a></h3><p>${escapeHTML(page.lead)}</p></div>`).join('\n')}
</div>
</main>
${footer(l)}
</body>
</html>
`);
}

// Served by nginx for any path that is not a page, instead of the scanner
// with a 200 (a "soft 404" search engines index as duplicate content).
{
    const l = locales.en;
    write('404.html', `${head(l, { title: `Page not found — ${siteName}`, robots: 'noindex, follow' })}
<body>
<a class="skip-link" href="#main">${l.skip}</a>
${header(l, '', '/ro/')}
<main id="main" class="wrap">
<h1>Page not found</h1>
<p class="lead">There is nothing at this address. The scanner and the guides are below.</p>
<div class="cta"><a class="button" href="/">Open the scanner</a></div>
<div class="cards">
${pages.map(page => `<div class="card"><h3><a href="/${page.slug}/">${escapeHTML(page.h1)}</a></h3><p>${escapeHTML(page.lead)}</p></div>`).join('\n')}
</div>
</main>
${footer(l)}
</body>
</html>
`);
}

const legal = [['privacy.html', '2026-08-30', 'yearly', '0.3'], ['terms.html', '2026-08-30', 'yearly', '0.3'],
               ['acceptable-use.html', '2026-08-30', 'yearly', '0.3']];
const entry = (loc, lastmod, freq, priority, alternates = []) => `  <url>
    <loc>${loc}</loc>
${alternates.map(([lang, href]) => `    <xhtml:link rel="alternate" hreflang="${lang}" href="${href}"/>`).join('\n')}${alternates.length ? '\n' : ''}    <lastmod>${lastmod}</lastmod>
    <changefreq>${freq}</changefreq>
    <priority>${priority}</priority>
  </url>`;
const homeAlternates = [['en', `${origin}/`], ['ro', `${origin}/ro/`], ['x-default', `${origin}/`]];
const entries = [
    entry(`${origin}/`, contentDate, 'weekly', '1.0', homeAlternates),
    entry(`${origin}/ro/`, contentDate, 'weekly', '0.9', homeAlternates),
    ...pages.flatMap(page => [
        entry(`${origin}/${page.slug}/`, contentDate, 'monthly', '0.8', alternatesFor(page.slug)),
        entry(`${origin}${locales.ro.path(page.slug)}`, contentDate, 'monthly', '0.8', alternatesFor(page.slug)),
    ]),
    ...legal.map(([path, date, freq, priority]) => entry(`${origin}/${path}`, date, freq, priority)),
];
writeFileSync(join(frontendDir, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
${entries.join('\n')}
</urlset>
`);
console.log(`build-pages: wrote ${pages.length * 2 + 1} guide pages, 404.html and sitemap.xml`);
