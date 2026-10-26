// Romanian guides, paired with the English ones by `key` (the English slug).
// Written for how people search in Romanian, not translated word for word.

export const roNav = [
    ['email-lookup', 'Email'], ['username-search', 'Username'], ['domain-osint', 'Domeniu'],
    ['ip-lookup', 'IP'], ['phone-lookup', 'Telefon'], ['data-breach-check', 'Breșe'],
    ['sources', 'Surse'], ['how-it-works', 'Cum funcționează'], ['faq', 'Întrebări'],
];

export const roSourceGroups = [
    ['Email', [
        ['Gravatar', 'Profilul, numele afișat și conturile pe care Gravatar le-a verificat pentru adresă'],
        ['Commit-uri și profiluri GitHub', 'Contul GitHub și numele autorului din spatele adresei, din commit-uri sau din emailul public al profilului'],
        ['keys.openpgp.org', 'Alte adrese verificate pe aceeași cheie OpenPGP'],
        ['Keyserver Ubuntu', 'Numele de pe cheile PGP publice care menționează adresa (neverificate, cântărite ca atare)'],
        ['Holehe', 'Site-urile la care recuperarea contului recunoaște adresa'],
        ['XposedOrNot', 'Breșele de date în care apare adresa, ce s-a scurs și când (gratuit)'],
        ['Have I Been Pwned', 'Breșe și paste-uri (opțional, cu cheie API)'],
        ['Analiză email', 'Livrabilitate, furnizorul de email și adrese de unică folosință'],
        ['Securitatea emailului', 'SPF, DMARC, DKIM, MTA-STS, DNSSEC și CAA pentru domeniul propriu al adresei'],
    ]],
    ['Username', [
        ['480+ site-uri (date Sherlock)', 'Prezența pe sute de platforme, fiecare rezultat verificat cu un nume pe care nu-l are nimeni'],
        ['GitHub', 'Profilul, organizațiile, conturile sociale și adresele verificate de GitHub pe cheile GPG ale contului'],
        ['GitLab, Codeberg', 'Profiluri, nume, locații și site-uri'],
        ['Chei SSH', 'Aceeași cheie SSH publică pe conturile de GitHub, GitLab și Codeberg'],
        ['Poze de profil', 'Aceeași fotografie pe două platforme, comparată printr-un hash perceptual care rezistă la redimensionare; avatarurile generate sunt ignorate'],
        ['Keybase', 'Dovezi semnate care leagă Twitter, Reddit, Hacker News, GitHub și domenii'],
        ['Mastodon, Bluesky', 'Profiluri, link-uri verificate rel=me și handle-uri pe domeniu propriu'],
        ['DEV Community, Lobsters', 'Profiluri și conturile GitHub, Twitter și Mastodon pe care le listează'],
        ['Duolingo', 'Numele, data înscrierii și limbile unui profil; și dacă un email are cont'],
        ['Lichess', 'Numele real, țara, data înscrierii și conturile listate pe profilul unui jucător'],
        ['speedrun.com', 'Regiunea, data înscrierii și conturile Twitch, YouTube și Twitter legate de un speedrunner'],
        ['Telegram, Hacker News, Steam', 'Profiluri publice'],
        ['npm, PyPI, crates.io, Docker Hub', 'Pachete și imagini publicate'],
    ]],
    ['Domeniu', [
        ['RDAP / WHOIS', 'Registrarul, datele și, unde nu sunt ascunse, numele, organizația, emailul și telefonul deținătorului'],
        ['DNS', 'Înregistrările A, MX și TXT și serviciile folosite de deținător (Microsoft 365, Google Workspace, Atlassian, Stripe…)'],
        ['Certificate Transparency', 'Subdomenii din certificatele emise (crt.sh, cu CertSpotter ca rezervă)'],
        ['DNS pasiv', 'Rezoluții istorice și alte subdomenii'],
        ['Pagina principală', 'Conturile marcate rel=me, link-urile spre profiluri, emailul de contact, telefonul și autorul'],
        ['Securitate web', 'TLS, header-e de securitate HTTP și serverul folosit'],
        ['Fișiere expuse', '.env, .git, dump-uri de baze de date și backup-uri lăsate publice, confirmate după conținut'],
        ['Wayback Machine', 'Prima și ultima arhivare și câte există'],
        ['Domenii-capcană', 'Domenii asemănătoare care rezolvă (posibil phishing)'],
        ['Keybase, Bluesky', 'Conturi care au dovedit controlul asupra domeniului'],
    ]],
    ['Adresă IP', [
        ['InternetDB (Shodan)', 'Porturi deschise, CVE-uri cunoscute și hostname-uri (gratuit)'],
        ['RIPEstat', 'Prefixul rutat, AS-ul de origine și operatorul rețelei'],
        ['RDAP / WHOIS', 'Rețeaua căreia îi aparține adresa'],
        ['Tor Project', 'Dacă adresa e un nod de ieșire Tor activ'],
        ['GreyNoise', 'Dacă adresa scanează internetul și cum e clasificată'],
        ['Shodan, AbuseIPDB, VirusTotal', 'Servicii, rapoarte de abuz și reputație (chei API opționale)'],
    ]],
    ['Telefon', [
        ['Abstract phone intelligence', 'Validitate, operator, țară, tipul liniei și uneori numele titularului'],
        ['libphonenumber (offline)', 'Țara, regiunea prefixului și operatorul inițial al plajei, fără nicio cerere'],
        ['Găsite pe parcurs', 'Numerele de pe site-ul sau din înregistrarea domeniului unei ținte devin piste noi'],
    ]],
];

export const roPages = [
    {
        key: 'email-lookup', slug: 'cautare-email',
        title: 'Căutare după email (OSINT) — conturi, breșe și cine e în spate',
        description: 'Căutare OSINT gratuită după adresa de email: conturile înregistrate cu ea, persoana din spate, cheile PGP și breșele de date în care apare — fiecare legătură cu un scor de încredere.',
        h1: 'Căutare după email',
        lead: 'Află la ce duce o adresă de email: conturile create cu ea, numele persoanei din spate, cheile și profilurile legate de ea și breșele în care s-a scurs.',
        example: 'nume@exemplu.ro',
        body: `
<h2>Ce dezvăluie o adresă de email</h2>
<p>Emailul e cel mai bun punct de plecare într-o investigație OSINT, pentru că platformele îl verifică. Scanerul întreabă sursele care pot lega o adresă de un cont și păstrează motivul dat de fiecare:</p>
<ul>
<li><strong>GitHub</strong> leagă un commit de un cont doar printr-un email verificat, deci un commit semnat cu adresa numește proprietarul. Se verifică și emailul public al profilului.</li>
<li><strong>Gravatar</strong> întoarce profilul asociat adresei și conturile sociale verificate de Gravatar.</li>
<li><strong>Cheile OpenPGP</strong>: keys.openpgp.org listează doar adrese confirmate de proprietar, deci celelalte adrese de pe aceeași cheie sunt ale aceleiași persoane.</li>
<li><strong>Conturi înregistrate</strong>: Holehe întreabă formularele de recuperare a parolei dacă recunosc adresa și descoperă conturi pe Spotify, Office 365, Eventbrite și altele.</li>
<li><strong>Breșe de date</strong> din XposedOrNot (gratuit) și, opțional, Have I Been Pwned: ce breșe, când și ce s-a scurs.</li>
<li><strong>Domeniul adresei</strong>: pentru o adresă pe un domeniu propriu (nu Gmail sau Yahoo), se scanează și domeniul — deținătorul, site-ul și serviciile folosite.</li>
</ul>
<h2>De la o adresă la o amprentă întreagă</h2>
<p>Fiecare cont confirmat e urmat mai departe. Partea dinainte de @ e căutată ca username, un cont GitHub duce la dovezile lui Keybase, la cheile SSH și la site-ul listat, iar un domeniu dovedit pe Keybase e scanat la rândul lui. Fiecare pas e o verigă într-un lanț, iar lanțul decide cât de sigur e instrumentul că un cont aparține persoanei.</p>
<div class="note">Legăturile verificate de o platformă valorează 98%, cele publicate de persoană 90%, un username comun 40%. Un cont găsit doar pentru că are același nume nu poate prelua profilul. <a href="/ro/cum-functioneaza/">Cum funcționează scorul</a>.</div>
<h2>Pentru cine e</h2>
<p>Pentru verificarea propriei expuneri, investigarea phishing-ului și a fraudelor, due diligence și evaluări de securitate autorizate. Citește <a href="/acceptable-use.html">politica de utilizare</a> înainte să scanezi pe altcineva.</p>`,
        faq: [
            ['Pot afla cine deține o adresă de email?', 'Deseori, da. Când o platformă a verificat adresa — un commit GitHub, un profil Gravatar, o cheie OpenPGP — contul și numele de pe el sunt atribuite cu încredere mare. Adresele nefolosite public dezvăluie puțin.'],
            ['Proprietarul adresei află că a fost căutat?', 'Nu. Toate sursele sunt interogate pasiv; nu se trimite nimic către adresă. Verificările de recuperare a contului nu finalizează nicio resetare.'],
            ['Căutarea e gratuită?', 'Da. Verificarea conturilor înregistrate și căutarea pe 480 de site-uri cer un cont gratuit, verificat; restul merge anonim.'],
        ],
    },
    {
        key: 'username-search', slug: 'cautare-username',
        title: 'Căutare după username pe 480+ site-uri — fără rezultate false',
        description: 'Caută un username pe peste 480 de site-uri și în profilurile principalelor platforme. Fiecare rezultat e verificat cu un nume inexistent, iar conturile sunt legate prin chei SSH și dovezi Keybase.',
        h1: 'Căutare după username',
        lead: 'Vezi unde e folosit un username — și care dintre conturi aparțin, de fapt, aceleiași persoane.',
        example: 'username',
        body: `
<h2>Sute de site-uri, fără zgomot</h2>
<p>Majoritatea instrumentelor de căutare după username cer fiecărui site pagina de profil și raportează orice pagină care se încarcă. Multe site-uri răspund „200 OK” pentru orice nume — o pagină de login, una generică — așa că rezultatul e o listă lungă de conturi care nu există.</p>
<p>Scanerul întreabă fiecare site care raportează un cont și despre un nume aleator, pe care nu-l are nimeni. Un site care „găsește” și numele acela nu poate deosebi conturile reale de cele inexistente, iar rezultatul lui e eliminat. La o scanare obișnuită, asta elimină peste jumătate din rezultatele brute.</p>
<h2>Profiluri citite direct</h2>
<p>Pentru platformele importante se citește profilul prin API, nu doar un cod HTTP: GitHub (profil, organizații, conturi sociale și adresele verificate pe cheile GPG), GitLab, Codeberg, Keybase, Mastodon, Bluesky, Telegram, Hacker News, Steam, DEV Community, Lobsters, Duolingo, Lichess, speedrun.com, npm, PyPI, crates.io și Docker Hub.</p>
<h2>E aceeași persoană?</h2>
<p>Două conturi cu același nume pot fi ale unor străini. Scanerul caută dovezi care le leagă:</p>
<ul>
<li><strong>Aceeași cheie SSH</strong> pe conturile de GitHub, GitLab și Codeberg.</li>
<li><strong>Aceeași poză de profil</strong> pe două platforme, comparată printr-un hash perceptual; avatarurile generate și imaginile uniforme nu contează.</li>
<li><strong>Ce spune profilul despre proprietar</strong>: adresa de contact și celelalte conturi scrise în bio sau în README-ul de profil GitHub.</li>
<li><strong>Dovezi Keybase</strong>: declarații semnate care leagă o identitate Keybase de Twitter, Reddit, Hacker News, GitHub și domenii.</li>
<li><strong>Link-uri publicate de persoană</strong>: Twitter-ul de pe profilul GitHub, conturile de pe un profil DEV sau Lobsters, link-urile verificate rel=me de pe Mastodon.</li>
</ul>
<p>Conturile legate astfel apar confirmate; restul rămân separat, ca găsite doar după nume. <a href="/ro/cum-functioneaza/">Cum funcționează atribuirea</a>.</p>`,
        faq: [
            ['Câte site-uri sunt verificate?', 'Aproximativ 480, din datele proiectului Sherlock, plus vreo douăzeci de platforme citite prin API-ul lor de profil.'],
            ['De ce unele conturi apar neconfirmate?', 'Un username identic dovedește doar că numele e luat. Dacă nimic nu leagă contul de celelalte — o cheie SSH comună, o dovadă semnată, un link publicat, aceeași poză de profil — rămâne neconfirmat.'],
            ['Am nevoie de cont?', 'Căutarea pe 480 de site-uri cere un cont gratuit, verificat. Profilurile principalelor platforme se verifică anonim.'],
        ],
    },
    {
        key: 'domain-osint', slug: 'osint-domeniu',
        title: 'OSINT domeniu — deținător WHOIS, DNS, subdomenii și servicii folosite',
        description: 'Tot ce e public despre un domeniu într-o singură scanare: deținătorul din RDAP/WHOIS, DNS, subdomenii din certificate, serviciile SaaS folosite, fișiere expuse și conturile deținătorului.',
        h1: 'OSINT pentru domenii',
        lead: 'Tot ce e public despre un domeniu, într-o singură scanare: cine l-a înregistrat, ce rulează pe el, ce expune și ce servicii și conturi folosește deținătorul.',
        example: 'exemplu.ro',
        body: `
<h2>Deținătorul</h2>
<p>Înregistrarea RDAP a registry-ului dă registrarul și datele de înregistrare, actualizare și expirare. Pentru registry-urile „subțiri”, cum e .com, se interoghează și serverul RDAP al registrarului, unde stau datele deținătorului — iar unde nu sunt ascunse, se extrag numele, organizația, emailul, telefonul și țara. Emailul și telefonul deținătorului devin apoi piste noi.</p>
<h2>Infrastructură și servicii</h2>
<ul>
<li><strong>DNS</strong>: adrese, servere de mail și înregistrări TXT.</li>
<li><strong>Servicii folosite</strong>: tokenurile din TXT, expeditorii din SPF și serverele MX arată Microsoft 365, Google Workspace, Atlassian, Stripe, Slack, Zoom, OpenAI și zeci de altele.</li>
<li><strong>Subdomenii</strong> din jurnalele Certificate Transparency și din DNS-ul pasiv.</li>
<li><strong>Istoricul DNS</strong>: adresele la care a trimis domeniul de-a lungul anilor, din DNS-ul pasiv. O adresă folosită înainte de mutarea în spatele unui CDN poate fi încă serverul de origine.</li>
<li><strong>Fiecare IP</strong> la care rezolvă domeniul e verificat pentru porturi deschise, CVE-uri și operatorul rețelei. Marginea unui CDN (Cloudflare, Fastly…) e numită ca atare, nu raportată drept porturile deschise ale domeniului.</li>
</ul>
<h2>Expunere</h2>
<ul>
<li><strong>Fișiere expuse</strong>: .env, directoare .git, dump-uri de baze de date și backup-uri, confirmate după conținut, nu doar după un cod 200.</li>
<li><strong>Securitate web</strong>: TLS și header-e HTTP de securitate, cu notă.</li>
<li><strong>Securitatea emailului</strong>: dacă se pot trimite emailuri false în numele domeniului (SPF, DMARC, DKIM, MTA-STS).</li>
<li><strong>Domenii-capcană</strong> asemănătoare care rezolvă — candidate pentru phishing.</li>
<li><strong>Preluare de subdomenii</strong> (subdomain takeover): subdomenii al căror CNAME trimite la GitHub Pages, S3, Heroku, Azure sau alte servicii unde numele nu mai e revendicat — oricine l-ar putea revendica și ar servi conținut pe subdomeniu.</li>
</ul>
<h2>Oamenii din spate</h2>
<p>Pagina principală e citită pentru conturile marcate rel=me, profilurile spre care trimite, un email și un telefon de contact. Keybase și Bluesky sunt întrebate cine a dovedit controlul asupra domeniului. Wayback Machine arată de cât timp există.</p>`,
        faq: [
            ['Pot vedea cine deține un domeniu?', 'Când înregistrarea nu e ascunsă, da — multe domenii .ro, organizații și înregistrări mai vechi încă numesc deținătorul. Altfel, pagina principală și dovezile Keybase sau Bluesky îl identifică deseori.'],
            ['Cum sunt găsite subdomeniile?', 'Din jurnalele Certificate Transparency, care înregistrează fiecare certificat public, și din istoricul DNS.'],
            ['Scanarea e intruzivă?', 'Nu. Citește înregistrări publice și accesează câteva căi cunoscute, cum ar face un browser.'],
            ['Cum e detectată preluarea unui subdomeniu?', 'Doar din DNS sau dintr-o singură încărcare de pagină: ținta CNAME-ului nu mai există sau serviciul răspunde cu pagina lui de „nimic aici”. Nu se revendică și nu se înregistrează nimic.'],
        ],
    },
    {
        key: 'ip-lookup', slug: 'cautare-ip',
        title: 'Căutare adresă IP — porturi deschise, CVE-uri, operator și reputație',
        description: 'Verifică o adresă IP: porturile deschise și vulnerabilitățile cunoscute, rețeaua și AS-ul care o anunță, reputația de abuz și scanare și dacă e un nod de ieșire Tor.',
        h1: 'Căutare după adresă IP',
        lead: 'Ce expune o adresă IP, cine o operează și dacă are o reputație.',
        example: '8.8.8.8',
        body: `
<h2>Ce se verifică</h2>
<ul>
<li><strong>Porturi deschise și vulnerabilități cunoscute</strong> din InternetDB, baza gratuită a Shodan: porturi, CVE-uri, hostname-uri și etichete. O gazdă care răspunde doar pe porturi web e raportată ca site, nu ca expunere.</li>
<li><strong>Operatorul rețelei</strong>: prefixul rutat, AS-ul de origine și operatorul din RIPEstat, plus alocarea din RDAP-ul registrului regional.</li>
<li><strong>Reputație</strong>: dacă GreyNoise a văzut adresa scanând internetul și, opțional, Shodan, AbuseIPDB și VirusTotal.</li>
<li><strong>Tor</strong>: dacă adresa e un nod de ieșire Tor activ, din lista Tor Project.</li>
<li><strong>Domeniile pe care le servește</strong>: numele la care răspunde adresa (reverse DNS) și celelalte domenii găzduite pe ea. Un nume cu sens devine o pistă nouă; numele generate de furnizor, nu.</li>
</ul>
<p>Verdictele curate apar ca atare și nu adaugă nimic la scorul de risc; doar constatările reale contează.</p>`,
        faq: [
            ['Pot afla cine se află în spatele unei adrese IP?', 'Poți afla operatorul rețelei și organizația căreia i-a fost alocat blocul. Identificarea unei persoane cere evidențele furnizorului, care nu sunt publice.'],
            ['Sunt acceptate adrese interne?', 'Nu. Adresele private, loopback și cele de metadate cloud sunt refuzate, atât ca input, cât și când sunt descoperite în timpul unei scanări.'],
        ],
    },
    {
        key: 'phone-lookup', slug: 'cautare-telefon',
        title: 'Verificare număr de telefon — operator, țară, tip de linie',
        description: 'OSINT pentru numere de telefon: validitate, operator, țară, tipul liniei și, unde există, numele titularului — plus numerele găsite pe site-ul sau în înregistrarea domeniului unei ținte.',
        h1: 'Verificare număr de telefon',
        lead: 'Verifică un număr de telefon în format internațional: dacă e valid, ce operator și ce țară are și ce tip de linie e.',
        example: '+40721000000',
        body: `
<h2>Ce afli</h2>
<ul>
<li><strong>Validitatea</strong> și dacă numărul e alocat.</li>
<li><strong>Operatorul, țara și regiunea</strong> numărului — țara, regiunea căreia i-a fost alocat prefixul și operatorul căruia i-a fost alocată plaja vin offline, din datele libphonenumber (Google), chiar și când niciun furnizor nu răspunde. Un număr portat poate avea între timp alt operator.</li>
<li><strong>Tipul liniei</strong>: mobil, fix, VoIP, gratuit.</li>
<li><strong>Numele titularului</strong>, când furnizorul îl are.</li>
</ul>
<h2>Numere găsite în alte scanări</h2>
<p>Un număr de pe site-ul unei ținte (un link <code>tel:</code>) sau dintr-o înregistrare de domeniu devine o pistă nouă și e verificat și el — dar doar numerele în format internațional, pentru că la un număr național ar trebui ghicită țara. Un număr găsit pe un cont care doar are același nume cu ținta nu intră niciodată în profilul ei.</p>`,
        faq: [
            ['Ce format folosesc?', 'Formatul internațional, cu prefixul țării, de exemplu +40 721 234 567. Un număr național, ca 0721 234 567, nu spune țara, așa că scanarea cere prefixul.'],
            ['Pot afla al cui e un număr?', 'Uneori: verificarea întoarce numele titularului când furnizorul îl are. Numărul e comparat și cu ce au găsit celelalte surse despre o țintă.'],
        ],
    },
    {
        key: 'data-breach-check', slug: 'verificare-bresa-date',
        title: 'Verificare gratuită breșe de date — ți-a fost expus emailul?',
        description: 'Verifică gratuit în ce breșe de date apare un email: când a avut loc fiecare, câte conturi a expus și ce s-a scurs — parole, carduri, acte de identitate — cântărite într-un scor de risc.',
        h1: 'Verificare breșe de date',
        lead: 'Vezi în ce breșe s-a scurs o adresă de email, ce a expus fiecare și cât de grav e.',
        example: 'nume@exemplu.ro',
        body: `
<h2>Ce primești</h2>
<ul>
<li><strong>Fiecare breșă</strong> în care apare adresa, de la cea mai recentă, cu anul și numărul de conturi expuse.</li>
<li><strong>Ce s-a scurs</strong>: parole, date de card, acte de identitate, telefoane, adrese.</li>
<li><strong>Parole stocate slab</strong>: breșele în care parolele erau în clar sau într-o formă ușor de spart.</li>
<li><strong>Un scor de risc</strong> care cântărește breșele după conținut, nu după număr: o scurgere recentă de parole și carduri contează mult mai mult decât o listă veche de newsletter.</li>
</ul>
<p>Datele vin din XposedOrNot, gratuit și fără cheie, și opțional din Have I Been Pwned.</p>
<h2>Ce faci mai departe</h2>
<ol>
<li>Schimbă parola la fiecare cont care folosea o parolă scursă, începând cu emailul și banca.</li>
<li>Activează autentificarea în doi pași peste tot unde se poate.</li>
<li>Așteaptă-te la phishing țintit care citează date scurse și verifică mesajele neașteptate pe alt canal.</li>
<li>Dacă s-au scurs date de card sau de identitate, urmărește extrasele și ia în calcul blocarea creditului.</li>
</ol>`,
        faq: [
            ['Verificarea e gratuită?', 'Da. Nu cere cont și nici cheie.'],
            ['Emailul meu e salvat?', 'Scanările sunt criptate, iar cele anonime se șterg după 30 de zile. Vezi politica de confidențialitate.'],
            ['De ce crește scorul la breșele cu parole?', 'Pentru că o parolă scursă poate fi folosită direct împotriva ta, pe când o adresă scursă înseamnă mai ales spam.'],
        ],
    },
    {
        key: 'sources', slug: 'surse',
        title: 'Surse OSINT — peste 45 de surse de date pentru fiecare scanare',
        description: 'Cele peste 45 de surse OSINT pe care scanerul le interoghează pentru emailuri, username-uri, domenii, adrese IP și numere de telefon, și ce dezvăluie fiecare.',
        h1: 'Surse OSINT',
        lead: 'Fiecare scanare interoghează sursele potrivite inputului. Majoritatea sunt gratuite și nu cer cheie; câteva acceptă o cheie API opțională.',
        body: 'SOURCES',
        faq: [],
    },
    {
        key: 'how-it-works', slug: 'cum-functioneaza',
        title: 'Cum funcționează — scorul de atribuire pentru rezultatele OSINT',
        description: 'Cum transformă scanerul rezultatele brute în profil: derivarea țintelor, pivotare, legături verificate, declarate, observate și deduse, scoruri de atribuire și un scor de risc care cântărește ce s-a scurs.',
        h1: 'Cum funcționează',
        lead: 'Un instrument OSINT care listează orice cont cu același nume e ușor de făcut și greu de crezut. Acesta ține evidența motivului pentru care fiecare rezultat e legat de țintă și a cât de puternică e legătura.',
        body: `
<h2>1. De la un input la mai multe</h2>
<p>O adresă de email e căutată și după partea dinainte de @ ca username, un username cu separatori după variantele lui, iar o adresă pe un domeniu propriu după acel domeniu. Fiecare identificator derivat ține minte cum s-a ajuns la el.</p>
<h2>2. Urmărirea pistelor</h2>
<p>Rezultatele numesc identificatori noi: o adresă de pe o cheie GitHub, un domeniu dovedit pe Keybase, un site de pe un profil, un telefon de pe o pagină. Se scanează până la două runde de piste, dar doar de la conturi deja probabil ale țintei, și niciodată handle-uri de pe platforme comune, cum e <code>nume.bsky.social</code>.</p>
<h2>3. Legături și cât valorează fiecare</h2>
<div class="table-wrap"><table>
<thead><tr><th scope="col">Tip</th><th scope="col">Exemplu</th><th scope="col">Valoare</th></tr></thead>
<tbody>
<tr><td>Verificată</td><td>GitHub a legat un commit de cont printr-un email verificat; o dovadă Keybase semnată</td><td>98%</td></tr>
<tr><td>Declarată</td><td>Persoana a listat contul sau site-ul pe profilul ei</td><td>90%</td></tr>
<tr><td>Observată</td><td>Aceeași cheie SSH pe ambele conturi; recuperarea contului unui site recunoaște adresa</td><td>80%</td></tr>
<tr><td>Dedusă</td><td>Același username ca partea dinainte de @ / altă pistă / o variantă</td><td>55% / 40% / 35%</td></tr>
</tbody></table></div>
<h2>4. Atribuirea</h2>
<p>Fiecare identificator primește scorul celui mai puternic lanț până la input — produsul legăturilor de pe drum. Un cont aflat la două legături verificate distanță are 96%; unul care doar are același nume are în jur de 40%. Numele, locurile și organizațiile sunt cântărite după aceste scoruri, deci un străin cu același username nu poate prelua profilul.</p>
<h2>5. Dosarul</h2>
<p>Raportul începe cu profilul pe scurt: numele probabil, conturile confirmate (80% sau mai mult), probabile (50–79%) și neconfirmate, site-urile și domeniile țintei, datele de contact și ce s-a scurs.</p>
<h2>6. Riscul</h2>
<p>Scorul de risc adună categorii — breșe, servicii expuse, identități legate, date de contact, conturi — fiecare saturându-se, ca volumul singur să nu-l poată umfla la maximum. Un raport de breșe contează după conținut: câte breșe, dacă s-au scurs parole, date de plată sau de identitate și cât de recente sunt. Verdictele curate nu adaugă nimic.</p>
<h2>Confidențialitate</h2>
<p>Inputurile și rezultatele scanărilor sunt criptate, scanările anonime expiră după 30 de zile, iar site-ul nu are scripturi terțe sau analytics. Vezi <a href="/privacy.html">politica de confidențialitate</a>.</p>`,
        faq: [],
    },
    {
        key: 'faq', slug: 'intrebari',
        title: 'Întrebări frecvente — Digital Footprint Tracker',
        description: 'Răspunsuri despre scanerul OSINT: ce poate găsi, cât de precis e, legalitate, confidențialitate, păstrarea datelor, cost și chei API.',
        h1: 'Întrebări frecvente',
        lead: 'Ce face scanerul, ce nu face și cum tratează datele.',
        body: '',
        faq: [
            ['Ce pot căuta?', 'O adresă de email, un username, un domeniu, o adresă IP sau un număr de telefon în format internațional. Scanerul recunoaște singur ce ai introdus.'],
            ['E gratuit?', 'Da. Scanările anonime acoperă majoritatea surselor; un cont gratuit, verificat, adaugă căutarea pe 480 de site-uri, verificarea conturilor înregistrate, scanări salvate și monitorizare.'],
            ['Cât de precise sunt rezultatele?', 'Fiecare rezultat are motivul pentru care e legat de țintă și un scor de atribuire. Conturile legate prin link-uri verificate sau publicate sunt sigure; cele găsite doar după nume apar neconfirmate.'],
            ['Este OSINT legal?', 'Colectarea informațiilor publice e legală în majoritatea locurilor, dar felul în care le folosești poate să nu fie. Scanează-te pe tine, organizația ta sau persoane pe care ai dreptul să le investighezi și respectă politica de utilizare.'],
            ['Persoana scanată primește vreo notificare?', 'Nu. Sursele sunt interogate pasiv, iar verificările de recuperare a contului nu trimit nicio resetare.'],
            ['Ce se întâmplă cu scanările mele?', 'Inputurile și rezultatele sunt criptate. Scanările anonime se șterg după 30 de zile; cei cu cont își aleg singuri perioada de păstrare.'],
            ['Am nevoie de chei API?', 'Nu. Cheile pentru Shodan, AbuseIPDB, VirusTotal și Have I Been Pwned adaugă surse când operatorul le configurează, dar sursele gratuite acoperă fiecare tip de input.'],
            ['Îl pot folosi din scripturi?', 'Da, prin API-ul REST, cu o cheie API din contul tău. Vezi documentația API.'],
            ['Site-ul are tracking?', 'Nu. Nu există scripturi terțe, analytics sau beacon-uri; fiecare resursă e servită de pe acest domeniu.'],
        ],
    },
];

export const roHome = {
    title: 'Instrument OSINT gratuit: căutare după email, username, domeniu și IP',
    description: 'Instrument OSINT gratuit: află conturile, breșele și persoana din spatele unui email, username, domeniu, IP sau număr de telefon, din peste 45 de surse — fiecare legătură cu scor de încredere.',
    h1: 'Instrument OSINT gratuit',
    lead: 'Introdu un email, un username, un domeniu, o adresă IP sau un număr de telefon și vezi ce e public despre el: conturi, breșe, infrastructură și cine se află în spate — fiecare legătură cu un scor care spune cât de sigură e.',
};
