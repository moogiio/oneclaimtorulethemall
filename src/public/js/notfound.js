// The 404 page: a claims pipeline trace for the missing address and a few
// rules to "fix" it with. Nothing is sent anywhere, it all stays in the page.
const $ = (id) => document.getElementById(id);

const PERMIT = 'http://schemas.microsoft.com/authorization/claims/permit';
const DENY = 'http://schemas.microsoft.com/authorization/claims/deny';
const weekday = () => new Date().toLocaleDateString('en-US', { weekday: 'long' });

const FIXES = {
  permit: {
    rule: `@RuleName = "Permit everyone, harder"\n=> issue(Type = "${PERMIT}", Value = "true");`,
    badge: ['warning', '0 page claims'],
    message: 'Wrong step, and everyone was already permitted anyway. Access was never the problem, the page simply does not exist.',
  },
  deny: {
    rule: `@RuleName = "Deny everyone"\n=> issue(Type = "${DENY}", Value = "DenyUsersWithClaim");`,
    badge: ['error', 'Access denied'],
    get message() {
      return `Now nobody gets anything, including you. Bold move for a ${weekday()}. The linter in the app calls this “Denies everyone” and leaves it out of the export.`;
    },
  },
  raw: {
    rule: '@RuleName = "Pass through everything"\nc:[]\n => issue(claim = c);',
    badge: ['warning', '1 claim, wrong type'],
    message: 'Every incoming claim went straight through, so you got back exactly what you sent: a path to nowhere. Also, this app exists so nobody has to write rules by hand.',
  },
  home: {
    rule: '@RuleName = "Send lost visitors home"\nNOT EXISTS([Type == "urn:oneclaim:page"])\n => issue(Type = "urn:oneclaim:page", Value = "/");',
    badge: ['accent', '1 page claim issued'],
    message: 'That is the one. No page claim? Issue the start page instead.',
    follow: true,
  },
};

const RESULTS = [
  '0 claims issued. The relying party received no page.',
  'Still 0 claims. AD FS is nothing if not consistent.',
  'Still 0. Running it again will not create the page, but we admire the persistence.',
  'Still 0. Have you tried restarting the AD FS service? Please don’t.',
];

// Shown percent-encoded on purpose: decoded, a crafted link could put a
// readable message of its choice on this site. Encoded paths are ASCII, so
// cutting them never splits a character.
function shownPath() {
  const path = window.location.pathname;
  return path.length > 80 ? `${path.slice(0, 79)}…` : path;
}

// A fresh AD FS style activity id per run. getRandomValues also works over
// plain HTTP, unlike crypto.randomUUID.
function activityId() {
  const hex = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
}

function stamp() {
  $('nf-activity').textContent = activityId();
  $('nf-time').textContent = new Date().toISOString();
}

let runs = 1;
function replay() {
  const card = $('nf-trace-card');
  $('nf-result-text').textContent = RESULTS[Math.min(runs, RESULTS.length - 1)];
  runs++;
  stamp();
  // Restart the CSS reveal (skipped entirely with reduced motion).
  card.classList.remove('nf-play');
  void card.offsetWidth;
  card.classList.add('nf-play');
}

function pick(button) {
  const fix = FIXES[button.dataset.fix];
  for (const b of document.querySelectorAll('.nf-fix')) b.setAttribute('aria-pressed', String(b === button));
  $('nf-rule').textContent = fix.rule;
  $('nf-badge').className = `badge ${fix.badge[0]}`;
  $('nf-badge').textContent = fix.badge[1];
  $('nf-message').textContent = fix.message;
  $('nf-follow').hidden = !fix.follow;
  $('nf-outcome').hidden = false;
  $('nf-announce').textContent = `${fix.badge[1]}. ${fix.message}`;
}

for (const el of document.querySelectorAll('[data-path]')) el.textContent = shownPath();
stamp();
$('nf-replay').addEventListener('click', replay);
for (const b of document.querySelectorAll('.nf-fix')) b.addEventListener('click', () => pick(b));
$('nf-admin').addEventListener('click', () => {
  const msg = $('nf-admin-msg');
  msg.hidden = !msg.hidden;
  $('nf-admin').setAttribute('aria-expanded', String(!msg.hidden));
});
