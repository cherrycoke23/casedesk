// Case Desk — Microsoft 365 connection (read-only). Sign-in uses OAuth 2.0 auth-code + PKCE in a popup.
const AUTH = 'https://login.microsoftonline.com/organizations/oauth2/v2.0';
const GRAPH = 'https://graph.microsoft.com/v1.0';
export const SCOPES = ['User.Read', 'Mail.Read', 'Calendars.Read', 'Tasks.Read', 'Notes.Read', 'offline_access'];
const SCOPE_STR = ['openid', 'profile', ...SCOPES].join(' ');
const LS_TOK = 'casedesk.tokens';

export const redirectUri = () => new URL('auth.html', location.href).href.split('?')[0];
export const isLocalhost = () => /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(location.origin);

const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));

let mem = null;
const load = () => { try { return mem || (mem = JSON.parse(localStorage.getItem(LS_TOK) || 'null')); } catch { return null; } };
const save = (t) => { mem = t; if (t) localStorage.setItem(LS_TOK, JSON.stringify(t)); else localStorage.removeItem(LS_TOK); };
export const hasSession = () => !!(load() && load().refresh_token);
export const signOut = () => save(null);

async function tokenRequest(clientId, params) {
  const body = new URLSearchParams({ client_id: clientId, scope: SCOPE_STR, redirect_uri: redirectUri(), ...params });
  const r = await fetch(`${AUTH}/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error_description ? j.error_description.split('\r\n')[0] : `Sign-in failed (${r.status})`);
  save({ access_token: j.access_token, refresh_token: j.refresh_token || (load() || {}).refresh_token, exp: Date.now() + (j.expires_in - 120) * 1000 });
}

// Must be called directly from a click so the popup isn't blocked.
export function signIn(clientId) {
  const popup = window.open('about:blank', 'casedesk-signin', 'width=520,height=700');
  if (!popup) return Promise.reject(new Error('Pop-up was blocked. Allow pop-ups for localhost and try again.'));
  return (async () => {
    const verifier = rand(48), state = rand(16);
    const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    const q = new URLSearchParams({ client_id: clientId, response_type: 'code', redirect_uri: redirectUri(), scope: SCOPE_STR, state, code_challenge: challenge, code_challenge_method: 'S256', prompt: 'select_account' });
    popup.location.href = `${AUTH}/authorize?${q}`;
    const url = await new Promise((resolve, reject) => {
      const iv = setInterval(() => {
        if (popup.closed) { clearInterval(iv); reject(new Error('Sign-in window was closed.')); return; }
        let href = '';
        try { href = popup.location.href; } catch { return; }
        if (href.startsWith(redirectUri())) { clearInterval(iv); popup.close(); resolve(new URL(href)); }
      }, 300);
    });
    const p = url.searchParams;
    if (p.get('error')) throw new Error(p.get('error_description') || p.get('error'));
    if (p.get('state') !== state) throw new Error('Sign-in state mismatch — try again.');
    await tokenRequest(clientId, { grant_type: 'authorization_code', code: p.get('code'), code_verifier: verifier });
  })();
}

async function accessToken(clientId) {
  const t = load();
  if (!t) throw new Error('Not signed in.');
  if (t.access_token && Date.now() < t.exp) return t.access_token;
  try { await tokenRequest(clientId, { grant_type: 'refresh_token', refresh_token: t.refresh_token }); }
  catch (e) { save(null); throw new Error('Your session expired — sign in again.'); }
  return load().access_token;
}

async function g(clientId, path, pages = 1) {
  let url = path.startsWith('http') ? path : GRAPH + path, out = [], first = null;
  for (let i = 0; i < pages && url; i++) {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${await accessToken(clientId)}` } });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error((j.error && j.error.message) || `Microsoft Graph error ${r.status}`), { status: r.status, path });
    if (!j.value) return j;
    first = first || j; out = out.concat(j.value); url = j['@odata.nextLink'];
  }
  return out;
}
const soft = async (p) => { try { return await p; } catch (e) { return { __err: e.message }; } };

const NUM_RE = /\b\d{1,4}[- ]?[A-Z]{1,5}[- ]?\d{2,7}(?:[- ][A-Z]{1,4})?\b/i;
const STOP = new Set(['estate', 'of', 'the', 'in', 're', 'matter', 'inc', 'inc.', 'llc', 'corp', 'corp.', 'co', 'co.', 'et', 'al', 'al.', 'and', 'people', 'state', 'county', 'city']);
function autoKeywords(name) {
  const kws = [];
  const num = name.match(NUM_RE); if (num) kws.push(num[0]);
  name.split(/\s+v(?:s)?\.?\s+/i).forEach((side) => {
    const w = side.replace(NUM_RE, '').split(/[\s,—–-]+/).find((x) => x.length >= 3 && !STOP.has(x.toLowerCase()));
    if (w) kws.push(w);
  });
  return kws;
}
// overrides: "Plan title = kw1, kw2" one per line
function parseOverrides(text) {
  const m = {};
  (text || '').split('\n').forEach((line) => { const [k, v] = line.split('='); if (k && v) m[k.trim().toLowerCase()] = v.split(',').map((s) => s.trim()).filter(Boolean); });
  return m;
}
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const utc = (dt) => new Date(/Z$|[+-]\d\d:\d\d$/.test(dt) ? dt : dt + 'Z');
const sod = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
const time12 = (d) => d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });

const DISC_RE = /\b(rfps?|rfas?|rogs?|srogs?|frogs?|interrogator\w*|requests? for (production|admission)|discovery responses?|responses? (due|to))\b/i;
const DEAD_RE = /\b(due|deadline|statute|s\.?o\.?l\.?|cut-?off|last day|filing|file|serve|designat\w*|expires?)\b/i;
const HEAR_RE = /\b(hearing|conference|trial|oral argument|cmc|msc|osc|arraignment|calendar call|status)\b/i;
const DEAD_TYPE = (s) => /statute|s\.?o\.?l/i.test(s) ? 'Statute' : /expert/i.test(s) ? 'Expert' : /cut-?off|discovery/i.test(s) ? 'Discovery' : /hearing|trial|conference/i.test(s) ? 'Hearing' : /serve|disclos/i.test(s) ? 'Service' : 'Filing';

export async function loadAll(clientId, overridesText) {
  const now = new Date(), base = sod(now);
  const off = (d) => Math.round((sod(d) - base) / 86400000);
  const me = await g(clientId, '/me?$select=displayName,mail,userPrincipalName');
  const domain = ((me.mail || me.userPrincipalName || '').split('@')[1]) || '';
  const warnings = [];

  const start = new Date(base.getTime() - 3 * 86400000).toISOString();
  const end = new Date(base.getTime() + 60 * 86400000).toISOString();
  const [tasksR, eventsR, mailR, sectionsR] = await Promise.all([
    soft(g(clientId, '/me/planner/tasks', 5)),
    soft(g(clientId, `/me/calendarView?startDateTime=${start}&endDateTime=${end}&$select=id,subject,start,end,isAllDay,location,webLink,isCancelled&$orderby=start/dateTime&$top=200`, 5)),
    soft(g(clientId, `/me/messages?$filter=flag/flagStatus eq 'flagged'&$select=id,subject,from,receivedDateTime,webLink&$top=100`, 2)),
    soft(g(clientId, '/me/onenote/sections?$select=id,displayName,links&$top=100', 3)),
  ]);
  [['Planner', tasksR], ['Calendar', eventsR], ['Mail', mailR], ['OneNote', sectionsR]].forEach(([n, r]) => r && r.__err && warnings.push(`${n}: ${r.__err}`));
  const tasks = Array.isArray(tasksR) ? tasksR : [], events = Array.isArray(eventsR) ? eventsR : [], mail = Array.isArray(mailR) ? mailR : [], sections = Array.isArray(sectionsR) ? sectionsR : [];

  // Cases = one Planner plan per case
  const planIds = [...new Set(tasks.map((t) => t.planId))];
  const plans = await Promise.all(planIds.map(async (id) => {
    const [p, b] = await Promise.all([soft(g(clientId, `/planner/plans/${id}?$select=id,title`)), soft(g(clientId, `/planner/plans/${id}/buckets?$select=id,name`))]);
    return { id, title: (p && p.title) || 'Untitled plan', buckets: Array.isArray(b) ? b : [] };
  }));
  const ov = parseOverrides(overridesText);
  const CASES = plans.map((p) => {
    const num = p.title.match(NUM_RE);
    return { id: p.id, name: p.title.replace(NUM_RE, '').replace(/[\s—–\-·|,]+$/, '').trim() || p.title, no: num ? num[0] : '—', hue: null, kws: ov[p.title.toLowerCase()] || autoKeywords(p.title) };
  }).sort((a, b) => a.name.localeCompare(b.name));
  const matchers = CASES.map((c) => ({ id: c.id, re: c.kws.length ? new RegExp(`\\b(${c.kws.map(esc).join('|')})\\b`, 'i') : null }));
  const matchCase = (text) => { const m = matchers.find((x) => x.re && x.re.test(text || '')); return m ? m.id : null; };

  sections.forEach((s) => {
    const id = CASES.find((c) => c.name.toLowerCase() === s.displayName.toLowerCase())?.id || matchCase(s.displayName);
    const c = CASES.find((x) => x.id === id);
    if (c && !c.notesUrl) c.notesUrl = (s.links.oneNoteClientUrl || s.links.oneNoteWebUrl || {}).href;
  });

  const bucketName = {};
  plans.forEach((p) => p.buckets.forEach((b) => { bucketName[b.id] = b.name; }));
  const TASKS = tasks.filter((t) => t.percentComplete < 100 || (t.completedDateTime && off(utc(t.completedDateTime)) === 0)).map((t) => ({
    id: t.id, title: t.title, c: t.planId, bucket: bucketName[t.bucketId] || 'Tasks',
    off: t.dueDateTime ? off(utc(t.dueDateTime)) : null, done: t.percentComplete === 100,
    status: t.percentComplete === 100 ? 'Completed' : t.percentComplete > 0 ? 'In progress' : 'Not started',
    url: `https://tasks.office.com/${domain}/Home/Task/${t.id}`,
  }));

  const EVENTS = [], DEADLINES = [], DISCOVERY = [];
  events.filter((e) => !e.isCancelled).forEach((e) => {
    const s = e.isAllDay ? new Date(e.start.dateTime.slice(0, 10) + 'T00:00:00') : utc(e.start.dateTime);
    const en = e.isAllDay ? s : utc(e.end.dateTime);
    const o = off(s), subj = e.subject || '(no subject)', c = matchCase(subj), loc = (e.location && e.location.displayName) || '';
    if (DISC_RE.test(subj)) {
      DISCOVERY.push({ id: e.id, c, set: subj, dir: /\b(our|respond to|served on us)\b/i.test(subj) ? 'on' : /\b(their|opposing|defendant'?s|plaintiff'?s) responses?\b/i.test(subj) ? 'by' : null, served: null, due: o, status: null, url: e.webLink });
    } else if (e.isAllDay || DEAD_RE.test(subj)) {
      DEADLINES.push({ id: e.id, title: subj, c, type: DEAD_TYPE(subj), off: o, url: e.webLink });
    } else if (o === 0) {
      EVENTS.push({ id: e.id, start: [s.getHours(), s.getMinutes()], end: [en.getHours(), en.getMinutes()], title: subj, c, loc: loc || '—', kind: HEAR_RE.test(subj) ? 'Hearing' : 'Meeting', url: e.webLink });
    }
  });

  const EMAILS = mail.sort((a, b) => b.receivedDateTime.localeCompare(a.receivedDateTime)).map((m) => {
    const d = utc(m.receivedDateTime);
    return { id: m.id, off: off(d), time: time12(d), from: (m.from && m.from.emailAddress && (m.from.emailAddress.name || m.from.emailAddress.address)) || 'Unknown', title: m.subject || '(no subject)', c: matchCase(m.subject), url: m.webLink };
  });

  return { me: { name: me.displayName, email: me.mail || me.userPrincipalName }, base, CASES, EVENTS, DEADLINES, TASKS, EMAILS, DISCOVERY, warnings, loadedAt: now };
}

export const canSignIn = () => location.protocol === 'https:' || isLocalhost();
const PKCE = 'casedesk.pkce';
// Full-page redirect sign-in (works inside an iPad Home Screen app, where pop-ups don't).
export async function beginSignIn(clientId) {
  const verifier = rand(48), state = rand(16);
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  localStorage.setItem(PKCE, JSON.stringify({ verifier, state }));
  localStorage.setItem('casedesk.return', location.href.split('#')[0].split('?')[0]);
  const q = new URLSearchParams({ client_id: clientId, response_type: 'code', redirect_uri: redirectUri(), scope: SCOPE_STR, state, code_challenge: challenge, code_challenge_method: 'S256', prompt: 'select_account' });
  location.assign(`${AUTH}/authorize?${q}`);
}
export const pendingCode = () => { const p = new URLSearchParams(location.search); return p.has('code') || p.has('error'); };
export async function finishSignIn(clientId) {
  const p = new URLSearchParams(location.search);
  history.replaceState(null, '', location.pathname);
  let pk = null; try { pk = JSON.parse(localStorage.getItem(PKCE) || 'null'); } catch (e) {}
  localStorage.removeItem(PKCE);
  if (p.get('error')) throw new Error(p.get('error_description') || p.get('error'));
  if (!pk || p.get('state') !== pk.state) throw new Error('Sign-in state mismatch. Try again.');
  if (!clientId) throw new Error('Paste your Application (client) ID in step 4 first.');
  await tokenRequest(clientId, { grant_type: 'authorization_code', code: p.get('code'), code_verifier: pk.verifier });
}
