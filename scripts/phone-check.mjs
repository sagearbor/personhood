#!/usr/bin/env node
// scripts/phone-check.mjs — drive the deployed web app through a full
// round-1 enrollment in real headless Chrome, emulating a 390x844 phone.
//
// It is the browser half of the post-deploy check (scripts/e2e-remote.sh is
// the API half): invite gate → email → on-screen magic link → skip the
// anchor step → sign & issue. At every step it asserts there is no
// horizontal scroll and no uncaught page error, and saves a screenshot.
//
// Usage:
//   PERSONHOOD_INVITE_CODE=... node scripts/phone-check.mjs [WEB_URL]
//
//   WEB_URL                 default https://personhood-web.web.app
//   PERSONHOOD_INVITE_CODE  required when the issuer is invite-gated (read
//                           from env so it never appears in argv)
//   CHROME                  Chrome binary; default: the macOS app path
//   OUT                     screenshot dir; default ./tmp/phone-check
//
// Requires a deployment in test mode (DEV_EXPOSE_CHALLENGE_SECRETS=1): the
// magic link must be on screen, since there is no inbox to read. No npm
// dependencies — Chrome DevTools Protocol over Node's built-in WebSocket.

import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const WEB_URL = process.argv[2] || 'https://personhood-web.web.app';
const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const OUT = process.env.OUT || 'tmp/phone-check';
const INVITE = process.env.PERSONHOOD_INVITE_CODE || '';
const W = 390;
const H = 844;

mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const profile = mkdtempSync(join(tmpdir(), 'phone-check-'));
const chrome = spawn(CHROME, [
  '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });

const wsURL = await new Promise((resolve, reject) => {
  let buf = '';
  chrome.stderr.on('data', (d) => {
    buf += d;
    const m = buf.match(/DevTools listening on (ws:\/\/\S+)/);
    if (m) resolve(m[1]);
  });
  chrome.on('exit', (c) => reject(new Error(`chrome exited ${c}`)));
  setTimeout(() => reject(new Error('chrome did not start')), 15000);
});

// Attach to the page target through the browser endpoint.
const browser = new WebSocket(wsURL);
await new Promise((r) => browser.addEventListener('open', r, { once: true }));
let nextId = 1;
const pending = new Map();
const pageErrors = [];
browser.addEventListener('message', (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
  } else if (msg.method === 'Runtime.exceptionThrown') {
    pageErrors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
  }
});
const send = (method, params = {}, sessionId) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    browser.send(JSON.stringify({ id, method, params, sessionId }));
  });

const { targetInfos } = await send('Target.getTargets');
const page = targetInfos.find((t) => t.type === 'page');
const { sessionId } = await send('Target.attachToTarget', { targetId: page.targetId, flatten: true });
const cdp = (m, p) => send(m, p, sessionId);

await cdp('Runtime.enable');
await cdp('Page.enable');
await cdp('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 3, mobile: true });
await cdp('Emulation.setTouchEmulationEnabled', { enabled: true });
await cdp('Emulation.setUserAgentOverride', {
  userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
});

async function evaluate(expr) {
  const r = await cdp('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
  return r.result.value;
}

// In-page helpers: find by visible text / label, set React-controlled input.
const HELPERS = `
  window.__pc = {
    text: () => document.body.innerText,
    btn: (re) => [...document.querySelectorAll('button')].find(b => new RegExp(re, 'i').test(b.textContent) && !b.disabled),
    click: (re) => { const b = __pc.btn(re); if (!b) return false; b.click(); return true; },
    fill: (labelRe, value) => {
      const lab = [...document.querySelectorAll('label')].find(l => new RegExp(labelRe, 'i').test(l.textContent));
      const inp = lab && (lab.htmlFor ? document.getElementById(lab.htmlFor) : lab.querySelector('input'));
      if (!inp) return false;
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(inp, value);
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    },
    overflow: () => document.documentElement.scrollWidth - window.innerWidth,
  };`;

let step = 0;
async function checkpoint(name) {
  step++;
  const overflow = await evaluate('__pc.overflow()');
  const { data } = await cdp('Page.captureScreenshot', { format: 'png' });
  const file = join(OUT, `${String(step).padStart(2, '0')}-${name}.png`);
  writeFileSync(file, Buffer.from(data, 'base64'));
  if (overflow > 0) throw new Error(`${name}: page is ${overflow}px wider than the ${W}px viewport`);
  if (pageErrors.length) throw new Error(`${name}: uncaught page error: ${pageErrors[0]}`);
  console.log(`ok   ${name}  (${file})`);
}

async function waitFor(desc, expr, timeoutMs = 30000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await evaluate(expr)) return;
    await sleep(300);
  }
  throw new Error(`timed out waiting for ${desc}; page says:\n${(await evaluate('__pc.text()')).slice(0, 600)}`);
}

let exitCode = 0;
try {
  await cdp('Page.navigate', { url: WEB_URL });
  await waitFor('app boot', `document.readyState === 'complete' && !!document.querySelector('main')`);
  await evaluate(HELPERS);
  await waitFor('invite gate or email step', `/invite code|email address/i.test(__pc.text())`);
  await checkpoint('boot');

  if (/invite code required/i.test(await evaluate('__pc.text()'))) {
    if (!INVITE) throw new Error('issuer is invite-gated; set PERSONHOOD_INVITE_CODE');
    if (!(await evaluate(`__pc.fill('invite code', ${JSON.stringify(INVITE)})`))) throw new Error('no invite code field');
    await evaluate(`__pc.click('continue')`);
  }
  await waitFor('email step', `!!document.querySelector('input[type=email], input[inputmode=email]') || /email address/i.test(__pc.text())`);
  await checkpoint('email-step');

  const email = `phone-check-${Date.now()}@example.com`;
  if (!(await evaluate(`__pc.fill('email address', '${email}')`))) throw new Error('no email field');
  await waitFor('send button enabled', `!!__pc.btn('send magic link')`);
  await evaluate(`__pc.click('send magic link')`);
  await waitFor('on-screen magic link', `!!document.querySelector('a[href*="/v1/methods/email/verify"]')`);
  await checkpoint('magic-link-shown');

  // "Click" the link the way a second tab would: a GET the page can't read.
  await evaluate(`fetch(document.querySelector('a[href*="/v1/methods/email/verify"]').href, { mode: 'no-cors' }).then(() => true)`);
  await waitFor('email verified', `!!__pc.btn('continue')`);
  await checkpoint('email-verified');
  await evaluate(`__pc.click('continue')`);

  // Round 1 has no anchor: skip through any optional steps to the credential.
  for (let i = 0; i < 4; i++) {
    await sleep(500);
    if (await evaluate(`!!__pc.btn('sign & issue')`)) break;
    await evaluate(`__pc.click('^skip') || __pc.click('skip')`);
  }
  await waitFor('issue button', `!!__pc.btn('sign & issue')`);
  await checkpoint('credential-step');
  await evaluate(`__pc.click('sign & issue')`);
  await waitFor('issued credential', `!!__pc.btn('save credential') && /did:web:/.test(__pc.text())`);
  await checkpoint('credential-issued');
  console.log('phone-check PASSED');
} catch (e) {
  exitCode = 1;
  console.error(`FAIL ${e.message}`);
  try {
    const { data } = await cdp('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(OUT, 'failure.png'), Buffer.from(data, 'base64'));
  } catch {}
} finally {
  browser.close();
  chrome.kill();
}
process.exit(exitCode);
