// Consent and error pages in a real browser (ADR-0010 §4-8, ADR-0024): WCAG 2.2 AA via axe,
// no JavaScript, equal-weight buttons, the 1 s Allow delay, Deny back to the app, and screenshots
// for the human review (slice 1.4).
const { test, expect } = require('@playwright/test');
const { AxeBuilder } = require('@axe-core/playwright');

const shots = '/work/screenshots';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const authorize = (client, redirect) =>
  '/authorize?' + new URLSearchParams({
    client_id: client, redirect_uri: redirect, response_type: 'code',
    code_challenge: challenge, code_challenge_method: 'S256', state: 'app-state',
  });
const desktop = authorize('desktop', 'http://127.0.0.1:43210/callback');

// The page server's clock moves only here, so the 1 s Allow delay never depends on runner speed.
async function advance(page, d) {
  const res = await page.request.post(`/test/advance?d=${d}`);
  expect(res.status()).toBe(204);
}

async function noViolations(page) {
  const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
  expect(r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(', ')}`)).toEqual([]);
}

for (const scheme of ['light', 'dark']) {
  test(`consent page is accessible and readable (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    const blocked = [];
    page.on('console', (m) => { if (m.type() === 'error') blocked.push(m.text()); });
    await page.goto(desktop);
    await expect(page.locator('h1')).toHaveText('Example Desktop App wants to use Team dashboards as you');
    await expect(page.locator('main')).toContainText('an app on this computer');
    await expect(page.locator('main')).toContainText("you'll sign in with Microsoft Entra next");
    await noViolations(page);
    expect(blocked).toEqual([]); // the stylesheet passes the CSP
    await page.screenshot({ path: `${shots}/consent-desktop-${scheme}.png`, fullPage: true });
  });
}

// WCAG 2.2 1.4.10 Reflow: at 320 CSS px nothing scrolls sideways, even with a long unbroken name
// and host (axe does not check this).
test('at 320 px the page reflows without sideways scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 640 });
  await page.goto(authorize('long', 'https://a-very-long-subdomain-name-for-reflow-checks.app.example.org/oauth/callback'));
  await page.getByText('Technical details').click();
  await expect(page.locator('details code').first()).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await noViolations(page);
  await page.screenshot({ path: `${shots}/consent-phone-details.png`, fullPage: true });
});

test('a web app shows its redirect host and no loopback warning', async ({ page }) => {
  await page.goto(authorize('web', 'https://app.example.org/oauth/callback'));
  await expect(page.locator('main')).toContainText('app.example.org');
  await expect(page.locator('main')).not.toContainText('Only allow this if');
  await noViolations(page);
  await page.screenshot({ path: `${shots}/consent-web.png`, fullPage: true });
});

test('an unverified app shows its sanitised name labelled Not verified', async ({ page }) => {
  await page.goto(authorize('unverified', 'http://127.0.0.1:43210/callback'));
  await expect(page.locator('h1')).toHaveText('Free Tools[0m Helper wants to use Team dashboards as you');
  await expect(page.locator('main')).toContainText('(Not verified)');
  await noViolations(page);
  await page.screenshot({ path: `${shots}/consent-unverified.png`, fullPage: true });
});

test('nothing is focused on load and Allow and Deny carry equal weight', async ({ page }) => {
  await page.goto(desktop);
  expect(await page.evaluate(() => document.activeElement === document.body)).toBe(true);
  const deny = await page.getByRole('button', { name: 'Deny' }).boundingBox();
  const allow = await page.getByRole('button', { name: 'Allow' }).boundingBox();
  expect(Math.round(deny.width)).toBe(Math.round(allow.width));
  expect(Math.round(deny.height)).toBe(Math.round(allow.height));
  expect(deny.height).toBeGreaterThanOrEqual(24); // WCAG 2.2 2.5.8 target size
  const look = (b) => b.evaluate((el) => {
    const s = getComputedStyle(el);
    return [s.backgroundColor, s.color, s.borderColor, s.borderWidth, s.fontWeight, s.fontSize].join(' ');
  });
  expect(await look(page.getByRole('button', { name: 'Allow' }))).toBe(await look(page.getByRole('button', { name: 'Deny' })));
  await page.keyboard.press('Tab'); // summary
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Deny' })).toBeFocused();
  await page.screenshot({ path: `${shots}/consent-keyboard-focus.png` });
});

// The unit tests check the parameters; this proves a real browser's Origin and Sec-Fetch-Site pass
// the CSRF check (it caught Referrer-Policy: no-referrer turning Origin into "null").
test('a real browser can Deny back to the app', async ({ page }) => {
  await page.goto(desktop);
  // The app's callback is not listening; the redirect itself is what matters.
  const [res] = await Promise.all([
    page.waitForResponse((r) => r.url().endsWith('/consent')),
    page.getByRole('button', { name: 'Deny' }).click(),
  ]);
  expect(res.status()).toBe(302);
  const u = new URL(res.headers()['location']);
  expect(u.origin + u.pathname).toBe('http://127.0.0.1:43210/callback');
  expect(u.searchParams.get('error')).toBe('access_denied');
});

test('Allow at once asks again; after a second it goes to the IdP', async ({ page }) => {
  await page.goto(desktop);
  await page.getByRole('button', { name: 'Allow' }).click();
  await expect(page.getByRole('status')).toContainText('Take a moment to check the details');
  await noViolations(page);
  await page.screenshot({ path: `${shots}/consent-too-fast.png`, fullPage: true });
  await advance(page, '1s');
  await page.getByRole('button', { name: 'Allow' }).click();
  await page.waitForURL('**/stub-idp**');
});

test('answering from another browser shows an error page', async ({ page, context }) => {
  await page.goto(desktop);
  await context.clearCookies();
  await page.getByRole('button', { name: 'Allow' }).click();
  await expect(page.locator('h1')).toHaveText('This consent page was opened in another browser.');
  await expect(page.locator('main')).toContainText(/Reference: [0-9a-f-]{36}/);
  await noViolations(page);
  await page.screenshot({ path: `${shots}/error-other-browser.png`, fullPage: true });
});

for (const scheme of ['light', 'dark']) {
  test(`unknown app shows an error page with a reference (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    const res = await page.goto(authorize('nobody', 'http://127.0.0.1:43210/callback'));
    expect(res.status()).toBe(400);
    await expect(page.locator('h1')).toHaveText('This app is not registered with the proxy.');
    await expect(page.locator('main')).toContainText(/Reference: [0-9a-f-]{36}/);
    await noViolations(page);
    await page.screenshot({ path: `${shots}/error-unknown-app-${scheme}.png`, fullPage: true });
  });
}
