const fs = require('fs');
const path = require('path');
const {chromium} = require('playwright');

(async () => {
  const html = fs.readFileSync(path.join(__dirname, '../controlserver/templates/console.html'), 'utf8');
  const executable = process.env.ENDPOINTAI_TEST_BROWSER_EXECUTABLE;
  if (!executable) throw Error('Explicit browser executable required');
  const browser = await chromium.launch({headless: true, executablePath: executable});
  try {
    for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) {
      const page = await browser.newPage({viewport});
      const requests = [], errors = [];
      let busy = false;
      page.on('pageerror', error => errors.push(error.message));
      await page.addInitScript(() => {
        const native = window.setInterval;
        window.__fixtureIntervals = [];
        window.setInterval = (callback, delay, ...args) => {
          if (delay === 60000) { window.__fixtureIntervals.push(callback); return 1; }
          return native(callback, delay, ...args);
        };
      });
      await page.route('**/*', async route => {
        const url = new URL(route.request().url());
        if (url.origin !== 'http://fixture.invalid') return route.abort();
        if (url.pathname === '/console') return route.fulfill({status: 200, contentType: 'text/html', body: html});
        if (url.pathname === '/auth/mode') return route.fulfill({json: {mode: 'legacy'}});
        if (url.pathname === '/admin/v1/policy') return route.fulfill({json: {policyVersion: 1, allowlistedDomains: [], routingRules: []}});
        if (url.pathname === '/admin/v1/analytics/devices') {
          requests.push(Object.fromEntries(url.searchParams));
          if (busy) return route.fulfill({status: 503, json: {error: {code: 'ANALYTICS_BUSY', message: 'busy'}}});
          return route.fulfill({json: {total: 50, skip: Number(url.searchParams.get('skip') || 0), take: 25,
            devices: [{device: {deviceId: 'synthetic-id', hostname: 'synthetic-host', osVersion: 'Windows',
              serviceVersion: 'test', employeeIds: ['00123'], lastSeenAtUtc: '2026-11-01T00:00:00Z'},
              onlineState: 'online', runningAgents: [], discoveredAgents: [], hasAnomaly: false,
              everAnomaly: false, dataInsufficient: false}]}});
        }
        return route.abort();
      });
      await page.goto('http://fixture.invalid/console');
      await page.waitForResponse(response => response.url().endsWith('/auth/mode'));
      await page.locator('#token').fill('synthetic-token');
      await page.locator('#actor').fill('synthetic-operator');
      await page.locator('#authForm button[type=submit]').click();
      await page.waitForFunction(() => window.__fixtureIntervals.length === 1);
      await page.locator('[data-page=assets]').click();
      await page.locator('#devices').getByText('synthetic-host').waitFor();
      const initial = requests.length;
      await page.locator('#search').pressSequentially('abc', {delay: 300});
      await page.evaluate(() => window.__fixtureIntervals[0]());
      await page.waitForTimeout(400);
      if (requests.length !== initial) throw Error('Typing or automatic refresh triggered a pending search');
      await Promise.all([page.waitForResponse(r => r.url().includes('/analytics/devices?')), page.locator('#search').press('Enter')]);
      if (requests.length !== initial + 1 || requests.at(-1).search !== 'abc' || requests.at(-1).skip !== '0') throw Error('Enter did not submit the first page');
      await Promise.all([page.waitForResponse(r => r.url().includes('/analytics/devices?')), page.evaluate(() => window.__fixtureIntervals[0]())]);
      if (requests.at(-1).search !== 'abc') throw Error('Automatic refresh did not resume after submission');
      await Promise.all([page.waitForResponse(r => r.url().includes('/analytics/devices?')), page.locator('#assetPager').getByText('下一页').click()]);
      await page.waitForFunction(() => document.querySelector('#assetPager').textContent.includes('第 26–50'));
      if (requests.at(-1).skip !== '25') throw Error('Next page failed');
      await page.locator('#search').fill('changed');
      const before = requests.length;
      await Promise.all([page.waitForResponse(r => r.url().includes('/analytics/devices?')), page.locator('#assetPager').getByText('上一页').click()]);
      await page.waitForFunction(() => document.querySelector('#assetPager').textContent.includes('第 1–25'));
      if (requests.length !== before + 1 || requests.at(-1).search !== 'changed' || requests.at(-1).skip !== '0') throw Error('Pending search did not start on the first page');
      await page.locator('#searchMode').selectOption('employee');
      await page.locator('#search').fill('00123');
      const beforeButton = requests.length;
      await Promise.all([page.waitForResponse(r => r.url().includes('/analytics/devices?')), page.locator('#refreshList').click()]);
      await page.waitForFunction(() => !document.querySelector('#assetFreshness').textContent.includes('搜索条件已更改'));
      if (requests.length !== beforeButton + 1 || requests.at(-1).employeeExact !== '00123' || requests.at(-1).skip !== '0') throw Error('Button did not submit exact search');
      busy = true;
      await Promise.all([page.waitForResponse(r => r.url().includes('/analytics/devices?')), page.locator('#refreshList').click()]);
      await page.waitForFunction(() => document.querySelector('#assetError').textContent.includes('当前有其他查询正在进行，请稍后重试'));
      if (errors.length) throw Error(errors.join('; '));
      await page.close();
    }
    console.log('Explicit search, paging and exact-search button passed in desktop and mobile browsers.');
  } finally { await browser.close(); }
})().catch(error => {console.error(error.stack || error); process.exitCode = 1});
