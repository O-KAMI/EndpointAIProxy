const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

(async () => {
  const html = fs.readFileSync(path.join(__dirname, '../controlserver/templates/console.html'), 'utf8');
  const executable = process.env.ENDPOINTAI_TEST_BROWSER_EXECUTABLE;
  if (!executable) throw Error('Explicit browser executable required');
  const browser = await chromium.launch({headless: true, executablePath: executable});
  try {
    for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) {
      const page = await browser.newPage({viewport});
      const requests = [], errors = [];
      let unavailable = false;
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/*', async route => {
        const url = new URL(route.request().url());
        if (url.origin !== 'http://fixture.invalid') return route.abort();
        if (url.pathname === '/console') return route.fulfill({status: 200, contentType: 'text/html', body: html});
        if (url.pathname === '/auth/mode') return route.fulfill({json: {mode: 'legacy'}});
        if (url.pathname === '/admin/v1/analytics/devices') {
          const mode = url.searchParams.get('snapshot');
          requests.push(mode);
          if (mode === '1' && unavailable) return route.fulfill({status: 503, json: {error: 'ANALYTICS_CACHE_UNAVAILABLE'}});
          const result = {total: 1, skip: 0, take: 25, updatedAtUtc: '2026-11-01T00:00:00Z', devices: [{
            device: {deviceId: 'synthetic-id', hostname: 'synthetic-host', osVersion: 'Windows',
              serviceVersion: 'test', onlineState: 'online', employeeIds: ['00123'], lastSeenAtUtc: '2026-11-01T00:00:00Z'},
            onlineState: 'online', runningAgents: [], discoveredAgents: [], hasAnomaly: false,
            everAnomaly: false, dataInsufficient: false
          }]};
          if (mode === '1') Object.assign(result, {cacheAgeSeconds: 20, cacheStale: false});
          return route.fulfill({json: result});
        }
        return route.abort();
      });
      await page.goto('http://fixture.invalid/console');
      await page.waitForResponse(response => response.url().endsWith('/auth/mode'));
      await page.evaluate(() => {document.querySelector('#authView').classList.add('hidden'); document.querySelector('#appShell').classList.remove('hidden')});
      await page.locator('[data-page=assets]').click();
      await page.locator('#devices').getByText('synthetic-host').waitFor();
      if (requests.at(-1) !== '0') throw Error('default request did not select automatic mode');
      await page.locator('#assetDataSource').selectOption('1');
      await page.waitForFunction(() => document.querySelector('#assetFreshness').textContent.includes('筛选快照'));
      if (requests.at(-1) !== '1') throw Error('snapshot mode was not requested');
      unavailable = true;
      await page.locator('#refreshList').click();
      await page.waitForFunction(() => document.querySelector('#assetError').textContent.includes('终端列表加载失败'));
      if (requests.at(-1) !== '1') throw Error('unavailable snapshot silently fell back');
      if (errors.length) throw Error(errors.join('; '));
      await page.close();
    }
    console.log('Snapshot selection, freshness and unavailable behavior passed in desktop and mobile browsers.');
  } finally { await browser.close(); }
})().catch(error => {console.error(error.stack || error); process.exitCode = 1});
