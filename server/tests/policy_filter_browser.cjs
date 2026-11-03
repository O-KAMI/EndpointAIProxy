const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.ENDPOINTAI_TEST_BROWSER_EXECUTABLE });
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(process.env.ENDPOINTAI_TEST_ORIGIN + '/console');
    await page.waitForFunction(() => document.querySelector('label[for=token]').textContent === '密码');
    await page.locator('#actor').fill('admin');
    await page.locator('#token').fill('synthetic password 123');
    await page.locator('#authForm button[type=submit]').click();
    await page.locator('#appShell').waitFor({ state: 'visible' });
    await page.locator('[data-page=rollouts]').click();
    await page.locator('#policyBatchList button').first().click();
    await page.locator('#policyBatchDetail').waitFor({ state: 'visible' });
    for (const [state, expected, excluded] of [
      ['applyFailed', process.env.ENDPOINTAI_TEST_FAILED, process.env.ENDPOINTAI_TEST_UNSUPPORTED],
      ['unsupported', process.env.ENDPOINTAI_TEST_UNSUPPORTED, process.env.ENDPOINTAI_TEST_FAILED],
    ]) {
      const response = page.waitForResponse(r => r.url().includes('/policy-rollouts/') && r.url().includes('state=' + state));
      await page.locator('#policyBatchFilter').selectOption(state);
      await response;
      await page.waitForFunction(id => document.querySelector('#policyBatchTargets').textContent.includes(id), expected);
      if ((await page.locator('#policyBatchTargets').textContent()).includes(excluded)) throw Error('Filter included another target');
    }
    if (errors.length) throw Error('Browser errors: ' + errors.join('; '));
    await context.close();
  } finally {
    await browser.close();
  }
})().catch(error => { process.stderr.write(String(error.stack || error)); process.exitCode = 1; });
