const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.ENDPOINTAI_TEST_BROWSER_EXECUTABLE });
  try {
    for (const username of ['viewer', 'operator', 'admin']) {
      const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } });
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(process.env.ENDPOINTAI_TEST_ORIGIN + '/console');
      await page.waitForFunction(() => document.querySelector('label[for=token]').textContent === '密码');
      await page.locator('#actor').fill(username);
      await page.locator('#token').fill('synthetic password 123');
      await page.locator('#authForm button[type=submit]').click();
      await page.locator('#appShell').waitFor({ state: 'visible', timeout: 15000 });
      if (await page.locator('#token').inputValue()) throw new Error('Password input was not cleared');
      if (await page.evaluate(() => sessionStorage.getItem('sf-admin-token'))) throw new Error('Local password persisted as legacy token');
      await page.locator('[data-page=policy]').click();
      await page.waitForFunction(() => document.querySelector('#policySummary').textContent.includes('最后上报校准成功'));
      const summary = await page.locator('#policySummary').textContent();
      if (!summary.includes('未确认校准成功') || !summary.includes('离线设备为最后上报状态') || summary.includes('待同步')) throw new Error('Policy summary obscures last-reported state');
      if (username !== 'admin') {
        await page.locator('#gatewayTab').click();
        const previousHeartbeat = await page.locator('#heartbeatInterval').inputValue();
        await page.locator('#heartbeatInterval').fill('120');
        if (!await page.locator('#savePolicy').isDisabled()) throw new Error('Read-only policy role can submit a global policy draft');
        await page.locator('#heartbeatInterval').fill(previousHeartbeat);
        const status = await page.evaluate(async () => {
          try { await api('/admin/v1/policy', { method: 'PUT', body: '{}' }); return 200; }
          catch (error) { return error.status; }
        });
        if (status !== 403 || !await page.locator('#appShell').isVisible()) throw new Error('Policy permission or session handling failed');
      }
      await page.locator('[data-page=assets]').click();
      await page.locator('#devices button').first().waitFor({ state: 'visible' });
      await page.locator('#search').fill(process.env.ENDPOINTAI_TEST_EMPLOYEE);
      const searched = page.waitForResponse(r => r.url().includes('/analytics/devices?') && new URL(r.url()).searchParams.get('search') === process.env.ENDPOINTAI_TEST_EMPLOYEE);
      await page.locator('#search').press('Enter');
      if (!(await searched).ok()) throw new Error('Indexed employee search failed');
      await page.locator('#devices button').first().waitFor({ state: 'visible' });
      if (!(await page.locator('#devices').innerText()).includes(process.env.ENDPOINTAI_TEST_EMPLOYEE)) throw new Error('Employee search omitted the matching device');
      if (username === 'viewer') {
        await page.setViewportSize({ width: 390, height: 844 });
        if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw new Error('Mobile asset list overflows the page');
        if (process.env.ENDPOINTAI_VISUAL_OUTPUT) await page.screenshot({ path: path.join(process.env.ENDPOINTAI_VISUAL_OUTPUT, 'mobile-assets-populated.png'), fullPage: true });
      }
      await page.locator('#devices button').first().click();
      if (username === 'viewer') {
        await page.locator('#detailView').waitFor({ state: 'visible', timeout: 15000 });
        if (!await page.locator('#disableProxy').isDisabled() || !await page.locator('#enableProxy').isDisabled()) throw new Error('Viewer can operate command buttons');
        await page.waitForFunction(() => document.querySelector('#devicePolicyState').textContent.includes('全局 v'));
        if (!await page.locator('#saveDevicePolicy').isDisabled()) throw new Error('Viewer can submit device policy');
        if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw new Error('Mobile device detail overflows the page');
        if (process.env.ENDPOINTAI_VISUAL_OUTPUT) await page.screenshot({ path: path.join(process.env.ENDPOINTAI_VISUAL_OUTPUT, 'mobile-detail-populated.png'), fullPage: true });
        await page.setViewportSize({ width: 1440, height: 1000 });
        if (await page.locator('#recoverCredential').isVisible()) throw new Error('Viewer can see recovery action');
      } else if (username === 'operator') {
        await page.locator('#detailView').waitFor({ state: 'visible', timeout: 15000 });
        await page.waitForFunction(() => document.querySelector('#devicePolicyState').textContent.includes('全局 v'));
        if (await page.locator('#disableProxy').isDisabled()) throw new Error('Operator cannot operate command buttons');
        if (!await page.locator('#saveDevicePolicy').isDisabled() || await page.locator('#recoverCredential').isVisible()) throw new Error('Operator can mutate device policy or recover credentials');
      } else {
        const timingWarnings = [];
        page.on('dialog', async dialog => {
          if (dialog.type() === 'prompt') await dialog.accept(dialog.message().includes('主机名') ? process.env.ENDPOINTAI_TEST_HOSTNAME : 'synthetic test');
          else if (dialog.message().includes('120 秒')) { timingWarnings.push(dialog.message()); await dialog.dismiss(); }
          else await dialog.accept();
        });
        await page.locator('#recoverCredential').click();
        await page.locator('#recoveryDialog').waitFor({ state: 'visible', timeout: 15000 });
        const material = JSON.parse(await page.locator('#recoveryMaterial').inputValue());
        if (!material.deviceId || !material.deviceToken) throw new Error('Recovery material incomplete');
        await page.locator('#closeRecovery').click();
        if (await page.locator('#recoveryMaterial').inputValue()) throw new Error('Recovery material not cleared');
        await page.locator('[data-page=policy]').click();
        await page.locator('#gatewayTab').click();
        await page.locator('#heartbeatInterval').fill('120');
        if (!await page.locator('#gatewayExplanation').innerText().then(text => text.includes('120 秒'))) throw new Error('Timing warning missing');
        await page.locator('#savePolicy').click();
        if (timingWarnings.length !== 1 || !await page.locator('#policyDirty').innerText().then(text => text.includes('未保存'))) throw new Error('Timing warning cancellation failed');
      }
      await page.locator('[data-page=rollouts]').click();
      if (username === 'viewer') {
        if (!await page.locator('#createRollout').isDisabled()) throw new Error('Viewer can create a rollout');
        if (!(await page.locator('#rolloutAccess').innerText()).includes('操作员或管理员')) throw new Error('Command batch permission explanation missing');
        if (!(await page.locator('#policyBatchAccess').innerText()).includes('管理员权限')) throw new Error('Policy batch permission explanation missing');
        if (process.env.ENDPOINTAI_VISUAL_OUTPUT) {
          await page.screenshot({ path: path.join(process.env.ENDPOINTAI_VISUAL_OUTPUT, 'desktop-rollouts-readonly.png'), fullPage: true });
          await page.setViewportSize({ width: 390, height: 844 });
          if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw new Error('Read-only batch page overflows');
          await page.screenshot({ path: path.join(process.env.ENDPOINTAI_VISUAL_OUTPUT, 'mobile-rollouts-readonly.png'), fullPage: true });
          await page.setViewportSize({ width: 1440, height: 1000 });
        }
      } else if (username === 'operator') {
        if (await page.locator('#createRollout').isDisabled()) throw new Error('Operator cannot create command rollouts');
        if (!await page.locator('#policyBatchCreate').isDisabled()) throw new Error('Operator can create policy rollouts');
        if (!(await page.locator('#policyBatchAccess').innerText()).includes('管理员权限')) throw new Error('Operator policy batch explanation missing');
      } else {
        await page.locator('#rolloutDevices').fill(process.env.ENDPOINTAI_TEST_DEVICE);
        await page.locator('#rolloutReason').fill('synthetic batch');
        await page.locator('#createRollout').click();
        await page.locator('#rolloutTitle').waitFor({ state: 'visible', timeout: 15000 });
        await page.locator('#resumeRollout').click();
        await page.waitForFunction(() => document.querySelector('#rolloutTitle').textContent.includes('running'));
        await page.locator('#pauseRollout').click();
        await page.waitForFunction(() => document.querySelector('#rolloutTitle').textContent.includes('paused'));
        const filtered = page.waitForResponse(r => r.url().includes('/admin/v1/rollouts/') && r.url().includes('state=pending'));
        await page.locator('#rolloutFilter').selectOption('pending');
        if (!(await filtered).ok()) throw new Error('Batch filter request failed');
        await page.waitForFunction(id => document.querySelector('#rolloutTargets').textContent.includes(id), process.env.ENDPOINTAI_TEST_DEVICE);
      }
      if (errors.length) throw new Error('Browser errors: ' + errors.join('; '));
      await page.locator('#signOut').click();
      await page.locator('#authView').waitFor({ state: 'visible', timeout: 15000 });
      if (await page.locator('#appShell').isVisible() || await page.locator('#token').inputValue() || await page.locator('#actor').inputValue()) throw new Error('Sign-out retained visible session state');
      if (await page.evaluate(() => sessionStorage.getItem('sf-admin-token') || sessionStorage.getItem('sf-local-actor'))) throw new Error('Sign-out retained stored session state');
      await context.close();
    }
  } finally {
    await browser.close();
  }
})().catch(error => { process.stderr.write(String(error.stack || error)); process.exitCode = 1; });
