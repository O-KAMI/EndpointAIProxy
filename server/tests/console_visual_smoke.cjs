// Visual smoke test of static console shells only; no authentication or API is exercised.
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

(async () => {
  const source = fs.readFileSync(path.join(__dirname, '../controlserver/templates/console.html'), 'utf8');
  const output = process.env.ENDPOINTAI_VISUAL_OUTPUT;
  if (!output || !process.env.ENDPOINTAI_TEST_BROWSER_EXECUTABLE) throw Error('Explicit output directory and browser executable required');
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, executablePath: process.env.ENDPOINTAI_TEST_BROWSER_EXECUTABLE });
  try {
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844]]) {
      const page = await browser.newPage({ viewport: { width, height } });
      await page.route('**/*', route => route.abort());
      await page.setContent(source, { waitUntil: 'load' });
      for (const view of ['auth', 'analytics', 'policy', 'assets', 'rollouts']) {
        await page.evaluate(view => {
          document.querySelector('#authView').classList.toggle('hidden', view !== 'auth');
          document.querySelector('#appShell').classList.toggle('hidden', view === 'auth');
          for (const button of document.querySelectorAll('#mainNav [data-page]')) {
            if (button.dataset.page === view) button.setAttribute('aria-current', 'page');
            else button.removeAttribute('aria-current');
          }
          const views = { analytics: 'analyticsView', policy: 'policyView', assets: 'listView', rollouts: 'rolloutView' };
          for (const [name, id] of Object.entries(views)) {
            const target = document.getElementById(id);
            if (!target) throw Error('Missing view: ' + name);
            target.classList.toggle('hidden', name !== view);
          }
        }, view);
        const overflow = await page.evaluate(() => ({ document: document.documentElement.scrollWidth, viewport: innerWidth }));
        if (overflow.document > overflow.viewport) throw Error(`${name}/${view}: horizontal page overflow ${JSON.stringify(overflow)}`);
        if (name === 'desktop' && view === 'auth') {
          const heading = await page.locator('.auth-card h1').evaluate(el => ({ height: el.getBoundingClientRect().height, lineHeight: parseFloat(getComputedStyle(el).lineHeight) }));
          if (heading.height > heading.lineHeight + 1) throw Error('Desktop login title wraps');
        }
        await page.screenshot({ path: path.join(output, `${name}-${view}.png`), fullPage: true });
      }
      await page.close();
    }
    console.log('Ten static console shell screenshots captured without horizontal page overflow.');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
