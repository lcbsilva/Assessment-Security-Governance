const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  fullyParallel: true,
  reporter: [['list'], ['json', { outputFile: 'runtime/playwright-report.json' }]],
  use: {
    browserName: 'chromium',
    headless: true,
    colorScheme: 'light',
    locale: 'pt-BR',
  },
});
