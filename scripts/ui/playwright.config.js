// Browser lane config: one Chromium project, the page server on loopback, screenshots kept.
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: 'pages.spec.js',
  outputDir: '/work/test-results',
  reporter: [['list']],
  retries: 0,
  // One worker, in order: the page server has one clock, which tests move forward (POST /test/advance).
  workers: 1,
  fullyParallel: false,
  use: { baseURL: 'http://127.0.0.1:9440', browserName: 'chromium' },
  webServer: {
    command: '/work/pageserver -listen 127.0.0.1:9440',
    url: 'http://127.0.0.1:9440/assets/page.css',
    reuseExistingServer: false,
    timeout: 10000,
  },
});
