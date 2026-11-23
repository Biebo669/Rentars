import { defineConfig, devices } from '@playwright/test';

// Cross-browser coverage (firefox/webkit) is expensive and flaky-prone, so it
// only runs in the scheduled matrix job (or when explicitly requested) rather
// than on every pull request.
const fullMatrix = !!process.env.PLAYWRIGHT_FULL_MATRIX;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI
    ? [['html', { open: 'never' }], ['github']]
    : [['html', { open: 'on-failure' }]],
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3001',
    // Capture diagnostics on failure so regressions can be diagnosed from CI
    // artifacts alone.
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  // Visual regression snapshots are stored adjacent to each spec file so that
  // baselines are versioned in Git alongside the tests that reference them.
  snapshotPathTemplate: '{testDir}/{testFilePath}-snapshots/{arg}{ext}',
  // Tolerances for snapshot comparisons — overridden per-test where needed.
  expect: {
    toHaveScreenshot: {
      // Ignore anti-aliasing differences between platforms
      threshold: 0.2,
    },
  },
  projects: [
    // Required CI coverage: Chromium desktop + mobile viewports.
    {
      name: 'chromium-desktop',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'chromium-mobile',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'chromium-mobile-ios',
      use: { ...devices['iPhone 13'] },
    },
    // Cross-browser coverage runs only in the scheduled matrix job.
    ...(fullMatrix
      ? [
          {
            name: 'firefox',
            use: { ...devices['Desktop Firefox'] },
          },
          {
            name: 'webkit',
            use: { ...devices['Desktop Safari'] },
          },
        ]
      : []),
  ],
  webServer: {
    command: process.env.CI ? 'yarn start' : 'yarn dev',
    url: 'http://localhost:3001',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      PORT: '3001',
    },
  },
});
