const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const reportPath = path.resolve(process.env.REPORT_PATH || 'dist/assessment.html');

test.beforeEach(async ({ page }) => {
  if (!fs.existsSync(reportPath)) {
    throw new Error(`Relatório não encontrado: ${reportPath}. Gere dist/assessment.html antes do E2E.`);
  }
  await page.goto(`file://${reportPath}`);
});

test('abre o relatório e exibe as áreas críticas', async ({ page }) => {
  await expect(page).toHaveTitle(/Security & Governance Assessment/);
  await expect(page.locator('header')).toContainText('SoftwareOne');
  for (const id of ['executive-summary', 'coverage', 'inventory-overview', 'risks', 'discovery', 'transparency']) {
    await expect(page.locator(`#${id}`)).toBeVisible();
  }
  expect(await page.locator('table').count()).toBeGreaterThan(0);
});

test('filtro de discovery funciona sem quebrar a página', async ({ page }) => {
  const input = page.locator('#discoverySearch');
  await expect(input).toBeVisible();
  await input.fill('texto-que-nao-existe-no-discovery');
  await expect(page.locator('#discoveryCount')).toContainText('0 de');
  await input.fill('');
  await expect(page.locator('#discoveryCount')).not.toContainText('0 de');
});

test('painéis técnicos começam compactos e podem ser expandidos', async ({ page }) => {
  const panels = page.locator('#discovery > .panel');
  const count = await panels.count();
  expect(count).toBeGreaterThan(1);
  await expect(panels.nth(1)).toHaveClass(/collapsed/);
  await panels.nth(1).locator('h3').click();
  await expect(panels.nth(1)).not.toHaveClass(/collapsed/);
});

test('é responsivo e preparado para impressão', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator('header h1')).toBeVisible();
  await page.emulateMedia({ media: 'print' });
  await expect(page.locator('main')).toBeVisible();
});

test('não produz erro JavaScript no carregamento', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.reload();
  expect(errors).toEqual([]);
});

test('mantém requisitos básicos de acessibilidade', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('lang', 'pt-BR');
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.locator('input#discoverySearch')).toHaveAttribute('aria-label', /.+/);
  await expect(page.locator('button')).toHaveCount(2);
  await expect(page.locator('nav a').first()).toBeVisible();
});

test('gera snapshots de referência para revisão visual', async ({ page }, testInfo) => {
  const directory = path.resolve('runtime/playwright-screenshots');
  fs.mkdirSync(directory, { recursive: true });
  await page.screenshot({ path: path.join(directory, `${testInfo.project.name}-desktop.png`), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(directory, `${testInfo.project.name}-mobile.png`), fullPage: true });
  expect(fs.existsSync(path.join(directory, `${testInfo.project.name}-desktop.png`))).toBeTruthy();
  expect(fs.existsSync(path.join(directory, `${testInfo.project.name}-mobile.png`))).toBeTruthy();
});
