// Drives the real upload page in headless Chromium: types a username,
// chooses a file and waits for the row to reach the expected state.
// Usage: node browser-upload.mjs ORIGIN FILE EXPECTED_LABEL_PREFIX
import { chromium } from "playwright";

const [origin, file, expected] = process.argv.slice(2);
const browser = await chromium.launch();
const page = await browser.newPage({ ignoreHTTPSErrors: true });
page.on("console", (m) => console.log("console:", m.text()));
page.on("response", (r) => { if (r.status() >= 400) console.log("HTTP", r.status(), r.request().method(), r.url()); });
await page.goto(origin + "/");
await page.fill("#username", "browserci");
await page.setInputFiles("#file-input", file);
await page.click("#upload-btn");
const state = page.locator("#file-list .file-state").first();
let last = "";
const deadline = Date.now() + 15 * 60 * 1000;
while (Date.now() < deadline) {
  const t = (await state.textContent()) || "";
  if (t !== last && !/^Uploading \d+%$/.test(t)) console.log("state:", t);
  last = t;
  if (t.startsWith(expected)) { await browser.close(); process.exit(0); }
  if (/^(Failed|Upload failed|Cancelled)/i.test(t)) break;
  await page.waitForTimeout(1000);
}
console.log("final state:", last);
await browser.close();
process.exit(1);
