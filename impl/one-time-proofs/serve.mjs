import { createAS, listen } from './server.mjs';
const dir = new URL('.', import.meta.url).pathname;
const as = createAS();
const srv = await listen(as, { port: Number(process.env.PORT ?? 8787), staticFiles: {
  '/': [dir + 'browser.html', 'text/html'],
  '/client.mjs': [dir + 'client.mjs', 'text/javascript'],
  '/stats': [dir + 'stats.json', 'application/json'],
}});
import { writeFileSync } from 'node:fs';
setInterval(() => writeFileSync(dir + 'stats.json', JSON.stringify(as.stats)), 50);
console.log(srv.url);
