// CommonJS (no "type":"module")
const express = require('express');
const getRawBody = require('raw-body');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');

// small helpers
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const log = (...args) => console.log(new Date().toISOString(), ...args);

// simple pages for humans/health checks
app.get('/', (req, res) => res.type('text/plain').send('LINE proxy is alive'));
app.get('/healthz', (req, res) => res.type('text/plain').send('ok'));
app.get('/line/webhook', (req, res) => res.type('text/plain').send('Use POST /line/webhook'));

// LINE → proxy → Apps Script
app.post('/line/webhook', async (req, res) => {
  try {
    // 1) read raw body (required for signature verification)
    const raw = (await getRawBody(req)).toString('utf8');

    // 2) verify LINE signature
    const sig = req.header('x-line-signature') || '';
    const channelSecret = process.env.LINE_CHANNEL_SECRET || '';
    if (!channelSecret) {
      log('ERR missing LINE_CHANNEL_SECRET');
      return res.status(500).send('Missing secret');
    }
    const calc = crypto.createHmac('sha256', channelSecret).update(raw).digest('base64');
    if (!sig || !safeEq(calc, sig)) {
      log('WARN bad signature');
      return res.status(403).send('bad signature');
    }

    // 3) respond to LINE immediately (important to avoid timeouts)
    res.status(200).send('ok');

    // 4) forward to Apps Script with our own HMAC (fire-and-forget with timeout)
    const appsScriptUrl = process.env.APPS_SCRIPT_URL;
    const forwardSecret = process.env.FORWARD_SHARED_SECRET || '';
    if (!appsScriptUrl || !forwardSecret) {
      return log('ERR missing APPS_SCRIPT_URL or FORWARD_SHARED_SECRET');
    }

    const ts = Math.floor(Date.now() / 1000).toString();
    const fSig = crypto.createHmac('sha256', forwardSecret).update(raw + '|' + ts).digest('base64');

    // Abort if Apps Script is slow; LINE already got 200
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 3000); // 3s cap
    try {
      const resp = await fetch(
        `${appsScriptUrl}?ts=${encodeURIComponent(ts)}&sig=${encodeURIComponent(fSig)}`,
        { method: 'POST', headers: { 'content-type': 'application/json' }, body: raw, signal: controller.signal }
      );
      const text = await resp.text();
      log('forwarded -> Apps Script', resp.status, text.slice(0, 120));
    } catch (e) {
      log('ERR forward failed', String(e));
    } finally {
      clearTimeout(t);
    }
  } catch (err) {
    log('ERR handler', err?.stack || String(err));
    // If we reach here before replying, be sure to end the request
    if (!res.headersSent) res.status(500).send('err');
  }
});

// start server
const port = process.env.PORT || 8080;
app.listen(port, () => log('listening on', port));
