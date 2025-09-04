// CommonJS (no "type":"module")
const express = require('express');
const getRawBody = require('raw-body');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');

// helpers
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const log = (...args) => console.log(new Date().toISOString(), ...args);

// pick non-sensitive headers for debug
const pickDebugHeaders = (h = {}) => {
  const keys = ['user-agent', 'content-type', 'x-forwarded-for', 'x-line-signature'];
  const out = {};
  for (const k of keys) if (h[k]) out[k] = h[k];
  return out;
};
const clientIp = (req) => (req.headers['x-forwarded-for'] || '').split(',')[0]?.trim() || req.ip || 'unknown';

// human/health
app.get('/',        (req, res) => res.type('text/plain').send('LINE proxy is alive'));
app.get('/healthz', (req, res) => res.type('text/plain').send('ok'));
app.get('/line/webhook', (req, res) => res.type('text/plain').send('Use POST /line/webhook'));

// LINE → proxy → Apps Script
app.post('/line/webhook', async (req, res) => {
  try {
    // 1) raw body (needed for signature verify)
    const raw = (await getRawBody(req, { encoding: 'utf8' }));
    log('recv webhook bytes=', Buffer.byteLength(raw, 'utf8'));

    // 2) verify LINE signature
    const sig = req.header('x-line-signature') || '';
    const channelSecret = process.env.LINE_CHANNEL_SECRET || '';
    if (!channelSecret) {
      log('ERR missing LINE_CHANNEL_SECRET');
      return res.status(500).send('Missing secret');
    }
    const calc = crypto.createHmac('sha256', channelSecret).update(raw).digest('base64');
    if (!sig || !safeEq(calc, sig)) {
      log('WARN bad signature from LINE');
      return res.status(403).send('bad signature');
    }

    // 3) reply to LINE ASAP
    res.status(200).send('ok');

    // 4) forward to Apps Script with our own HMAC (strict verify will happen in GAS)
    const appsScriptUrl = process.env.APPS_SCRIPT_URL;
    const forwardSecret = process.env.FORWARD_SHARED_SECRET || '';
    if (!appsScriptUrl || !forwardSecret) {
      return log('ERR missing APPS_SCRIPT_URL or FORWARD_SHARED_SECRET');
    }

    // Build envelope payload for GAS (Option A)
    const debugMeta = {
      version: 'cloudrun-v1.2',
      proxyReceivedAt: new Date().toISOString(),
      clientIp: clientIp(req),
      headers: pickDebugHeaders(req.headers),
    };
    const payloadObj = { rawBody: raw, debug: debugMeta };
    const payload = JSON.stringify(payloadObj);

    // HMAC over payload + "|" + ts
    const ts = Math.floor(Date.now() / 1000).toString();
    const hmacInput = payload + '|' + ts;
    const fSig = crypto.createHmac('sha256', forwardSecret).update(hmacInput).digest('base64');

    // TEMP: longer timeout to avoid GAS cold starts while debugging
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 8000);

    try {
      // TEMP: add dbg=1 so GAS can log pre-verify ping
      const url = `${appsScriptUrl}?ts=${encodeURIComponent(ts)}&sig=${encodeURIComponent(fSig)}&dbg=1`;

      // helpful diagnostics
      log('forward url=', url);
      log('HMAC input preview=', hmacInput.slice(0, 160));

      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: payload,
        signal: controller.signal
      });

      const text = await resp.text();
      log('forwarded -> Apps Script status=', resp.status, 'bodyPreview=', text.slice(0, 200));
    } catch (e) {
      log('ERR forward failed', String(e));
    } finally {
      clearTimeout(t);
    }
  } catch (err) {
    log('ERR handler', err?.stack || String(err));
    if (!res.headersSent) res.status(500).send('err');
  }
});

// start
const port = process.env.PORT || 8080;
app.listen(port, () => log('listening on', port));
