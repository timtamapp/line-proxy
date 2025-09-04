// CommonJS (no "type":"module")
const express = require('express');
const getRawBody = require('raw-body');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');

// small helpers
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const log = (...args) => console.log(new Date().toISOString(), ...args);

// pick a few harmless headers for debugging (avoid secrets)
const pickDebugHeaders = (h = {}) => {
  const keys = ['user-agent', 'content-type', 'x-forwarded-for', 'x-line-signature'];
  const out = {};
  for (const k of keys) if (h[k]) out[k] = h[k];
  return out;
};

// get best-effort client ip
const clientIp = (req) => (req.headers['x-forwarded-for'] || '').split(',')[0]?.trim() || req.ip || 'unknown';

// simple pages for humans/health checks
app.get('/', (req, res) => res.type('text/plain').send('LINE proxy is alive'));
app.get('/healthz', (req, res) => res.type('text/plain').send('ok'));
app.get('/line/webhook', (req, res) => res.type('text/plain').send('Use POST /line/webhook'));

// LINE → proxy → Apps Script
app.post('/line/webhook', async (req, res) => {
  try {
    // 1) read raw body (required for signature verification)
    const raw = (await getRawBody(req)).toString('utf8');

    // 2) verify LINE signature against raw body
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

    // Build a richer payload for GAS (Option A: GAS logs to Debug sheet)
    const debugMeta = {
      proxyReceivedAt: new Date().toISOString(),
      clientIp: clientIp(req),
      headers: pickDebugHeaders(req.headers),
      // keep this minimal; raw is already included separately
      note: 'Forwarded by Cloud Run proxy with debug metadata for GAS logging',
    };

    // The payload GAS will receive (GAS should verify HMAC against this exact body)
    const payloadObj = {
      rawBody: raw, // original LINE webhook JSON string
      debug: debugMeta
    };
    const payload = JSON.stringify(payloadObj);

    // HMAC over payload + "|" + ts  (GAS must reproduce this)
    const ts = Math.floor(Date.now() / 1000).toString();
    const fSig = crypto.createHmac('sha256', forwardSecret).update(payload + '|' + ts).digest('base64');

    // Abort if Apps Script is slow; LINE already got 200
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 3000); // 3s cap

    try {
      const url = `${appsScriptUrl}?ts=${encodeURIComponent(ts)}&sig=${encodeURIComponent(fSig)}`;
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: payload,
        signal: controller.signal
      });
      const text = await resp.text();
      log('forwarded -> Apps Script', resp.status, text.slice(0, 200));
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
