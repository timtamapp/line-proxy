// CommonJS (no "type":"module")
const express = require('express');
const getRawBody = require('raw-body');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');

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
    if (!channelSecret) return res.status(500).send('Missing LINE_CHANNEL_SECRET');

    const calc = crypto.createHmac('sha256', channelSecret).update(raw).digest('base64');
    const safeEq = (a, b) =>
      a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    if (!sig || !safeEq(calc, sig)) return res.status(403).send('bad signature');

    // 3) forward to Apps Script with our own HMAC
    const appsScriptUrl = process.env.APPS_SCRIPT_URL;
    const forwardSecret = process.env.FORWARD_SHARED_SECRET || '';
    if (!appsScriptUrl || !forwardSecret) return res.status(500).send('Missing config');

    const ts = Math.floor(Date.now() / 1000).toString();
    const fSig = crypto.createHmac('sha256', forwardSecret).update(raw + '|' + ts).digest('base64');

    const resp = await fetch(
      `${appsScriptUrl}?ts=${encodeURIComponent(ts)}&sig=${encodeURIComponent(fSig)}`,
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: raw }
    );
    const text = await resp.text();

    return res.status(resp.status || 200).send(text);
  } catch (err) {
    console.error(err);
    return res.status(500).send('err');
  }
});

// start server
const port = process.env.PORT || 8080;
app.listen(port, () => console.log('listening on', port));
