// cloud-run-proxy/index.js  (CommonJS)
const express = require('express');
const getRawBody = require('raw-body');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');

// Simple pages (handy for browser + health checks)
app.get('/', (req, res) => res.status(200).send('LINE proxy is alive'));
app.get('/healthz', (req, res) => res.status(200).send('ok'));

// LINE webhook → verify X-Line-Signature → forward to Apps Script with our HMAC
app.post('/line/webhook', async (req, res) => {
  try {
    // 1) Read raw body (needed for signature verification)
    const raw = (await getRawBody(req)).toString('utf8');

    // 2) Verify LINE signature
    const sig = req.header('x-line-signature') || '';
    const channelSecret = process.env.LINE_CHANNEL_SECRET || '';
    if (!channelSecret) {
      console.error('Missing LINE_CHANNEL_SECRET');
      return res.status(500).send('Missing secret');
    }
    const calc = crypto.createHmac('sha256', channelSecret).update(raw).digest('base64');
    const safeEq = (a, b) =>
      a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    if (!sig || !safeEq(calc, sig)) return res.status(403).send('bad signature');

    // 3) Forward to Apps Script with our own HMAC
    const forwardSecret = process.env.FORWARD_SHARED_SECRET || '';
    if (!forwardSecret) {
      console.error('Missing FORWARD_SHARED_SECRET');
      return res.status(500).send('Missing forward secret');
    }
    const ts =
