mport express from 'express';
import getRawBody from 'raw-body';
import crypto from 'crypto';


const app = express();
app.post('/line/webhook', async (req, res) => {
try {
const raw = (await getRawBody(req)).toString('utf8');
const sig = req.header('x-line-signature') || '';
const secret = process.env.LINE_CHANNEL_SECRET || '';
if (!secret) return res.status(500).send('Missing secret');


const h = crypto.createHmac('sha256', secret).update(raw).digest('base64');
const safeEq = (a,b)=> a.length===b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
if (!sig || !safeEq(h, sig)) return res.status(403).send('bad signature');


// Forward to Apps Script with our own HMAC
const ts = Math.floor(Date.now()/1000).toString();
const forwardSecret = process.env.FORWARD_SHARED_SECRET || '';
const fSig = crypto.createHmac('sha256', forwardSecret).update(raw + '|' + ts).digest('base64');
const url = process.env.APPS_SCRIPT_URL; // e.g. https://script.google.com/macros/s/XXX/exec


const resp = await fetch(`${url}?ts=${encodeURIComponent(ts)}&sig=${encodeURIComponent(fSig)}`, {
method: 'POST', headers: { 'content-type': 'application/json' }, body: raw,
});
const text = await resp.text();
return res.status(200).send(text);
} catch (e){
console.error(e);
return res.status(500).send('err');
}
});


app.get('/healthz', (req,res)=>res.send('ok'));


const port = process.env.PORT || 8080;
app.listen(port, ()=>console.log('listening on', port));