/** SYNTERX Stripe signed webhook, separate server function. */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { bridge } from './api.mjs';

const result = (status, message) => new Response(JSON.stringify({ok:status<400,message}),{
  status,headers:{'content-type':'application/json','cache-control':'no-store'}
});

function verifyStripe(raw, header, secret) {
  const elements=Object.fromEntries(String(header||'').split(',').map(x=>x.trim().split('=',2)));
  const timestamp=Number(elements.t);
  const signatures=String(header||'').split(',').map(x=>x.trim()).filter(x=>x.startsWith('v1=')).map(x=>x.slice(3));
  if(!Number.isSafeInteger(timestamp)||Math.abs(Date.now()/1000-timestamp)>300) return false;
  const expected=createHmac('sha256',secret).update(`${timestamp}.${raw}`).digest('hex');
  return signatures.some(signature=>{
    if(!/^[a-f0-9]{64}$/i.test(signature))return false;
    return timingSafeEqual(Buffer.from(expected,'hex'),Buffer.from(signature,'hex'));
  });
}
function normalizeLink(value) {
  try {const u=new URL(String(value));return u.origin.toLowerCase()+u.pathname.replace(/\/$/,'')}
  catch{return ''}
}
async function stripePaymentLinkUrl(id) {
  if(!/^plink_[A-Za-z0-9]+$/.test(String(id||'')))throw Error('Not a Payment Link checkout');
  const key=process.env.STRIPE_SECRET_KEY;
  if(!key)throw Error('STRIPE_SECRET_KEY missing');
  const r=await fetch('https://api.stripe.com/v1/payment_links/'+encodeURIComponent(id),{
    headers:{authorization:'Bearer '+key}
  });
  if(!r.ok)throw Error('Stripe Payment Link verification failed');
  const link=await r.json();
  return link.url;
}
export default async function(req) {
  if(req.method!=='POST')return result(405,'POST only');
  const secret=process.env.STRIPE_WEBHOOK_SECRET;
  if(!secret)return result(500,'Webhook secret not configured');
  const raw=await req.text();
  if(!verifyStripe(raw,req.headers.get('stripe-signature'),secret))return result(400,'Invalid Stripe signature');
  let evt;
  try{evt=JSON.parse(raw)}catch{return result(400,'Invalid event JSON')}
  if(!['checkout.session.completed','checkout.session.async_payment_succeeded'].includes(evt.type)) {
    return result(200,'Not a payment confirmation event');
  }
  const session=evt.data?.object;
  if(session?.object!=='checkout.session'||session.payment_status!=='paid'||session.mode!=='payment'){
    return result(200,'Awaiting successful payment');
  }
  const orderId=String(session.client_reference_id||'');
  if(!/^[a-f0-9-]{36}$/i.test(orderId))return result(200,'Checkout not from SYNTERX');
  try {
    const order=await bridge('getOrderForPayment',{orderId});
    if(!order)return result(200,'Unknown order');
    if(session.currency!=='huf'||Number(session.amount_total)!==Number(order.amountHuf)) {
      return result(200,'Order amount/currency mismatch');
    }
    const actualLink=await stripePaymentLinkUrl(session.payment_link);
    if(!normalizeLink(actualLink)||normalizeLink(actualLink)!==normalizeLink(order.stripePaymentLinkUrl)){
      return result(200,'Payment Link mismatch');
    }
    await bridge('markOrderPaid',{
      orderId,sessionId:String(session.id),eventId:String(evt.id),
      paymentEmail:String(session.customer_details?.email||'').slice(0,254)
    });
    return result(200,'Verified paid order');
  }catch(e){
    console.error('Stripe webhook processing failed:',String(e.message||e));
    // Stripe will retry on errors. Do not claim success when Google Sheets wasn't updated.
    return result(500,'Could not process event');
  }
}
