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
    if(session.currency!=='huf'||Number(session.amount_total)!==Number(order.amountHuf)*100) {
      return result(200,'Order amount/currency mismatch');
    }
    if(order.stripeSessionId!==session.id||session.ui_mode!=='embedded_page'||
       String(session.metadata?.order_id||'')!==orderId||
       String(session.metadata?.product_id||'')!==String(order.productId)) {
      return result(200,'Session/order mismatch');
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
