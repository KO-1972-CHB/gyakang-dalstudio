import {NextResponse} from 'next/server';
import {createHmac,timingSafeEqual,randomBytes} from 'node:crypto';
export const runtime='nodejs';
const cookieName='gyakang_session';
function equal(a,b){const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y)}
export async function POST(req){const pass=process.env.DALSTUDIO_PASSWORD,secret=process.env.DALSTUDIO_SESSION_SECRET;
if(!pass||!secret||secret.length<32)return NextResponse.json({error:'Server configuration missing'},{status:503});
const origin=req.headers.get('origin');if(origin&&new URL(origin).host!==req.headers.get('host'))return NextResponse.json({error:'Forbidden'},{status:403});
let body;try{body=await req.json()}catch{return NextResponse.json({error:'Invalid request'},{status:400})}
if(typeof body.password!=='string'||body.password.length>1024||!equal(body.password,pass))return NextResponse.json({error:'Invalid credentials'},{status:401});
const expires=Math.floor(Date.now()/1000)+60*60*12;const payload=`${expires}.${randomBytes(16).toString('hex')}`;const signature=createHmac('sha256',secret).update(payload).digest('base64url');
const res=NextResponse.json({ok:true});res.cookies.set(cookieName,`${payload}.${signature}`,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'strict',path:'/',maxAge:60*60*12});res.headers.set('Cache-Control','no-store');return res;
}