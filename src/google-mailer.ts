import { BadRequestException, Body, Controller, Get, Header, Injectable, Post, Query, Req, Res, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Schema } from 'mongoose';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { decodeJwt, EncryptJWT, jwtDecrypt, jwtVerify, createRemoteJWKSet } from 'jose';
import { SettingsService, origin } from './settings';
import { SigningService, schoolKey, publicJson } from './security';
import { persisted } from './config';
const SCOPE='https://www.googleapis.com/auth/gmail.send';
const hash=(v:string)=>createHash('sha256').update(v).digest('hex');
const googleKeys=createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'),{timeoutDuration:5000});
export const GmailOAuthStateSchema=new Schema({id:{type:String,unique:true},schoolCode:String,schoolPublicKey:String,schoolBaseUrl:String,connectId:String,encryptionPublicKey:String,returnOrigin:String,stateHash:{type:String,unique:true,sparse:true},browserHash:String,verifier:String,nonce:String,started:Boolean,consumed:Boolean,expiresAt:{type:Date,expires:0}}, {timestamps:true});
function text(v:unknown,max=2048):v is string{return typeof v==='string'&&v.length>0&&v.length<=max;}
@Injectable()
export class GoogleMailerBroker {
 constructor(@InjectModel('School') readonly schools:Model<any>,@InjectModel('Replay') readonly replays:Model<any>,@InjectModel('GmailOAuthState') readonly states:Model<any>,readonly settings:SettingsService,readonly signing:SigningService){}
 private encryptionKey(){return createPrivateKey(persisted('gmail-broker-encryption.pem',()=>generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({format:'pem',type:'pkcs8'}) as string));}
 private credentials(){const id=process.env.GOOGLE_OAUTH_CLIENT_ID?.trim(),secret=process.env.GOOGLE_OAUTH_CLIENT_SECRET?.trim();if(!id||!secret)throw new ServiceUnavailableException('Google mailer broker is not configured');return {id,secret};}
 async assertion(claims:Record<string,unknown>,audience:string){return this.signing.assertion({...claims,purpose:'gmail-broker'},audience,'5m');}
 async key(){return {assertion:await this.assertion({publicKey:createPublicKey(this.encryptionKey()).export({format:'pem',type:'spki'}) as string},'carpschool-gmail-broker')};}
 async authenticate(body:any,action:string){
  try{
   if(!body||Object.keys(body).length!==1||!text(body.assertion,32768))throw new Error();
   const unsafe=decodeJwt(body.assertion);if(!text(unsafe.iss,40)||!/^[a-z0-9-]{2,40}$/.test(unsafe.iss))throw new Error();
   const school=await this.schools.findOne({schoolCode:unsafe.iss,trusted:true,enabled:{$ne:false}}).lean<any>();if(!school?.publicKey||!school.baseUrl)throw new Error();
   const issuer=await this.settings.issuer(),p=(await jwtVerify(body.assertion,schoolKey(school.publicKey),{algorithms:['EdDSA'],issuer:school.schoolCode,audience:issuer,requiredClaims:['iat','exp','jti'],maxTokenAge:'5m'})).payload;
   if(p.action!==action||!p.jti||!p.iat||!p.exp||p.exp-p.iat>300)throw new Error();
   await this.replays.create({key:'gmail:'+school.schoolCode+':'+p.jti,expiresAt:new Date((p.exp+300)*1000)});
   return {school,p};
  }catch{throw new UnauthorizedException('Invalid school mailer request');}
 }
 async connect(body:unknown){
  const {school,p}=await this.authenticate(body,'connect');this.credentials();
  try{
   if(!text(p.connectId,64)||!/^[a-f0-9]{64}$/.test(p.connectId)||!text(p.encryptionPublicKey,5000)||!text(p.returnOrigin))throw new Error();
   const rsa=createPublicKey(p.encryptionPublicKey);if(rsa.asymmetricKeyType!=='rsa'||(rsa.asymmetricKeyDetails?.modulusLength??0)<2048)throw new Error();
   const ret=origin(p.returnOrigin,false);if(!(await this.settings.get()).corsOrigins.includes(ret))throw new Error();
   const base=origin(school.baseUrl,false),id=randomBytes(32).toString('hex');
   await this.states.create({id,schoolCode:school.schoolCode,schoolPublicKey:school.publicKey,schoolBaseUrl:base,connectId:p.connectId,encryptionPublicKey:p.encryptionPublicKey,returnOrigin:ret,started:false,consumed:false,expiresAt:new Date(Date.now()+600000)});
   return {url:new URL('/mailer/google/start?ticket='+id,await this.settings.issuer()).href};
  }catch{throw new BadRequestException('Invalid Google mailer connection');}
 }
 async start(ticket:unknown){
  if(!text(ticket,64)||!/^[a-f0-9]{64}$/.test(ticket))throw new UnauthorizedException('Invalid connection');
  const state=randomBytes(32).toString('hex'),browser=randomBytes(32).toString('hex'),verifier=randomBytes(32).toString('base64url'),nonce=randomBytes(32).toString('hex');
  const pending=await this.states.findOneAndUpdate({id:ticket,started:false,consumed:false,expiresAt:{$gt:new Date()}},{$set:{started:true,stateHash:hash(state),browserHash:hash(browser),verifier,nonce}},{new:true}).lean<any>();
  if(!pending)throw new UnauthorizedException('Invalid connection');
  const u=new URL('https://accounts.google.com/o/oauth2/v2/auth');u.search=new URLSearchParams({client_id:this.credentials().id,redirect_uri:new URL('/mailer/google/callback',await this.settings.issuer()).href,response_type:'code',scope:SCOPE+' openid email',access_type:'offline',prompt:'consent',state,nonce,code_challenge: createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'}).toString();
  return {url:u.href,cookieName:'cs_gmail_'+hash(state).slice(0,16),browser};
 }
 async exchange(fields:Record<string,string>){
  const {id,secret}=this.credentials();
  const res=await fetch('https://oauth2.googleapis.com/token',{method:'POST',redirect:'error',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({...fields,client_id:id,client_secret:secret}),signal:AbortSignal.timeout(15000)});
  if(!res.ok)throw new Error('Google token exchange failed');const data:any=await res.json();
  if(!text(data.access_token,10000)||!Number.isInteger(data.expires_in)||data.expires_in<60||data.expires_in>7200||data.token_type!=='Bearer')throw new Error('Invalid token');
  if(typeof data.scope!=='string'||!data.scope.split(' ').includes(SCOPE))throw new Error('Send scope missing');
  return data;
 }
 async bundle(schoolCode:string,publicKey:string,claims:Record<string,unknown>){
  const issuer=await this.settings.issuer();
  const encrypted=await new EncryptJWT(claims).setProtectedHeader({alg:'RSA-OAEP-256',enc:'A256GCM',typ:'JWT'}).setIssuer(issuer).setAudience(schoolCode).setIssuedAt().setExpirationTime('5m').setJti(randomUUID()).encrypt(createPublicKey(publicKey));
  return {assertion:await this.assertion({encrypted},schoolCode)};
 }
 async identity(idToken:string){return (await jwtVerify(idToken,googleKeys,{algorithms:['RS256'],issuer:['https://accounts.google.com','accounts.google.com'],audience:this.credentials().id,requiredClaims:['exp','iat','sub']})).payload;}
 async callback(q:any,cookie:string){
  if(!text(q.state,64)||!/^[a-f0-9]{64}$/.test(q.state))throw new UnauthorizedException('Invalid OAuth state');
  const name='cs_gmail_'+hash(q.state).slice(0,16),browser=cookie.split(';').map(v=>v.trim()).find(v=>v.startsWith(name+'='))?.slice(name.length+1);
  if(!browser||!/^[a-f0-9]{64}$/.test(browser))throw new UnauthorizedException('OAuth browser mismatch');
  const pending=await this.states.findOneAndUpdate({stateHash:hash(q.state),browserHash:hash(browser),started:true,consumed:false,expiresAt:{$gt:new Date()}},{$set:{consumed:true},$unset:{verifier:1}},{new:false}).lean<any>();
  if(!pending)throw new UnauthorizedException('OAuth state expired or used');
  const redirect=new URL('/admin/school',pending.returnOrigin);redirect.searchParams.set('mailer','error');
  try{
   if(q.error||!text(q.code,4096))throw new Error();
   const school=await this.schools.findOne({schoolCode:pending.schoolCode,trusted:true,enabled:{$ne:false},publicKey:pending.schoolPublicKey,baseUrl:pending.schoolBaseUrl}).lean<any>();if(!school)throw new Error();
   const data=await this.exchange({grant_type:'authorization_code',code:q.code,code_verifier:pending.verifier,redirect_uri:new URL('/mailer/google/callback',await this.settings.issuer()).href});
   if(!text(data.refresh_token,10000)||!text(data.id_token,16384))throw new Error();
   const identity=await this.identity(data.id_token);
   if(identity.nonce!==pending.nonce||identity.email_verified!==true||!text(identity.email,254)||!/^([^\s@]+)@([^\s@]+)$/.test(identity.email))throw new Error();
   const bundle=await this.bundle(pending.schoolCode,pending.encryptionPublicKey,{connectId:pending.connectId,accessToken:data.access_token,refreshToken:data.refresh_token,email:identity.email,expiresAt:Date.now()+data.expires_in*1000});
   const delivered=await publicJson(new URL('/mailer/google/callback',pending.schoolBaseUrl),bundle);if(delivered?.ok!==true)throw new Error();redirect.searchParams.set('mailer','connected');
  }catch{/* No error bodies, tokens, authorization codes or credentials are surfaced. */}
  await this.states.deleteOne({_id:pending._id});return {url:redirect.href,cookieName:name};
 }
 async refresh(body:unknown){
  const {school,p}=await this.authenticate(body,'refresh');
  try{
   if(!text(p.encrypted,32768)||!text(p.encryptionPublicKey,5000))throw new Error();
   const payload=(await jwtDecrypt(p.encrypted,this.encryptionKey(),{keyManagementAlgorithms:['RSA-OAEP-256'],contentEncryptionAlgorithms:['A256GCM'],issuer:school.schoolCode,audience:await this.settings.issuer(),requiredClaims:['iat','exp','jti'],maxTokenAge:'5m'})).payload;
   if(!text(payload.refreshToken,10000)||!text(payload.requestId,64)||payload.requestId!==p.jti)throw new Error();
   const data=await this.exchange({grant_type:'refresh_token',refresh_token:payload.refreshToken});
   return await this.bundle(school.schoolCode,p.encryptionPublicKey,{requestId:p.jti,accessToken:data.access_token,expiresAt:Date.now()+data.expires_in*1000,...(text(data.refresh_token,10000)?{refreshToken:data.refresh_token}:{})});
  }catch{throw new ServiceUnavailableException('Google mailer refresh failed');}
 }
}
@Controller('mailer/google')
export class GoogleMailerBrokerController {
 constructor(readonly broker:GoogleMailerBroker){}
 @Get('key') @Header('Cache-Control','no-store') key(){return this.broker.key();}
 @Post('connect') @Header('Cache-Control','no-store') connect(@Body() b:unknown){return this.broker.connect(b);}
 @Post('refresh') @Header('Cache-Control','no-store') refresh(@Body() b:unknown){return this.broker.refresh(b);}
 @Get('start') async start(@Query('ticket') ticket:unknown,@Res() res:any){const r=await this.broker.start(ticket);res.set({'Cache-Control':'no-store','Referrer-Policy':'no-referrer'});res.cookie(r.cookieName,r.browser,{secure:true,httpOnly:true,sameSite:'lax',maxAge:600000,path:'/mailer/google/callback'});res.redirect(303,r.url);}
 @Get('callback') async callback(@Query() q:any,@Req() req:any,@Res() res:any){const r=await this.broker.callback(q,req.headers.cookie||'');res.set({'Cache-Control':'no-store','Referrer-Policy':'no-referrer'});res.clearCookie(r.cookieName,{secure:true,httpOnly:true,sameSite:'lax',path:'/mailer/google/callback'});res.redirect(303,r.url);}
}
