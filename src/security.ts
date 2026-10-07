import { BadRequestException, Injectable, OnModuleInit } from '@nestjs/common';
import { createPrivateKey, createPublicKey, randomUUID, verify } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import * as ipaddr from 'ipaddr.js';
import { exportJWK, SignJWT } from 'jose';
import { required } from './config';

export function publicAddress(address: string): boolean {
  try { const ip = ipaddr.process(address); return ip.range() === 'unicast'; } catch { return false; }
}
export function schoolKey(pem: string) {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== 'ed25519') throw new BadRequestException('School key must be Ed25519 SPKI PEM');
  return key;
}
export function validSignature(pem: string, data: string, signature: string) {
  try { return verify(null, Buffer.from(data), schoolKey(pem), Buffer.from(signature, 'base64')); } catch { return false; }
}
// Resolve once, reject EVERY non-public result and pin the TLS socket to that address.
// No redirects, proxy environment variables, or second DNS resolution are allowed.
export async function publicJson(url: URL): Promise<any> {
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) throw new BadRequestException('Public HTTPS on port 443 required');
  const addresses = await lookup(url.hostname, { all: true });
  if (!addresses.length || addresses.some(a => !publicAddress(a.address))) throw new BadRequestException('Private/reserved host rejected');
  const pinned = addresses[0];
  return new Promise((resolve, reject) => {
    const req = request(url, { method: 'GET', agent: false, lookup: (_host, _opts, cb: any) => cb(null, pinned.address, pinned.family), headers: { Accept: 'application/json' } }, res => {
      if (res.statusCode !== 200) { res.resume(); reject(new BadRequestException('Metadata request failed')); return; }
      let size = 0; const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 65536) { req.destroy(new Error('Response too large')); return; } chunks.push(chunk); });
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch { reject(new BadRequestException('Invalid JSON')); } });
      res.on('error', reject);
    });
    const deadline = setTimeout(() => req.destroy(new Error('HTTPS deadline exceeded')), 5000);
    req.on('close', () => clearTimeout(deadline)); req.on('error', () => reject(new BadRequestException('School HTTPS unavailable'))); req.end();
  });
}
@Injectable()
export class SigningService implements OnModuleInit {
  private key: ReturnType<typeof createPrivateKey>;
  private jwk: any;
  async onModuleInit() {
    const path = required('SIGNING_KEY_FILE');
    if ((statSync(path).mode & 0o077) !== 0) throw new Error('Signing key file must be owner-only (chmod 600)');
    this.key = createPrivateKey(readFileSync(path));
    if (this.key.asymmetricKeyType !== 'ed25519') throw new Error('Signing key must be Ed25519 PKCS8 PEM');
    this.jwk = { ...await exportJWK(createPublicKey(this.key)), kid: required('SIGNING_KEY_ID'), alg: 'EdDSA', use: 'sig' };
  }
  jwks() { return { keys: [this.jwk] }; }
  async issue(sub: string, schoolCode: string, schoolAdmin: boolean, avatar: string, name: string) {
    const ticket = await new SignJWT({ schoolAdmin, avatar, name }).setProtectedHeader({ alg: 'EdDSA', kid: required('SIGNING_KEY_ID'), typ: 'JWT' }).setSubject(sub).setAudience(schoolCode).setIssuer(required('CENTRAL_ISSUER')).setIssuedAt().setExpirationTime('15m').setJti(randomUUID()).sign(this.key);
    return { ticket, expiresIn: 900 };
  }
}
