import { BadRequestException, Injectable, OnModuleInit } from "@nestjs/common";
import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  verify,
} from "node:crypto";
import { generateKeyPairSync } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request } from "node:https";
import * as ipaddr from "ipaddr.js";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { persisted } from "./config";
import { SettingsService } from "./settings";

export function publicAddress(address: string): boolean {
  try {
    const ip = ipaddr.process(address);
    return ip.range() === "unicast";
  } catch {
    return false;
  }
}
export function schoolKey(pem: string) {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ed25519")
    throw new BadRequestException("School key must be Ed25519 SPKI PEM");
  return key;
}
export function validSignature(pem: string, data: string, signature: string) {
  try {
    return verify(
      null,
      Buffer.from(data),
      schoolKey(pem),
      Buffer.from(signature, "base64"),
    );
  } catch {
    return false;
  }
}
// Resolve once, reject EVERY non-public result and pin the TLS socket to that address.
// No redirects, proxy environment variables, or second DNS resolution are allowed.
export async function publicJson(url: URL, body?: unknown): Promise<any> {
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    (url.port && url.port !== "443")
  )
    throw new BadRequestException("Public HTTPS on port 443 required");
  const addresses = await lookup(url.hostname, { all: true });
  if (!addresses.length || addresses.some((a) => !publicAddress(a.address)))
    throw new BadRequestException("Private/reserved host rejected");
  const pinned = addresses[0];
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      {
        method: payload ? "POST" : "GET",
        agent: false,
        lookup: (_host, opts: any, cb: any) =>
          opts?.all ? cb(null, [pinned]) : cb(null, pinned.address, pinned.family),
        headers: payload
          ? { Accept: "application/json", "Content-Type": "application/json", "Content-Length": payload.length }
          : { Accept: "application/json" },
      },
      (res) => {
        if (res.statusCode !== 200 && !(payload && res.statusCode === 201)) {
          let text = "";
          res.on("data", (c: Buffer) => { if (text.length < 2000) text += c; });
          res.on("end", () => {
            let msg = "School request failed (" + res.statusCode + ")";
            try { const m = JSON.parse(text).message; if (typeof m === "string") msg = "School: " + m.slice(0, 300); } catch {}
            reject(new BadRequestException(msg));
          });
          return;
        }
        let size = 0;
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > 65536) {
            req.destroy(new Error("Response too large"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString()));
          } catch {
            reject(new BadRequestException("Invalid JSON"));
          }
        });
        res.on("error", reject);
      },
    );
    const deadline = setTimeout(
      () => req.destroy(new Error("HTTPS deadline exceeded")),
      5000,
    );
    req.on("close", () => clearTimeout(deadline));
    req.on("error", () =>
      reject(new BadRequestException("School HTTPS unavailable")),
    );
    req.end(payload);
  });
}
@Injectable()
export class SigningService implements OnModuleInit {
  private key: ReturnType<typeof createPrivateKey>;
  private jwk: any;
  constructor(private settings: SettingsService) {}
  async onModuleInit() {
    // Persistent Ed25519 key on the data volume; generated on first boot, never from env.
    this.key = createPrivateKey(
      persisted("signing.pem", () =>
        generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      ),
    );
    if (this.key.asymmetricKeyType !== "ed25519")
      throw new Error("data/signing.pem must be an Ed25519 PKCS8 PEM");
    const pub = await exportJWK(createPublicKey(this.key));
    this.jwk = { ...pub, kid: (await calculateJwkThumbprint(pub)).slice(0, 16), alg: "EdDSA", use: "sig" };
  }
  jwks() {
    return { keys: [this.jwk] };
  }
  async sign(claims: Record<string, unknown>, audience: string, expires: string) {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "EdDSA", kid: this.jwk.kid, typ: "JWT" })
      .setAudience(audience)
      .setIssuer(await this.settings.issuer())
      .setIssuedAt()
      .setExpirationTime(expires)
      .setJti(randomUUID());
  }
  /** networkAdmin lets the school grant read-only access to its admin user view (nothing else). */
  async issue(sub: string, schoolCode: string, schoolAdmin: boolean, networkAdmin: boolean, avatar: string, name: string) {
    const ticket = await (await this.sign({ schoolAdmin, networkAdmin, avatar, name }, schoolCode, "15m")).setSubject(sub).sign(this.key);
    return { ticket, expiresIn: 900 };
  }
  /** One-time setup assertion for a school's /setup/claim. */
  async setupAssertion(schoolCode: string, publicUrl: string, nonce: string, name: string) {
    return (await this.sign({ schoolCode, publicUrl, nonce, name }, "carpschool-setup", "5m")).sign(this.key);
  }
}
