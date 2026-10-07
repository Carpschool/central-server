import "reflect-metadata";
import { Test } from "@nestjs/testing";
import { ValidationPipe } from "@nestjs/common";
import { MongoMemoryServer } from "mongodb-memory-server";
import { createConnection, Connection } from "mongoose";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import * as request from "supertest";
import { createLocalJWKSet, jwtVerify, SignJWT, generateKeyPair } from "jose";
import { Webhook } from "svix";
import { AppModule } from "./app.module";
import { IdentityService } from "./auth";
import { SchoolSchema, ReplaySchema } from "./models";
import { publicAddress, SigningService, publicJson } from "./security";

jest.setTimeout(120000);
describe("central trust boundary", () => {
  let mongo: MongoMemoryServer,
    app: any,
    conn: Connection,
    schools: any,
    school: any,
    privateKey: any,
    folder: string;
  const identity = { authenticate: jest.fn() };
  beforeAll(async () => {
    mongo = await MongoMemoryServer.create();
    folder = mkdtempSync(tmpdir() + "/central-test-");
    const keys = generateKeyPairSync("ed25519");
    privateKey = keys.privateKey;
    writeFileSync(
      folder + "/key.pem",
      privateKey.export({ format: "pem", type: "pkcs8" }),
      { mode: 0o600 },
    );
    Object.assign(process.env, {
      MONGO_URI: mongo.getUri(),
      CLERK_SECRET_KEY: "sk_test_placeholder",
      CLERK_AUTHORIZED_PARTIES: "https://app.example",
      CENTRAL_ISSUER: "https://central.example",
      SIGNING_KEY_FILE: folder + "/key.pem",
      SIGNING_KEY_ID: "test-key",
      CLERK_WEBHOOK_SECRET:
        "whsec_" +
        Buffer.from("test-webhook-secret-32-bytes-long!").toString("base64"),
    });
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(IdentityService)
      .useValue(identity)
      .compile();
    app = module.createNestApplication({ rawBody: true });
    app.useGlobalPipes(
      new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }),
    );
    await app.init();
    conn = await createConnection(mongo.getUri()).asPromise();
    schools = conn.model("School", SchoolSchema);
    const replay = conn.model("Replay", ReplaySchema);
    await Promise.all([schools.init(), replay.init()]);
    school = await schools.create({
      schoolCode: "SENTINEL",
      name: "Sentinel",
      domains: ["edu.example"],
      trusted: true,
      publicKey: keys.publicKey.export({ format: "pem", type: "spki" }),
      baseUrl: "https://school.example",
    });
  });
  afterAll(async () => {
    await app?.close();
    await conn?.close();
    await mongo?.stop();
    if (folder) rmSync(folder, { recursive: true, force: true });
  });
  beforeEach(() =>
    identity.authenticate.mockResolvedValue({
      id: "user_a",
      firstName: "A",
      privateMetadata: {},
      publicMetadata: { admin: true },
      imageUrl: "",
    }),
  );
  it("publishes health and trusted schools", async () => {
    await request(app.getHttpServer()).get("/health").expect(200);
    const res = await request(app.getHttpServer()).get("/schools").expect(200);
    expect(res.body[0].schoolCode).toBe("SENTINEL");
    expect(res.body[0].publicKey).toBeUndefined();
  });
  it("does not treat public metadata as admin", async () => {
    await request(app.getHttpServer()).get("/admin/schools").expect(403);
  });
  it("permits only exact boolean privateMetadata admin", async () => {
    identity.authenticate.mockResolvedValue({
      privateMetadata: { admin: true },
    });
    await request(app.getHttpServer()).get("/admin/schools").expect(200);
  });
  it("rejects forged Clerk session at auth service boundary", async () => {
    const real = new IdentityService();
    await expect(real.authenticate("Bearer mock_admin")).rejects.toThrow(
      "Invalid Clerk session",
    );
    await expect(real.authenticate()).rejects.toThrow();
  });
  it("issues scoped ticket with correct private school role and 15 minute expiry", async () => {
    identity.authenticate.mockResolvedValue({
      id: "user_a",
      privateMetadata: {
        school: {
          [school._id.toString()]: { admin: true },
          other: { admin: true },
        },
      },
    });
    const res = await request(app.getHttpServer())
      .post("/tickets")
      .send({ schoolCode: "SENTINEL" })
      .expect(201);
    const jwks = await request(app.getHttpServer())
      .get("/.well-known/jwks.json")
      .expect(200);
    const { payload, protectedHeader } = await jwtVerify(
      res.body.ticket,
      createLocalJWKSet(jwks.body),
      {
        issuer: "https://central.example",
        audience: "SENTINEL",
        algorithms: ["EdDSA"],
      },
    );
    expect(payload.schoolAdmin).toBe(true);
    expect(payload.sub).toBe("user_a");
    expect(payload.exp - payload.iat).toBe(900);
    expect(payload.jti).toBeTruthy();
    expect(protectedHeader.kid).toBe("test-key");
    await expect(
      jwtVerify(res.body.ticket, createLocalJWKSet(jwks.body), {
        audience: "OTHER",
      }),
    ).rejects.toThrow();
    const attacker = await generateKeyPair("EdDSA");
    const forgery = await new SignJWT({ schoolAdmin: true })
      .setProtectedHeader({ alg: "EdDSA", kid: "test-key" })
      .sign(attacker.privateKey);
    await expect(
      jwtVerify(forgery, createLocalJWKSet(jwks.body)),
    ).rejects.toThrow();
  });
  it("rejects unknown school and extra ticket claims", async () => {
    await request(app.getHttpServer())
      .post("/tickets")
      .send({ schoolCode: "MISSING" })
      .expect(404);
    await request(app.getHttpServer())
      .post("/tickets")
      .send({ schoolCode: "SENTINEL", schoolAdmin: true })
      .expect(400);
  });
  it("checks signatures, freshness, persistent replay and trust on heartbeat", async () => {
    const data = {
      schoolCode: "SENTINEL",
      timestamp: Date.now(),
      nonce: "random-heartbeat-nonce-1234",
    };
    const signature = sign(
      null,
      Buffer.from(JSON.stringify(data)),
      privateKey,
    ).toString("base64");
    await request(app.getHttpServer())
      .post("/heartbeats")
      .send({ ...data, signature: Buffer.alloc(64).toString("base64") })
      .expect(401);
    await request(app.getHttpServer())
      .post("/heartbeats")
      .send({ ...data, signature })
      .expect(201);
    await request(app.getHttpServer())
      .post("/heartbeats")
      .send({ ...data, signature })
      .expect(409);
    await request(app.getHttpServer())
      .post("/heartbeats")
      .send({ ...data, timestamp: Date.now() - 120000, signature })
      .expect(401);
    await schools.updateOne({ _id: school._id }, { trusted: false });
    await request(app.getHttpServer())
      .post("/tickets")
      .send({ schoolCode: "SENTINEL" })
      .expect(404);
    await request(app.getHttpServer())
      .post("/heartbeats")
      .send({ ...data, signature })
      .expect(401);
    await schools.updateOne({ _id: school._id }, { trusted: true });
  });
  it("rejects bad webhook signature and accepts signed raw body", async () => {
    await request(app.getHttpServer())
      .post("/webhooks/clerk")
      .send({ type: "user.created" })
      .expect(401);
    const payload = JSON.stringify({
      type: "user.created",
      timestamp: Date.now(),
      data: { id: "user_cache", first_name: "Cached" },
    });
    const id = "msg_test123";
    const date = new Date();
    const signature = new Webhook(process.env.CLERK_WEBHOOK_SECRET).sign(
      id,
      date,
      payload,
    );
    await request(app.getHttpServer())
      .post("/webhooks/clerk")
      .set("svix-id", id)
      .set("svix-timestamp", String(Math.floor(date.getTime() / 1000)))
      .set("svix-signature", signature)
      .set("Content-Type", "application/json")
      .send(payload)
      .expect(201);
    expect(
      (await conn.collection("users").findOne({ clerkId: "user_cache" })).name,
    ).toBe("Cached");
  });
  it("fails on missing persistent key", async () => {
    const original = process.env.SIGNING_KEY_FILE;
    process.env.SIGNING_KEY_FILE = folder + "/missing";
    await expect(new SigningService().onModuleInit()).rejects.toThrow();
    process.env.SIGNING_KEY_FILE = original;
  });
});
describe("SSRF", () => {
  it.each([
    "127.0.0.1",
    "10.0.0.1",
    "169.254.169.254",
    "192.168.1.1",
    "::1",
    "::ffff:127.0.0.1",
    "fc00::1",
    "0.0.0.0",
    "224.0.0.1",
  ])("rejects reserved address %s", (address) =>
    expect(publicAddress(address)).toBe(false),
  );
  it("rejects HTTP, credentials, private DNS and custom ports", async () => {
    for (const url of [
      "http://example.com",
      "https://user:pass@example.com",
      "https://127.0.0.1",
      "https://example.com:8443",
    ])
      await expect(publicJson(new URL(url))).rejects.toThrow();
  });
});
