import { generateKeyPairSync, sign } from "node:crypto";
import { RegistryService } from "./registry";
import * as security from "./security";
describe("registry onboarding", () => {
  const keys = generateKeyPairSync("ed25519");
  const metadata = {
    schoolCode: "SCHOOL",
    name: "School",
    domains: ["edu.example"],
    baseUrl: "https://school.example",
    publicKey: keys.publicKey.export({ type: "spki", format: "pem" }),
  };
  const schools = { create: jest.fn(async (value) => value) };
  const registry = new RegistryService(schools as any, {} as any, {} as any);
  afterEach(() => jest.restoreAllMocks());
  it("requires signed nonce proof before trusting metadata", async () => {
    jest
      .spyOn(security, "publicJson")
      .mockImplementation(async (url) =>
        url.pathname.includes("well-known")
          ? metadata
          : {
              signature: sign(
                null,
                Buffer.from(url.searchParams.get("nonce")),
                keys.privateKey,
              ).toString("base64"),
            },
      );
    const result = await registry.onboard("https://school.example");
    expect(result.trusted).toBe(true);
    expect(result.schoolCode).toBe("SCHOOL");
  });
  it("rejects forged nonce signatures", async () => {
    jest
      .spyOn(security, "publicJson")
      .mockImplementation(async (url) =>
        url.pathname.includes("well-known")
          ? metadata
          : { signature: Buffer.alloc(64).toString("base64") },
      );
    await expect(registry.onboard("https://school.example")).rejects.toThrow(
      "Challenge signature rejected",
    );
  });
  it("rejects metadata for a different origin and malformed domains", async () => {
    jest
      .spyOn(security, "publicJson")
      .mockResolvedValue({ ...metadata, baseUrl: "https://attacker.example" });
    await expect(registry.onboard("https://school.example")).rejects.toThrow(
      "Invalid school metadata",
    );
    jest
      .spyOn(security, "publicJson")
      .mockResolvedValue({ ...metadata, domains: ["bad/domain"] });
    await expect(registry.onboard("https://school.example")).rejects.toThrow(
      "Invalid school metadata",
    );
  });
});
