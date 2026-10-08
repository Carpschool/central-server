#!/usr/bin/env node
// First-boot helper: node --env-file=.env scripts/settings.mjs publicUrl=https://central.example corsOrigins=https://web.example[,https://other]
// After that, network admins edit these in the web (Central admin > Settings). Webhook secret: set it in the web (write-only).
import { MongoClient } from "mongodb";
const uri = process.env.MONGO_URI;
if (!uri) { console.error("MONGO_URI required"); process.exit(1); }
const set = {};
for (const a of process.argv.slice(2)) {
  const [k, ...v] = a.split("="); const val = v.join("=");
  if (k === "publicUrl") set["value.publicUrl"] = new URL(val).origin;
  else if (k === "corsOrigins") set["value.corsOrigins"] = val.split(",").filter(Boolean).map((o) => new URL(o).origin);
  else { console.error("unknown key " + k); process.exit(1); }
}
const c = await MongoClient.connect(uri);
await c.db().collection("settings").updateOne({ key: "central" }, { $set: set }, { upsert: true });
await c.close();
console.log("updated", Object.keys(set).join(", "));
