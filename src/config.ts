export function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error('Missing required environment variable: ' + name);
  return value;
}
export function validateEnv() {
  for (const key of ['MONGO_URI', 'CLERK_SECRET_KEY', 'CLERK_WEBHOOK_SECRET', 'CENTRAL_ISSUER', 'SIGNING_KEY_FILE', 'SIGNING_KEY_ID', 'CLERK_AUTHORIZED_PARTIES']) required(key);
  const issuer = new URL(required('CENTRAL_ISSUER'));
  if (!['https:', 'http:'].includes(issuer.protocol)) throw new Error('Invalid CENTRAL_ISSUER');
}
