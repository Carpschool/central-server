# Carpschool central

NestJS + MongoDB trusted school registry, Clerk sessions, and Ed25519 federation tickets. Node 22 required.

Run npm ci, npm run build, npm test. Configure the variables in .env.example. MongoDB must be internal-only; do not expose its port. Central sends no email.

Generate the persistent signing key before starting with openssl genpkey -algorithm ED25519 -out central-ed25519.pem and chmod 600 central-ed25519.pem. Mount it read-only at SIGNING_KEY_FILE. Startup fails if absent, too broadly readable, or not Ed25519. Never regenerate it on restart. JWKS advertises SIGNING_KEY_ID; coordinate school pin changes before rotating the active key.

Public endpoints are GET /health, GET /schools, GET /.well-known/jwks.json, POST /heartbeats, POST /webhooks/clerk, and GET /docs. POST /tickets requires a Clerk Bearer session and {schoolCode}. It returns {ticket,expiresIn:900}. Tickets include sub, schoolCode audience, CENTRAL_ISSUER issuer, exp, iat, jti, schoolAdmin, name and avatar. School admin is read from Clerk privateMetadata.school[school Mongo ID].admin, never public metadata or the user cache.

GET /admin/schools, POST /admin/schools {baseUrl}, and PATCH /admin/schools/:schoolCode/trust {trusted} require Clerk privateMetadata.admin === true. Onboarding accepts an HTTPS origin on port 443, rejects private/reserved DNS answers, pins connections, disallows redirects, bounds responses and verifies the school's signed challenge. Metadata is GET /.well-known/carpschool.json with {schoolCode,name,domains,publicKey,baseUrl}. publicKey is Ed25519 SPKI PEM. GET /federation/challenge?nonce=... returns {signature} (standard base64 Ed25519 signature over the nonce string). Onboarding itself establishes trust because it is an admin action.

POST /heartbeats accepts {schoolCode,timestamp,nonce,signature}. timestamp is Unix milliseconds, within 60 seconds; nonce is a fresh 16-128 character base64url string. Signature is standard base64 over JSON.stringify({schoolCode,timestamp,nonce}) in exactly that order. Unique persisted nonces prevent replay across processes. Untrusted schools cannot heartbeat or obtain new tickets; previously issued tickets expire within 15 minutes.

Svix verification uses the raw body plus svix-id, svix-timestamp, svix-signature. Clerk user.created, user.updated, user.deleted events update the user cache with ordered timestamps. Cache contents grant no roles. Rate limit is 60 requests/minute/IP. No proxy trust is enabled by default; deployment must configure a trusted proxy explicitly rather than trusting arbitrary forwarded headers. Swagger describes validated input DTOs.
