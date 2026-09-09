# Carpschool Central Authority Server - API Documentation

## Overview

The Central Authority Server (`central-server`) manages global user identities, registers trusted school servers using Ed25519 digital signatures, and issues cryptographically signed Federation Tickets for student clients connecting to school servers.

- **Base URL**: `http://localhost:4000` (or `https://central.carpschool.ca`)
- **Interactive Swagger UI**: `http://localhost:4000/api/docs`
- **Default Port**: `4000`
- **Database**: MongoDB (`central_db`), connected via Docker internal network with no exposed host ports.

---

## Authentication

Clients authenticate using a Clerk session JWT passed in the HTTP Authorization header:

```
Authorization: Bearer <clerk_session_token>
```

In development (`NODE_ENV != 'production'`), mock tokens starting with `mock_` (e.g. `Bearer mock_user_123`) are accepted for local testing.

---

## Endpoints

### 1. Central Authority Metadata & Ed25519 Signature

#### `GET /api/v1/meta`
* **Description**: Returns the Central Authority Server identity and 32-byte Ed25519 public key. Every response is cryptographically signed with Central Server's private key in the `x-central-signature` HTTP response header. School servers and clients use this to verify that the Central Authority is authentic.
* **Response Headers**:
  ```
  x-central-signature: <base64_ed25519_signature>
  ```
* **Response Body (200 OK)**:
  ```json
  {
    "service": "carpschool-central",
    "version": "2.0.0",
    "ed25519PublicKey": "YOUR_BASE64_ED25519_PUBLIC_KEY",
    "timestamp": "2026-09-08T23:30:00.000Z",
    "signature": "base64_ed25519_signature"
  }
  ```

### 2. Schools Directory & Trust

#### `POST /api/v1/schools/admin/onboard`
* **Description**: Automated admin onboarding for school servers. The admin supplies only the school server's Base URL and its 32-byte Ed25519 public key. Central Server queries the school server's `/api/v1/meta` endpoint, verifies the cryptographic signature from header `x-school-signature`, and automatically populates the school metadata.
* **Request Body**:
  ```json
  {
    "baseUrl": "https://ubc.carp.school",
    "ed25519PublicKey": "7q2w...BASE64_PUBLIC_KEY..."
  }
  ```
* **Response (201 Created)**:
  ```json
  {
    "_id": "673f...",
    "schoolCode": "ubc",
    "officialName": "University of British Columbia",
    "allowedEmailDomains": ["ubc.ca", "student.ubc.ca"],
    "baseUrl": "https://ubc.carp.school",
    "ed25519PublicKey": "7q2w...BASE64_PUBLIC_KEY...",
    "isTrusted": true,
    "lastHeartbeat": "2026-09-08T23:00:00.000Z"
  }
  ```

#### `GET /api/v1/schools`
* **Description**: Lists all admin-verified trusted schools. Used by Web, iOS, and Android clients to populate the school selection directory.
* **Response (200 OK)**:
  ```json
  [
    {
      "schoolCode": "ubc",
      "officialName": "University of British Columbia",
      "allowedEmailDomains": ["ubc.ca", "student.ubc.ca"],
      "baseUrl": "https://ubc.carp.school",
      "isTrusted": true
    }
  ]
  ```

#### `GET /api/v1/schools/:code`
* **Description**: Returns metadata for a specific school by its code (e.g. `ubc`).

#### `POST /api/v1/schools/ticket`
* **Auth Required**: `Bearer <clerk_token>`
* **Description**: Issues an Ed25519-signed Federation Ticket for connecting to a target school server. Supports both registered school codes and custom untrusted self-hosted URLs.
* **Request Body (Trusted School)**:
  ```json
  {
    "schoolCode": "ubc"
  }
  ```
* **Request Body (Untrusted Custom Server)**:
  ```json
  {
    "schoolCode": "custom",
    "customBaseUrl": "https://rides.myschool.org"
  }
  ```
* **Response (200 OK)**:
  ```json
  {
    "ticket": "eyJkYXRhIjp7ImNlbnRyYWxVc2VySWQiOiJ1c2VyXzEy...",
    "schoolBaseUrl": "https://ubc.carp.school",
    "isTrusted": true,
    "expiresAt": "2026-09-09T23:00:00.000Z"
  }
  ```

#### `POST /api/v1/schools/heartbeat`
* **Description**: Receives periodic heartbeat pings from registered school servers to maintain active status in the central directory. Authenticity is verified using the school server's Ed25519 digital signature.
* **Request Headers**:
  ```
  x-school-signature: <base64_ed25519_signature>
  ```
* **Request Body**:
  ```json
  {
    "schoolCode": "ubc",
    "timestamp": "2026-09-08T23:30:00.000Z",
    "activeCarpools": 12,
    "activeStudents": 48,
    "version": "2.0.0"
  }
  ```
* **Response (200 OK)**:
  ```json
  {
    "status": "ok",
    "acknowledgedAt": "2026-09-08T23:30:01.000Z"
  }
  ```

---

### 3. Global Identity & Profile Sync

#### `POST /api/v1/auth/sync`
* **Auth Required**: `Bearer <clerk_token>`
* **Description**: Synchronizes the user's Clerk profile with the Central Server database (`central_db`).
* **Request Body**:
  ```json
  {
    "email": "student@example.com",
    "fullName": "Jane Doe",
    "phoneNumber": "+16045550199",
    "avatarUrl": "https://img.clerk.com/..."
  }
  ```
* **Response (200 OK)**: Returns the synchronized user record.

#### `GET /api/v1/auth/me`
* **Auth Required**: `Bearer <clerk_token>`
* **Description**: Retrieves current global user profile.

---

## Cryptographic Ticket Structure

The issued `ticket` is a base64-encoded JSON package:
```json
{
  "data": {
    "centralUserId": "user_2n...",
    "clerkUserId": "user_2n...",
    "fullName": "Jane Doe",
    "primaryEmail": "student@example.com",
    "schoolCode": "ubc",
    "isTrusted": true,
    "issuedAt": "2026-09-08T23:00:00.000Z",
    "expiresAt": "2026-09-09T23:00:00.000Z",
    "issuer": "carpschool-central"
  },
  "signature": "base64_ed25519_signature",
  "centralPublicKey": "base64_central_public_key"
}
```
The school server verifies `signature` against `data` using `centralPublicKey` without making any network requests back to Central Server.
