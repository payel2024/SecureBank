# SecureBank — Two-Factor Authentication (2FA) (Payel)

Feature source extracted from the supplied SecureBank project.

## Included
- OTP verification UI
- 2FA frontend API service
- Shared API helper and backend integration references

## Backend integration required
The current backend implements `POST /api/auth/customer/verify-2fa` inside `backend/routes/auth.routes.js`, together with login and registration handlers. The source router is intentionally not duplicated here to avoid two competing copies of the same backend API. The 2FA backend handler must be extracted into a dedicated route/controller by the integration owner, preserving the existing endpoint and request/response contract.

Existing endpoint: `POST /api/auth/customer/verify-2fa` with `{ loginRequestId, otp }`. The login flow creates the OTP/login request, so 2FA must be tested together with the login feature.

## Shared dependencies
Uses the same MySQL database and canonical Prisma schema as the main SecureBank app. Do not create independent migrations or change database configuration in this feature repository.

## Safety
Never commit `.env`, OTP secrets, passwords, tokens, `node_modules`, or generated secrets.
