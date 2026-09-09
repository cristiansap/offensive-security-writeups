# NeonArcade — Challenge Solution

## Vulnerability: Mass Assignment / Parameter Pollution

The application uses signed session cookies to prevent direct tampering with fields like `role`. However, the profile settings endpoint does not whitelist which fields can be updated, allowing arbitrary user-supplied parameters to be written to the database.

## Steps to Reproduce

1. Register a normal user account and log in.
2. Navigate to the profile settings page and intercept the update request with Burp Suite.
3. In the POST body, append the extra parameter `role=admin` alongside the legitimate fields (e.g. `display_name`, `theme`).
4. Forward the request. The server accepts and persists the `role` value without validation.
5. The next session cookie issued by the server now contains `"role":"admin"` in its payload.
6. Navigate to the operator/admin panel — access is granted.

## Root Cause

The backend blindly passes the entire request body to the update call, without filtering out privileged fields such as `role`. An attacker can therefore escalate their own privileges by injecting any field present in the user model.
