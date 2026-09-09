# CTF Solutions

## Web-logic

### SwagShop
Add the VIP pass to cart, then press the "remove" button multiple times (the total price becomes negative), then press purchase and the balance will increase enough to buy the VIP pass. 

### LabResults
Sign up as new user, then click "View Report" and change the id on the URL from 5 to 1, as follows:
http://64f8644f-e978-4f31-8aa1-fa3d4368c5fa.offsec.m0lecon.it:8001/results/1

### Mission Control
Navigate to the "Briefings" tab, click on the classified (restricted) briefing, intercept the request using Burp as a proxy, then change: `X-Clearance-Level: operator` ===> `X-Clearance-Level: commander`
to unlock the privilege to read the briefing (which contains the flag).

### Al Dente
Register as new user, then navigate to "Profile" tab > press "Edit profile" button and modify slightly the name > press "Save changes" button > intercept the PUT request using Burp > modify the changed data that is being sent to the server in JSON format adding the `head_chef` role in order to elevate privileges:

`{"name": "mario", "email": "mario@gmail.com"}`  ===>  `{"name": "mar", "email": "mario@gmail.com", "role": "head_chef"}`

### TicketVault
Register as new user, then navigate to "My Tickets" tab > try to access any ticket > intercept the request using Burp as a proxy > right click on the request and press "Send to repeater" to use Burp repeater > now try to change the api to access the confidential ticket.

`GET /api/tickets/1` gives the following response in JSON format (which contains the flag):

`{"id":1,"title":"CRITICAL — Internal Security Breach Report","description":"CONFIDENTIAL — IT SECURITY MANAGER ONLY\n\nDuring routine log analysis on 2026-03-14, the SIEM flagged anomalous query patterns against the production database (db-prod-02). Investigation confirmed unauthorized data extraction between 02:47 and 03:12 UTC.\n\n--- Incident Details ---\nAttack vector: Exposed API endpoint with missing authorization check\nAffected systems: auth-prod-01, db-replica-03\nData exposed: User session tokens (est. 2,300 records)\nEvidence: /var/log/incident/breach_20260314.tar.gz\n\n--- Response Actions ---\n1. Rotated all active session tokens\n2. Patched the vulnerable endpoint\n3. Engaged external forensics team\n\nIncident Response Code: offsec{REDACTED}\n\nThis ticket is restricted to IT Security management. Do not distribute.","status":"open","priority":"critical","category":"Security","createdBy":"SIEM Alert System","createdAt":"2026-03-14T02:47:00Z","updatedAt":"2026-03-14T09:30:00Z"}`