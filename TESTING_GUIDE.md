# Security Patch Testing Guide

## How to Test the Patched Application

This guide provides step-by-step instructions to verify that all security vulnerabilities have been properly patched.

---

## 1. SQL Injection Testing

### Test Case 1.1: Login Form SQL Injection
**Vulnerable Endpoint**: `/signin` (POST)

**Test Payloads**:
```
Username: admin' --
Password: anything

Username: ' OR '1'='1' --
Password: anything

Username: admin' OR 1=1 --
Password: anything
```

**Expected Result**: ✅ Generic error message: "Invalid username or password"
**What NOT to see**: ❌ SQL error messages, database details, or successful login

**How to Test**:
1. Open `/signin`
2. Enter payload in username field
3. Enter any password
4. Click "Sign In"
5. Verify error message is generic

---

### Test Case 1.2: Todo Search SQL Injection
**Vulnerable Endpoint**: `/todos/search?q=` (GET)

**Test Payloads**:
```
q=' OR '1'='1
q=' UNION SELECT username FROM users --
q=' AND 1=0 UNION SELECT 1,2,3,4,5 --
```

**Expected Result**: ✅ No results or generic error, no data exposure
**What NOT to see**: ❌ Additional todos revealed, database info leaked

**How to Test**:
1. Login to the app
2. Go to `/todos`
3. Enter payload in search box
4. Submit search
5. Verify no SQL injection occurs

---

### Test Case 1.3: Todo Add SQL Injection
**Vulnerable Endpoint**: `/todos/add` (POST)

**Test Payloads**:
```
title: Test", ("hacked")); --
description: "); DELETE FROM todos; --
```

**Expected Result**: ✅ Todo added normally with literal text
**What NOT to see**: ❌ Database modified by injected SQL

**How to Test**:
1. Login
2. Go to `/todos`
3. Try to add todo with SQL payload
4. Verify todo is added with literal text, not executed as SQL

---

## 2. Command Injection Testing

### Test Case 2.1: Notes Cat Command Injection
**Vulnerable Endpoint**: `/notes` (GET)

**What was vulnerable**: File reading used `os.popen("cat " + filename)`

**Test Method**:
1. Login (as non-admin user)
2. Go to `/notes`
3. Notes should display safely from file

**Expected Result**: ✅ Notes displayed from file without command execution

---

### Test Case 2.2: Notes Search Command Injection
**Vulnerable Endpoint**: `/notes/search` (POST)

**Test Payloads**:
```
search_term: test; cat /etc/passwd
search_term: test`whoami`
search_term: test$(whoami)
search_term: test | cat /etc/passwd
```

**Expected Result**: ✅ Searches for literal text containing the payload
**What NOT to see**: ❌ System command output, file contents from other directories

**How to Test**:
1. Login (non-admin)
2. Go to `/notes`
3. Enter command injection payload in search
4. Verify it searches for literal text only

---

## 3. Cross-Site Scripting (XSS) Testing

### Test Case 3.1: XSS in Todo Title
**Vulnerable Endpoint**: `/todos/add` (POST)

**Test Payloads**:
```
title: <script>alert('XSS')</script>
title: <img src=x onerror="alert('XSS')">
title: <svg onload="alert('XSS')">
title: javascript:alert('XSS')
```

**Expected Result**: ✅ Payload displayed as plain text (escaped)
**What NOT to see**: ❌ JavaScript popup alert, script execution

**How to Test**:
1. Login
2. Go to `/todos`
3. Add new todo with payload
4. Verify HTML appears as text, not executed
5. Check browser console - no errors or warnings about CSP

---

### Test Case 3.2: XSS in Notes Search
**Vulnerable Endpoint**: `/notes/search` (POST)

**Test Payloads**:
```
search_term: <script>alert('XSS')</script>
search_term: <img src=x onerror="alert('XSS')">
```

**Expected Result**: ✅ Search term displayed as escaped text
**What NOT to see**: ❌ Script execution, popup alerts

---

### Test Case 3.3: XSS in File Content Display
**Vulnerable Endpoint**: `/files?file=` (GET)

**How to Test**:
1. Upload a file with XSS payload in filename
2. View the file
3. Verify filename is escaped properly

**Note**: File content itself is in `<pre>` tag and escaped

---

### Test Case 3.4: CSP Header Verification
**Test Method**: Check HTTP Response Headers

**Using Browser DevTools**:
1. Open any page of the app
2. Right-click → Inspect → Network tab
3. Click any request to app
4. Go to "Response Headers"
5. Look for `Content-Security-Policy` header

**Expected Headers Present**:
```
Content-Security-Policy: default-src 'self'; script-src 'self' ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
```

---

## 4. Path Traversal Testing

### Test Case 4.1: Directory Traversal in File Reading
**Vulnerable Endpoint**: `/files?file=` (GET)

**Test Payloads**:
```
file: ../../../etc/passwd
file: ../../config.py
file: /etc/passwd
file: ~/secret.txt
file: .../.../etc/passwd
```

**Expected Result**: ✅ File not found error, access denied
**What NOT to see**: ❌ System file contents, files outside upload folder

**How to Test**:
1. Login
2. Go to `/files`
3. Try to access file with `?file=` parameter
4. Enter traversal payload
5. Should get "Invalid file path" or "File not found"

---

### Test Case 4.2: Directory Traversal in File Deletion
**Vulnerable Endpoint**: `/delete-file/<filename>` (POST)

**Test Payloads**:
```
filename: ../../../important_file.txt
filename: /etc/passwd
```

**Expected Result**: ✅ Invalid file path error, file not deleted
**What NOT to see**: ❌ Files deleted outside upload folder

---

### Test Case 4.3: Zip File Extraction Path Traversal
**Vulnerable Endpoint**: `/upload-zip` (POST)

**How to Test**:
1. Create a ZIP file with path traversal in entry names
   Example: `../../../malicious.txt`
2. Try to upload it
3. Should extract safely within upload folder only

---

## 5. SSRF (Server-Side Request Forgery) Testing

### Test Case 5.1: SSRF URL Validation
**Vulnerable Endpoint**: `/ssrf` (GET/POST)

**Test Payloads** (should all be blocked):
```
url: http://localhost:5000/admin
url: http://127.0.0.1:5000/
url: http://0.0.0.0:8080
url: http://192.168.1.1
url: http://10.0.0.1
url: file:///etc/passwd
url: data:text/html,<script>alert('xss')</script>
url: javascript:alert('xss')
```

**Expected Result**: ✅ Error: "Invalid or unsafe URL"
**What NOT to see**: ❌ Access to internal resources, local file contents

**How to Test**:
1. Login
2. Go to `/ssrf`
3. Enter dangerous URL
4. Should get security error message

**Safe Test URLs** (should work):
```
url: https://www.google.com
url: https://www.example.com
url: https://api.github.com
```

---

## 6. Input Validation Testing

### Test Case 6.1: Username Validation
**Rules**:
- Minimum 3 characters
- Maximum 20 characters
- Only alphanumeric + underscore
- No special characters

**Test Cases**:
```
✅ Valid: "john_123", "Alice", "user_2024"
❌ Invalid: "ab", "user@123", "very_long_username_over_20"
```

**How to Test**:
1. Go to `/signup`
2. Try invalid usernames
3. Should see validation error

---

### Test Case 6.2: Email Validation
**Test Cases**:
```
✅ Valid: "user@example.com", "test.email@domain.co.uk"
❌ Invalid: "notanemail", "missing@domain", "@example.com"
```

---

### Test Case 6.3: Password Validation
**Rules**:
- Minimum 8 characters
- Must match confirmation

**Test Cases**:
```
✅ Valid: "MyPassword123", "SecurePass456"
❌ Invalid: "short", "password" (< 8 chars)
```

---

## 7. Secure Session Cookies Testing

### Test Case 7.1: HttpOnly Cookie Verification
**Test Method**: Browser DevTools

1. Open the app and login
2. Right-click → Inspect → Application/Storage → Cookies
3. Click the domain (localhost:5000)
4. Look for `session` cookie properties

**Expected**:
- ✅ `HttpOnly: true` - Cookie not accessible via JavaScript
- ✅ `Secure: true` - Cookie only sent over HTTPS
- ✅ `SameSite: Strict` - Prevents CSRF attacks

---

### Test Case 7.2: Session Cookie XSS Protection
**Test Method**: Browser Console

1. Login to the app
2. Open browser console (F12)
3. Try: `document.cookie`

**Expected Result**: ✅ Session cookie NOT visible (httponly flag)
**What NOT to see**: ❌ Session cookie value in console output

---

## 8. CORS Policy Testing

### Test Case 8.1: CORS Headers Verification
**Test Method**: Check response headers

1. Make request from browser
2. Check headers
3. Look for `Access-Control-Allow-Origin`

**Expected**:
- ✅ Limited to `localhost` and `127.0.0.1`
- ❌ NOT `Access-Control-Allow-Origin: *`

---

## 9. Error Message Testing

### Test Case 9.1: Generic Error Messages
**Test Method**: Trigger various errors

**When accessing non-existent file**:
Expected: ✅ "File not found"
NOT: ❌ `/home/user/app/uploads/filename.txt (No such file)`

**When database error occurs**:
Expected: ✅ Generic "An error occurred"
NOT: ❌ "sqlite3.IntegrityError: UNIQUE constraint failed"

---

## 10. Security Response Headers Testing

### Test Case 10.1: Using curl
```bash
curl -I http://localhost:5000

# Check for these headers:
# Content-Security-Policy: ...
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Referrer-Policy: strict-origin-when-cross-origin
```

---

## Automated Testing Script

### Using curl to test multiple payloads:

```bash
#!/bin/bash

echo "=== Testing SQL Injection ==="
curl -X POST http://localhost:5000/signin \
  -d "username=admin' --&password=test"

echo "=== Testing XSS ==="
curl "http://localhost:5000/todos/search?q=<script>alert('xss')</script>"

echo "=== Testing Path Traversal ==="
curl "http://localhost:5000/files?file=../../../etc/passwd"

echo "=== Testing SSRF ==="
curl -X POST http://localhost:5000/ssrf \
  -d "url=http://localhost/admin"
```

---

## Expected Test Results Summary

| Test | Vulnerable | Patched |
|------|-----------|---------|
| SQL Injection | Executes SQL | Returns error |
| Command Injection | Executes commands | No execution |
| XSS | Runs scripts | Escapes HTML |
| Path Traversal | Accesses files | Path blocked |
| SSRF | Accesses internal URLs | URL blocked |
| Missing Headers | No CSP headers | Headers present |
| Cookies | Accessible via JS | HttpOnly set |
| CORS | Origins: * | Origins: whitelist |

---

## Passing All Tests Means ✅

1. ✅ SQL Injection fully mitigated
2. ✅ Command Injection fully mitigated
3. ✅ XSS fully mitigated with CSP
4. ✅ Path Traversal fully mitigated
5. ✅ SSRF fully mitigated
6. ✅ Input validation in place
7. ✅ Sessions securely configured
8. ✅ CORS properly restricted
9. ✅ Security headers implemented
10. ✅ Error messages generic

---

**Application is now secure against OWASP Top 10 vulnerabilities!**
