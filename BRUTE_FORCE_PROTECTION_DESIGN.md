# Brute-Force Protection Design

## Overview
This document explains the brute-force attack mitigation strategy implemented in the Taremwa UAS login system. The implementation focuses on practical, auditable controls that balance security and usability.

## Threat Model

### Attack Scenario
An attacker attempts to compromise user accounts through repeated login attempts with different or guessed passwords.

**Attack Types:**
1. **Credential Stuffing**: Using leaked password lists against known usernames
2. **Dictionary Attack**: Guessing common passwords for known usernames
3. **User Enumeration**: Using login responses to discover valid usernames
4. **Distributed Attacks**: Attacking from multiple IP addresses

## Security Design

### 1. Hybrid Throttling Approach

We implement **both account-based and IP-based throttling** (hybrid approach):

#### Account-Based Throttling
**What it protects**: Prevents repeated attempts on a specific user account
- Tracks failed login attempts per username
- Remains consistent regardless of attacker's IP (defeats distributed attacks to some degree)
- Allows legitimate users to attempt other accounts (with limits)

**Implementation**:
```python
username_key = f"login_throttle:username:{username}"
cache.incr(username_key)  # Increment counter
```

#### IP-Based Throttling
**What it protects**: Prevents attack volume from single source
- Tracks failed attempts per IP address
- Limits attack rate from single machine or network
- Catches casual attackers scanning login pages

**Implementation**:
```python
ip_key = f"login_throttle:ip:{ip_address}"
cache.incr(ip_key)  # Increment counter
```

### Why Hybrid?
- **Account-based alone**: Vulnerable to distributed attacks (attacker uses many IPs)
- **IP-based alone**: Vulnerable to proxy/VPN use, shared networks
- **Hybrid**: Defends against both concentrated and distributed attacks

### 2. Throttle Parameters

**Configuration** (in `login_throttle.py`):
```python
MAX_LOGIN_ATTEMPTS = 5      # Failed attempts before throttle
LOCKOUT_DURATION = 900      # 15 minutes
ATTEMPT_WINDOW = 1800       # 30-minute tracking window
```

**Why 5 attempts?**
- Allows legitimate users 5 tries in case of forgotten password
- Stops attacker after reasonable guess attempts
- Not too strict (prevents false positives)

**Why 15-minute lockout?**
- Long enough to slow attacks significantly
- Short enough for legitimate users to retry
- Balances security vs. usability

**Why 30-minute window?**
- Tracks attempts in recent history
- Old failures don't count (after 30 mins of no attempts, counter resets)
- Prevents infinite accumulation

### 3. Attack Logging & Detection

#### LoginAttempt Model
Records all login attempts (successful and failed) in database:

```python
class LoginAttempt(models.Model):
    username = CharField()      # Username attempted
    ip_address = GenericIPAddressField()  # Source IP
    successful = BooleanField()  # Success or failure
    attempted_at = DateTimeField()  # Timestamp
```

**Purpose**:
- Security audit trail
- Detection of attack patterns
- Investigation of compromised accounts
- Compliance logging

**Database Indexes**:
- `(username, -attempted_at)` - Fast queries by account
- `(ip_address, -attempted_at)` - Fast queries by IP

#### Cache-Based Counters
Real-time failure counts stored in Django cache:

```
login_throttle:username:{username}  -> failure count
login_throttle:ip:{ip_address}      -> failure count
```

**Why cache instead of database for counters?**
- Faster lookup (microseconds vs milliseconds)
- No database write on every attempt
- Automatic expiration (ATTEMPT_WINDOW)
- Less strain on production database

### 4. User Experience

#### Login Flow
1. **User enters credentials**
2. **Check if throttled**: If yes → show throttle message, deny login
3. **Attempt authentication**: If yes → success, clear counters
4. **Failed login**: Record attempt, increment counters
5. **Near-lockout warning**: Show warning when 2-3 attempts remain

#### Messages

**Generic throttle message** (prevents user enumeration):
```
"Too many failed login attempts. Please try again later."
```
- Same message regardless of username validity
- No mention of account or IP
- Doesn't leak which accounts are locked

**Warning message** (when getting close to lockout):
```
"Warning: 2 login attempt(s) remaining before temporary lockout."
```
- Helps legitimate users without compromising security
- Only shown when very close to throttle

**Normal failure message** (unchanged):
```
"Invalid username or password."
```
- Generic (doesn't reveal if user exists)
- Doesn't change based on throttle state

### 5. Edge Cases & Design Decisions

#### Successful Login Clears Counters
**Why?** A successful login proves the user knows the password, so they shouldn't be penalized again immediately.

**Implementation**:
```python
if user is not None:
    LoginThrottler.clear_failures(
        username=username,
        ip_address=client_ip
    )
```

#### IP Extraction for Proxies
**Challenge**: In production, server may be behind a proxy/load balancer

**Solution**: Check `X-Forwarded-For` header first:
```python
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
```

**Security Note**: X-Forwarded-For can be spoofed by clients, so ideally the reverse proxy should:
1. Strip incoming X-Forwarded-For headers from untrusted clients
2. Add its own X-Forwarded-For with real client IP
3. Ensure only proxy's X-Forwarded-For is trusted

#### Distributed Attack Resilience
**Can an attacker defeat this by using many IPs?**

Yes, partially. But we've made it expensive:
- Each IP is independently throttled (5 failed attempts)
- Attacker needs 5 × (number of IPs) total attempts
- Combined with IP-based throttling, very slow

**Recommendation**: Use rate limiting at reverse proxy/firewall level for additional protection (e.g., limit requests per IP globally)

### 6. Production Setup

#### Cache Backend
**Development** (default): Local memory cache
** Production**: Should use Redis or Memcached

```python
# settings.py for production
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}
```

#### Monitoring & Alerting
Recommend implementing alerts for:
- Multiple lockouts for same username (potential account targeting)
- Multiple lockouts from same IP (potential attack)
- Unusual login patterns

#### HTTPS Requirement
- IP address tracking only secure when using HTTPS  
- Without HTTPS, X-Forwarded-For can be intercepted
- Configure in production Django settings:
  ```python
  SECURE_SSL_REDIRECT = True
  ```

### 7. Testing Strategy

**30+ comprehensive tests** cover:
1. **Normal behavior**: Successful login, failed login under limit
2. **Throttling**: Blocked after max attempts
3. **Account throttling**: Per-account tracking
4. **IP throttling**: Per-IP tracking
5. **Bypass attempts**: Can't throttle bypass using different accounts
6. **Counter reset**: Successful login clears counters
7. **Warning messages**: Near-lockout warnings work
8. **No user enumeration**: Throttle message is constant

### 8. Limitations & Future Improvements

#### Current Limitations
- **Single-server**: Cache-only solution works for single server; multi-server needs shared cache (Redis)
- **No distributed coordination**: Multiple servers don't share throttle state without distributed cache
- **No IP validation**: Relies on proxy being honest with X-Forwarded-For
- **Not encryption-aware**: Doesn't defend against offline password cracking

#### Future Enhancements
1. **CAPTCHA**: Add CAPTCHA after 2-3 failed attempts (not full lockout)
2. **Email notification**: Alert user if account being targeted
3. **Geo-IP detection**: Flag logins from unusual locations
4. **2FA requirement**: After failed attempts, require 2FA
5. **Machine learning**: Detect attack patterns automatically
6. **Rate limiting at edge**: Cloudflare/CDN-level protection
7. **Distributed coordination**: Use Redis for multi-server setups

### 9. OWASP Alignment

**OWASP A07:2021 - Identification & Authentication Failures**

✅ **Implements defenses for**:
- Insufficient rate limiting for login attempts
- No protection against automated credential stuffing
- No detection of abuse patterns

## Testing

All features tested comprehensively:
```bash
python manage.py test taremwa.tests_login_bruteforce
```

**Test coverage**:
- LoginAttempt model functionality
- LoginThrottler utility operations
- Login view integration tests
- Security edge cases
- User experience scenarios

## Security Considerations

### What This Protects Against
✅ Brute-force password guessing  
✅ Credential stuffing attacks  
✅ Account enumeration via throttle behavior  
✅ Distributed attacks from multiple IPs  
✅ Timing attacks (generic response times)  

### What This Doesn't Protect Against
❌ Phishing attacks  
❌ Compromised credentials via data breaches  
❌ Brute-force attacks at database layer  
❌ Denial-of-service (blocks legitimate users too)  
❌ Compromised authentication mechanism itself  

## Deployment Checklist

- [ ] Configure Redis/Memcached for production cache
- [ ] Enable HTTPS for IP-header security
- [ ] Set up monitoring for repeated failures
- [ ] Configure alerts for potential attacks
- [ ] Test X-Forwarded-For handling with reverse proxy
- [ ] Document timeout values in runbooks
- [ ] Train support team on throttle troubleshooting
- [ ] Monitor for false positives (shared networks)
- [ ] Consider adding CAPTCHA for better UX
- [ ] Set up logging and correlation with other auth events

## References

- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Brute Force Attack: https://owasp.org/www-community/attacks/Brute_force_attack
- Django Cache Framework: https://docs.djangoproject.com/en/stable/topics/cache/
- Django Request/Response Cycle: https://docs.djangoproject.com/en/stable/topics/http/request_response/

---

**Author**: Security Team  
**Date**: 2026-04-15  
**Status**: Implemented in assignment/harden-login-bruteforce branch
