# Rate Limiter Configuration Summary

## Updated Settings (More User-Friendly)

### General API Rate Limit
- **Window**: 5 minutes (was 15 min)
- **Max Requests**: 200 (was 100)
- **Purpose**: Protect against DDoS, allow normal usage

### Login Rate Limit
- **Window**: 5 minutes (was 15 min)
- **Max Failed Attempts**: 20 (was 5)
- **Skip Successful Logins**: ✅ YES
- **Purpose**: Allow multiple account logins, only block brute-force

### Exponential Backoff (Per Email+IP)
- **Max Lockout**: 5 minutes (was 1 hour)
- **Formula**: 2^n seconds
- **Examples**:
  - 1st fail: 2 seconds
  - 2nd fail: 4 seconds
  - 3rd fail: 8 seconds
  - 4th fail: 16 seconds
  - 5th fail: 32 seconds
  - 6th fail: 64 seconds
  - 7th fail: 128 seconds (2.1 min)
  - 8th fail: 256 seconds (4.3 min)
  - 9th+ fail: 300 seconds (5 min max)

## Key Improvements
1. ✅ Only failed logins count toward limit
2. ✅ Can login to multiple accounts without rate limit
3. ✅ Shorter lockout periods
4. ✅ Per-email tracking in exponential backoff
5. ✅ More lenient for testing/development
