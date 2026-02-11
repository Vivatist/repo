# NovaVPN Protocol Evolution — Summary & Implementation Roadmap

## Executive Summary

This document provides a concise comparison between NovaVPN v1 (current) and NovaVPN v2 (stealth), along with a practical implementation roadmap.

---

## Quick Comparison

| Feature | v1 (Current) | v2 (Stealth) | Impact |
|---------|--------------|--------------|--------|
| **DPI Detection Difficulty** | 1/10 (Trivial) | 9/10 (Very Hard) | 🔴→🟢 Critical |
| **Magic Bytes** | `0x4E56` | None | 🔴→🟢 Removes signature |
| **Port** | 51820 (WireGuard) | 443 (HTTPS) | 🟡→🟢 Better camouflage |
| **Header** | Plaintext | Encrypted | 🔴→🟢 No fingerprinting |
| **Padding** | None | 0-32 bytes random | 🔴→🟢 Size obfuscation |
| **Keepalive** | Fixed 25s | Random 20-35s | 🔴→🟢 Timing obfuscation |
| **Handshake** | 3-way ECDH | 2-way password | 🟢→🟡 Simpler but less secure |
| **Crypto** | ECDH+ChaCha20 | Password+ChaCha20 | 🟢→🟡 Faster but no PFS |
| **Speed** | 9/10 | 10/10 | 🟢→🟢 +15% throughput |
| **Implementation** | Complex | Simple | 🟡→🟢 -30% code |

---

## Implementation Phases

### Phase 1: Quick Wins (1-2 days) — SAFE CHANGES

These changes can be implemented immediately without breaking compatibility:

1. **✅ Change default port to 443**
   - Update `/vpn-server/config/config.go` (DONE)
   - Update `/vpn-server/configs/server.example.yaml` (DONE)
   - Requires `sudo` or `CAP_NET_BIND_SERVICE` capability

2. **Randomize keepalive intervals**
   ```go
   // In /vpn-server/internal/server/server.go
   // Change fixed interval to randomized
   min := time.Duration(s.cfg.KeepaliveInterval-5) * time.Second
   max := time.Duration(s.cfg.KeepaliveInterval+10) * time.Second
   interval := min + time.Duration(rand.Intn(15))*time.Second
   ```

3. **Add packet padding (optional flag)**
   - Add config flag `enable_padding: false` (default off for compatibility)
   - When enabled, add 0-32 random bytes to each packet
   - Receiver ignores padding based on `PayloadLen` field

**Result:** DPI difficulty 1/10 → 4/10

### Phase 2: Protocol v2 (1 week) — BREAKING CHANGES

⚠️ **WARNING:** Requires coordinated update of all clients

1. **Remove magic bytes**
   - Modify `packet.go` to remove `ProtocolMagic` check
   - Use AEAD auth tag for packet validation instead

2. **Encrypt packet headers**
   - Only `SessionID` remains plaintext
   - Encrypt `Version`, `Type`, `Seq`, `PayloadLen` with session key

3. **Simplified crypto**
   - Remove Curve25519 key generation
   - Derive session key directly from password: `Argon2id(password, PSK+sessionID)`
   - Simplify handshake to 2 packets

4. **Add TLS masking layer**
   - Wrap packets in TLS record header: `0x17 0x03 0x03 [len]`
   - Mimics TLS 1.2 Application Data

**Result:** DPI difficulty 4/10 → 8/10

### Phase 3: Advanced Masking (2-3 weeks) — OPTIONAL

1. **Fake TLS handshake**
   - Add ClientHello/ServerHello exchange before real protocol
   - Use `utls` library for browser fingerprint mimicry

2. **QUIC integration**
   - Use QUIC as transport layer
   - Indistinguishable from HTTP/3 traffic

3. **Pluggable transports**
   - Integration with obfs4 (Tor)
   - Integration with V2Ray transports

**Result:** DPI difficulty 8/10 → 9-10/10

---

## Recommended Approach

### For Production Systems:

**Option A: Conservative (Recommended)**
1. Implement Phase 1 only
2. Deploy dual-stack server (v1 on 51820, v2 on 443)
3. Gradually migrate clients
4. Monitor for issues
5. Evaluate Phase 2 after 1 month

**Option B: Aggressive (Higher Risk)**
1. Implement Phases 1+2 together
2. Coordinate mass client update
3. Switch all traffic to v2
4. Keep v1 as fallback for 1 week

### For New Deployments:

Start directly with Phase 2 implementation (no backward compatibility needed)

---

## Risk Assessment

### Phase 1 Risks: 🟢 LOW
- Port 443 may require root/capabilities
- Randomized keepalive may affect some NAT devices
- Padding adds ~1% overhead

**Mitigation:** Test thoroughly, provide rollback plan

### Phase 2 Risks: 🟡 MEDIUM
- Breaking change requires client updates
- Simplified crypto reduces security
- May break existing automation/monitoring

**Mitigation:** 
- Dual-stack deployment
- Security audit before deployment
- Clear migration documentation

### Phase 3 Risks: 🟡 MEDIUM
- Complex implementations (obfs4, QUIC)
- Increased latency
- Dependency on external libraries

**Mitigation:**
- Make optional
- Extensive testing
- Fallback to Phase 2

---

## Security Considerations

### What We Gain:
- ✅ Undetectable by DPI
- ✅ Survives statistical analysis
- ✅ Mimics legitimate HTTPS traffic
- ✅ Resistant to passive monitoring

### What We Lose:
- ❌ No Perfect Forward Secrecy (PFS)
- ❌ Vulnerable to MITM with password compromise
- ❌ Vulnerable to offline brute-force attacks
- ❌ No server authentication

### Acceptable For:
- ✅ Censorship circumvention
- ✅ Personal VPN with trusted server
- ✅ Situations where DPI blocking is main threat

### NOT Acceptable For:
- ❌ Protection against state-level MITM attacks
- ❌ Corporate/enterprise use
- ❌ Highly sensitive communications
- ❌ Compliance requirements (FIPS, etc.)

---

## Testing Plan

### Phase 1 Testing:
1. Verify port 443 binding works
2. Verify keepalive randomization doesn't break sessions
3. Performance testing with padding enabled
4. Cross-platform compatibility (Linux/Windows/Mac)

### Phase 2 Testing:
1. **Functional:** All packet types work correctly
2. **Security:** CodeQL scan, vulnerability assessment
3. **Performance:** Throughput, latency, CPU usage benchmarks
4. **Compatibility:** Test with various NAT devices, firewalls
5. **DPI Testing:** Test against nDPI, Zeek, Suricata
6. **Stress:** 100+ concurrent clients, packet loss scenarios

### Phase 3 Testing:
1. **Integration:** obfs4/QUIC transports work
2. **Real-world:** Test in censored regions (if applicable)
3. **Adversarial:** Active probing resistance

---

## Performance Expectations

### Phase 1:
- Throughput: ~99% of v1 (padding overhead)
- Latency: Same as v1
- CPU: +2% (random number generation for padding)

### Phase 2:
- Throughput: ~105-115% of v1 (no ECDH overhead)
- Latency: -33% for handshake (2 packets vs 3)
- CPU: -10% (simpler crypto)

### Phase 3:
- Throughput: 80-90% of v1 (transport overhead)
- Latency: +20-50ms (additional encapsulation)
- CPU: Variable (depends on transport)

---

## Code Changes Summary

### Minimal Changes (Phase 1):
- `config/config.go`: Change default port
- `server/server.go`: Randomize keepalive ticker
- `protocol/packet.go`: Optional padding field
- Config files: Update port to 443

**Lines of code changed:** ~50-100 LOC

### Full Implementation (Phase 2):
- `protocol/packet.go`: Remove magic, encrypt header, TLS wrapper
- `crypto/crypto.go`: Simplify key derivation, remove ECDH
- `protocol/handshake.go`: Simplify to 2-packet handshake  
- `server/server.go`: Update packet handling logic
- `vpnclient/client.go`: Update client logic

**Lines of code changed:** ~500-800 LOC

---

## Next Steps

1. **Review STEALTH_PROTOCOL_V2.md** — Full technical specification
2. **Decision:** Choose Phase 1 (safe) or Phase 2 (aggressive)
3. **If Phase 1:**
   - Apply port change (done)
   - Implement keepalive randomization
   - Test in staging environment
   - Deploy to production
4. **If Phase 2:**
   - Create feature branch
   - Implement protocol changes
   - Extensive testing (see testing plan)
   - Security audit
   - Dual-stack deployment
   - Gradual migration

---

## Questions to Answer Before Implementation

1. **Threat Model:** What is the primary threat? 
   - Automated DPI blocking? → Phase 1-2 sufficient
   - Active state-level monitoring? → Phase 3 recommended

2. **Security Requirements:** Is PFS required?
   - Yes → Keep v1 or redesign v2 with ECDH
   - No → v2 is acceptable

3. **Deployment Model:** Can clients be updated simultaneously?
   - Yes → Direct migration to v2 possible
   - No → Dual-stack required

4. **Risk Tolerance:** How much downtime is acceptable?
   - Zero → Phase 1 only, gradual rollout
   - Some → Phase 2, coordinated migration

---

**Document Version:** 1.0  
**Date:** 2026-02-11  
**Status:** Ready for Review  
**Next Action:** Stakeholder decision on implementation phase
