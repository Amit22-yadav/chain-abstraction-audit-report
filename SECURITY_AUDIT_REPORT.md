# Security Audit Report: Qubetics Chain Abstraction (MPC Node)

**Audit Date:** December 16, 2025
**Auditor:** Security Analysis via Claude Code
**Codebase:** Rust-based MPC (Multi-Party Computation) node for cross-chain transactions
**Severity Levels:** CRITICAL | HIGH | MEDIUM | LOW | INFO

---

## Executive Summary

This is a comprehensive security audit of the Qubetics Chain Abstraction codebase, which implements an MPC-based system for cross-chain cryptocurrency transactions between Bitcoin and EVM-compatible networks (Ethereum/Qubetics). The system uses Distributed Key Generation (DKG), threshold signatures, VRF-based node selection, and manages liquidity pools for solvers.

### Critical Findings Summary (VERIFIED)

| Severity | Count | Actively Used |
|----------|-------|---------------|
| CRITICAL | 2     | YES           |
| HIGH     | 5     | YES           |
| MEDIUM   | 6     | MIXED         |
| LOW      | 4     | MIXED         |
| INFO     | 3     | N/A           |

---

## Codebase Overview

### Project Structure
- **Language:** Rust (92 source files)
- **Package Name:** `mpc-node`
- **Main Components:**
  - DKG (Distributed Key Generation) - `src/dkg/`
  - Signing Node - `src/signing/`
  - Chain Abstraction (Bitcoin/Ethereum handlers) - `src/chain_abstraction/`
  - Network/P2P Layer - `src/network/`
  - RPC Server - `src/rpc_server/`
  - VRF (Verifiable Random Function) - `src/vrf/`
  - User Intent Manager - `src/user_intent_manager/`

### Supported Chains
- Bitcoin (Mainnet/Testnet)
- Ethereum
- Qubetics (EVM chain, ID: 9029)
- Polygon, BSC, Avalanche, Arbitrum, Optimism, Base

---

## CRITICAL VULNERABILITIES (VERIFIED AS ACTIVELY USED)

### CRITICAL-01: Hardcoded ECDSA Nonce (Complete Private Key Compromise)

**Location:** `src/signing/mod.rs:261-263`

```rust
// 2) Fixed nonce k = 0x42...42
let k_bytes = [0x42u8; 32];
let sec_nonce =
    SecretKey::from_slice(&k_bytes).map_err(|e| anyhow!("invalid nonce slice: {}", e))?;
```

**VERIFICATION - ACTIVELY CALLED:**
- `src/signing/chains/bitcoin.rs:337` - Called for every Bitcoin transaction signature
- `src/signing/chains/ethereum.rs:945` - Called for Ethereum transaction signatures
- `src/signing/chains/ethereum.rs:954` - Called for contract transaction signatures

**Impact:** CRITICAL - Complete private key extraction from ANY two signatures

**Description:** The `create_ecdsa_signature_with_signing_key` function is the **primary signing function** used for ALL Bitcoin and Ethereum transactions. It uses a hardcoded nonce value (`0x424242...42`). This is a catastrophic cryptographic vulnerability.

In ECDSA, using the same nonce for two different messages allows an attacker to mathematically derive the private key:

```
k = (z1 - z2) / (s1 - s2) mod n
private_key = (s * k - z) / r mod n
```

**Any attacker observing just TWO transactions signed by this system can extract the complete private key and steal ALL funds.**

**Call Path Verification:**
1. `sign_bitcoin_transaction()` in `src/signing/chains/bitcoin.rs:96`
2. Calls `create_ecdsa_signature_with_signing_key()` at line 337
3. Which uses hardcoded nonce at `src/signing/mod.rs:261`

**Recommendation:**
- IMMEDIATELY remove this code path
- Use RFC 6979 deterministic nonce generation
- Implement proper random nonce generation with cryptographic PRNG

---

### CRITICAL-02: Default API Key in Production Code

**Location:** `src/rpc_server/server.rs:330-331`

```rust
let expected_key =
    std::env::var("RPC_API_KEY").unwrap_or_else(|_| "default_dev_key".to_string());
```

**VERIFICATION - ACTIVELY USED:**
The `with_auth()` function is called on multiple critical endpoints:
- `src/rpc_server/server.rs:59` - `register_user` endpoint
- `src/rpc_server/server.rs:69` - `user_mpc_deposit` endpoint
- `src/rpc_server/server.rs:117` - `claim_reward` endpoint
- `src/rpc_server/server.rs:126` - `withdraw_liquidity` endpoint
- `src/rpc_server/server.rs:135` - `add_liquidity` endpoint

**Impact:** CRITICAL - Unauthorized API access if env var not set

**Description:** If the `RPC_API_KEY` environment variable is not set, the system falls back to `"default_dev_key"`. This hardcoded credential allows:
- Unauthorized access to all protected RPC endpoints
- User registration manipulation
- Fund withdrawal initiation
- Liquidity operations

**Recommendation:**
- Remove the default fallback
- Require `RPC_API_KEY` to be set (fail-closed)
- Use strong, randomly generated API keys

---

## HIGH SEVERITY VULNERABILITIES (VERIFIED)

### HIGH-01: Data Directory Cleared on Every Startup

**Location:** `src/main.rs:361-370`

```rust
// Clean up local data and logs directories on every startup
match fs::remove_dir_all("./data") {
    Ok(_) => info!("Removed ./data directory on startup"),
    // ...
}
```

**VERIFICATION:** This code runs in `main()` on every node startup.

**Impact:** HIGH - Loss of critical DKG state and user data

**Description:** The application **intentionally deletes all data on every restart**, including:
- DKG shares and commitments
- User registrations
- Transaction history
- Pending transactions

This makes the node completely stateless and unable to recover from restarts. In production, this would cause complete loss of cryptographic key material.

**Recommendation:**
- Remove this code for production builds
- Use a configuration flag for development vs production mode
- Implement proper data persistence and recovery

---

### HIGH-02: CORS Allow Any Origin

**Location:** `src/rpc_server/server.rs:189-190`

```rust
let cors = warp::cors()
    .allow_any_origin()
```

**VERIFICATION:** This is applied to all routes at line 227: `routes.with(cors)`

**Impact:** HIGH - Cross-site request forgery and unauthorized API access

**Description:** The RPC server accepts requests from any origin, enabling:
- CSRF attacks from malicious websites
- Unauthorized fund operations via user browsers
- Session hijacking

**Recommendation:** Configure allowed origins explicitly for production deployments.

---

### HIGH-03: Placeholder Contract Address Silently Skips Operations

**Locations (Multiple - All Verified):**
- `src/signing/rewards.rs:147,153` - Skips solver liquidity updates
- `src/network/rpc/channel_handler.rs:89,95` - Skips solver ID lookups
- `src/network/rpc/channel_handler.rs:498,499` - Skips contract operations
- `src/network/rpc/channel_handler.rs:685,686` - Skips contract calls
- `src/network/rpc/channel_handler.rs:845,846` - Skips contract calls

```rust
let contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
    .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

if contract_address == "0x0000000000000000000000000000000000000000" {
    // Skip contract operations silently
    return Ok(());
}
```

**Impact:** HIGH - Contract operations silently skipped, inconsistent state

**Description:** Multiple critical contract operations silently succeed without actually executing when using the placeholder address. This creates:
- Inconsistent on-chain vs. off-chain state
- Silent failures in reward/liquidity operations
- Potential for fund misappropriation

**Recommendation:** Fail explicitly when contract address is not configured.

---

### HIGH-04: Excessive Use of `.unwrap()` and `.expect()`

**Location:** Throughout codebase (389 occurrences across 51 files)

**Impact:** HIGH - Denial of service via panic

**Description:** The codebase heavily uses `.unwrap()`, `.expect()`, and `panic!()` which can crash the node. A malicious actor could craft inputs that trigger panics, causing node crashes and potential consensus failures.

**Recommendation:** Replace with proper error handling using `Result` and `?` operator.

---

### HIGH-05: API Key Logged in Plain Text

**Location:** `src/rpc_server/server.rs:332-335`

```rust
info!(
    "Auth Check: Received '{:?}', Expected '{}'",
    api_key, expected_key
);
```

**VERIFICATION:** This runs on every authenticated request.

**Impact:** HIGH - API key exposure in logs

**Description:** Both the received API key and expected API key are logged in plaintext on every authentication attempt, exposing credentials in log files.

**Recommendation:** Remove or mask credential logging.

---

## MEDIUM SEVERITY VULNERABILITIES

### MEDIUM-01: Bitcoin Signature Verification Not Implemented (NOT ACTIVELY CALLED)

**Location:** `src/chain_abstraction/handlers/bitcoin.rs:335-336`

```rust
tracing::warn!("Bitcoin signature verification not fully implemented - returning true for basic validation");
Ok(true)
```

**VERIFICATION STATUS:** The `verify_signature` function is defined in the `ChainHandler` trait (`src/chain_abstraction/handlers/mod.rs:32-37`) but **NO CALLERS FOUND** in the codebase.

**Impact:** MEDIUM (downgraded from CRITICAL) - Function exists but currently unused

**Risk:** Future integration risk - any code relying on this interface would have false security assumptions.

**Recommendation:** Either implement proper verification or remove/mark the function as unimplemented.

---

### MEDIUM-02: Ethereum Signature Verification Not Implemented (NOT ACTIVELY CALLED)

**Location:** `src/chain_abstraction/handlers/ethereum.rs:138-158`

**VERIFICATION STATUS:** Same as Bitcoin - `verify_signature` is part of the trait but **NO CALLERS FOUND**.

**Impact:** MEDIUM (downgraded from HIGH) - Function exists but currently unused

---

### MEDIUM-03: Aggregated Signature Verification Incomplete (PARTIALLY USED)

**Location:** `src/signing/mod.rs:667-716`

```rust
// In a full implementation, you would:
// 1. Parse the signature components (r, s, v)
// 2. Recover the public key from the signature and message hash
// 3. Verify against the expected public keys
// 4. Check threshold requirements

info!("Signature validation passed for {} signers", signed_message.signer_ids.len());
Ok(true)
```

**VERIFICATION STATUS:**
- Function `verify_aggregated_signature` is called from `handle_signed_message` at line 657
- However, **NO CODE SENDS `SigningMessage::SignedMessage`** - this message type is defined but never constructed/sent

**Impact:** MEDIUM - Code path exists but trigger message is never sent

---

### MEDIUM-04: No Rate Limiting on RPC Endpoints

**Impact:** MEDIUM - DoS vulnerability, brute force attacks

---

### MEDIUM-05: Private Key Handling in Memory

**Impact:** MEDIUM - Key exposure via memory dump (no mlock/secure wiping)

---

### MEDIUM-06: Missing Timeout on External API Calls

**Location:** `src/utils/transaction.rs:143-192`

**Impact:** MEDIUM - Node hang on slow/unresponsive APIs

---

## LOW SEVERITY VULNERABILITIES

### LOW-01: Verbose Error Messages Expose Internal State
### LOW-02: Debug Logging of Sensitive Data (signing keys logged at `src/signing/chains/bitcoin.rs:319-322`)
### LOW-03: Hardcoded Default Ports
### LOW-04: Large Request Body Limit (256KB)

---

## INFORMATIONAL FINDINGS

### INFO-01: TODO Comments Indicate Incomplete Implementation
### INFO-02: Missing Comprehensive Test Coverage
### INFO-03: Dependency Audit Recommended

---

## Summary of Verification Results

| Original Finding | Original Severity | Verified Status | Final Severity |
|-----------------|-------------------|-----------------|----------------|
| Hardcoded ECDSA Nonce | CRITICAL | **ACTIVELY USED** - All BTC/ETH signatures | **CRITICAL** |
| Default API Key | CRITICAL | **ACTIVELY USED** - 5 critical endpoints | **CRITICAL** |
| Bitcoin Signature Verification | CRITICAL | NOT CALLED - No callers found | MEDIUM |
| Ethereum Signature Verification | HIGH | NOT CALLED - No callers found | MEDIUM |
| Aggregated Signature Verification | HIGH | PARTIAL - Trigger never sent | MEDIUM |
| Data Directory Deletion | HIGH | **ACTIVELY USED** - Every startup | **HIGH** |
| CORS Allow Any Origin | HIGH | **ACTIVELY USED** - All routes | **HIGH** |
| Placeholder Contract Address | HIGH | **ACTIVELY USED** - Multiple locations | **HIGH** |
| Excessive unwrap() | HIGH | **ACTIVELY USED** - 389 occurrences | **HIGH** |
| API Key Logging | HIGH | **ACTIVELY USED** - Every auth request | **HIGH** |

---

## Recommendations Summary

### Immediate Actions (CRITICAL - VERIFIED ACTIVE)
1. **FIX HARDCODED NONCE** - This is actively used for ALL transaction signing
2. Remove default API key fallback - actively protects critical endpoints
3. Remove data directory deletion on startup (for production)

### Short-term Actions (HIGH - VERIFIED ACTIVE)
4. Implement proper error handling (remove unwrap/panic)
5. Restrict CORS to specific origins
6. Fail explicitly when contract address not configured
7. Remove API key logging

### Medium-term Actions (MEDIUM)
8. Implement proper signature verification functions (for future use)
9. Implement rate limiting
10. Add secure memory handling for keys
11. Add request timeouts for external APIs

---

## Conclusion

After verification, **2 CRITICAL vulnerabilities are confirmed as actively used in production code paths**:

1. **The hardcoded ECDSA nonce (CRITICAL-01)** is called for every single Bitcoin and Ethereum transaction signature. This alone allows complete fund theft from any attacker observing just 2 transactions.

2. **The default API key (CRITICAL-02)** protects 5 critical endpoints and falls back to a known value if not configured.

The signature verification functions (Bitcoin, Ethereum, Aggregated) that were initially flagged as CRITICAL/HIGH have been **downgraded to MEDIUM** as they are defined but not actually called in the current codebase.

**The hardcoded ECDSA nonce alone makes this system completely insecure for any real cryptocurrency operations.**

---

*This report was verified through call path analysis. Dynamic testing recommended.*
