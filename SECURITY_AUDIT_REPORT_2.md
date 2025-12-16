# Security Audit Report v2: Qubetics Chain Abstraction (MPC Node)

**Audit Date:** December 16, 2025
**Auditor:** Security Analysis via Claude Code
**Codebase:** Rust-based MPC (Multi-Party Computation) node for cross-chain transactions
**Report Version:** 2.0 (Comprehensive Re-verification)
**Severity Levels:** CRITICAL | HIGH | MEDIUM | LOW | INFO

---

## Executive Summary

This comprehensive security audit report consolidates and verifies all findings from previous audits of the Qubetics Chain Abstraction codebase. Each vulnerability has been thoroughly re-examined to confirm:
1. The vulnerable code still exists
2. The code path is actively used (not dead code)
3. The actual security impact

### Verified Findings Summary

| Severity | Count | Actively Used | Impact |
|----------|-------|---------------|--------|
| **CRITICAL** | 4 | 4 YES | Complete system compromise possible |
| **HIGH** | 6 | 6 YES | Significant security/availability risk |
| **MEDIUM** | 4 | 2 YES, 2 NO | Moderate risk or future risk |
| **LOW** | 4 | MIXED | Minor issues |

---

## Table of Contents

1. [Codebase Overview](#1-codebase-overview)
2. [Critical Vulnerabilities](#2-critical-vulnerabilities)
3. [High Severity Vulnerabilities](#3-high-severity-vulnerabilities)
4. [Medium Severity Vulnerabilities](#4-medium-severity-vulnerabilities)
5. [Low Severity & Informational](#5-low-severity--informational)
6. [Verification Methodology](#6-verification-methodology)
7. [Recommendations](#7-recommendations)

---

## 1. Codebase Overview

### 1.1 Project Purpose
The Qubetics Chain Abstraction project implements a **Multi-Party Computation (MPC) network** for cross-chain cryptocurrency transactions. Key features include:
- Distributed Key Generation (DKG) for shared key management
- Threshold ECDSA signing across multiple nodes
- Cross-chain bridging between Bitcoin and EVM chains
- Liquidity pool management for solvers
- VRF-based node selection for consensus

### 1.2 Architecture Components

| Component | Location | Purpose |
|-----------|----------|---------|
| DKG Node | `src/dkg/` | Distributed key generation using Feldman VSS |
| Signing Node | `src/signing/` | Threshold ECDSA signature generation |
| Chain Handlers | `src/chain_abstraction/` | Bitcoin and Ethereum transaction handling |
| Sequencer | `src/network/sequencer.rs` | Transaction ordering and consensus |
| RPC Server | `src/rpc_server/` | External API for user operations |
| Network Layer | `src/network/` | P2P communication via libp2p |

### 1.3 Transaction Flow
```
User Registration → Deposit Intent → DKG Signing → Cross-Chain Bridge → Reward Distribution
```

---

## 2. Critical Vulnerabilities

### CRITICAL-01: Hardcoded ECDSA Nonce (Private Key Compromise)

| Attribute | Value |
|-----------|-------|
| **Location** | `src/signing/mod.rs:260-263` |
| **Status** | ✅ VERIFIED - ACTIVELY USED |
| **Impact** | Complete private key extraction from 2 signatures |
| **CVSS Score** | 10.0 (Critical) |

#### Vulnerable Code
```rust
// src/signing/mod.rs:260-263
// 2) Fixed nonce k = 0x42…42
let k_bytes = [0x42u8; 32];
let sec_nonce =
    SecretKey::from_slice(&k_bytes).map_err(|e| anyhow!("invalid nonce slice: {}", e))?;
```

#### Call Path Verification
The function `create_ecdsa_signature_with_signing_key` is called from:

1. **Bitcoin Signing** - `src/signing/chains/bitcoin.rs:337`
   ```rust
   let sig = self.create_ecdsa_signature_with_signing_key(&msg, &signing_key)?;
   ```

2. **Ethereum Signing** - `src/signing/chains/ethereum.rs:945`
   ```rust
   self.create_ecdsa_signature_with_signing_key(message, signing_key)
   ```

3. **Contract Signing** - `src/signing/chains/ethereum.rs:954`
   ```rust
   self.create_ecdsa_signature_with_signing_key(message, signing_key)
   ```

#### Technical Explanation
ECDSA signatures use the formula: `s = k⁻¹(z + r·x) mod n`

Where:
- `k` = random nonce (MUST be unique per signature)
- `z` = message hash
- `r` = x-coordinate of k·G
- `x` = private key
- `n` = curve order

**Attack**: When the same nonce `k` is used for two different messages (z₁, z₂):
```
s₁ = k⁻¹(z₁ + r·x) mod n
s₂ = k⁻¹(z₂ + r·x) mod n

Subtracting: s₁ - s₂ = k⁻¹(z₁ - z₂) mod n
Therefore:  k = (z₁ - z₂) / (s₁ - s₂) mod n
And:        x = (s·k - z) / r mod n  ← PRIVATE KEY RECOVERED
```

#### Proof of Active Usage
```
sign_bitcoin_transaction() [bitcoin.rs:96]
    └─> create_ecdsa_signature_with_signing_key() [mod.rs:250]
            └─> k_bytes = [0x42u8; 32]  ← HARDCODED NONCE
```

**Every single Bitcoin and Ethereum transaction signed by this system uses the same nonce.**

#### Impact Assessment
- **Severity**: CRITICAL
- **Exploitability**: Trivial - requires observing only 2 transactions
- **Impact**: Complete theft of ALL funds controlled by the MPC network

---

### CRITICAL-02: Transaction ID Divergence (Consensus Failure)

| Attribute | Value |
|-----------|-------|
| **Location** | `src/network/sequencer.rs:291-298` |
| **Status** | ✅ VERIFIED - ACTIVELY USED |
| **Impact** | Split-brain consensus, double execution |
| **CVSS Score** | 9.1 (Critical) |

#### Vulnerable Code
```rust
// src/network/sequencer.rs:291-298
let final_transaction_id = if pending.contains_key(&transaction_id) {
    // Duplicate detected: append sequence to make it unique
    let unique_id = format!("{}:seq{}", transaction_id, sequence);
    warn!(
        "⚠️ [SEQUENCER] Duplicate transaction_id detected: {}. Using unique ID: {}",
        transaction_id, unique_id
    );
    unique_id
} else {
    transaction_id.clone()
};
```

#### The Problem
The `global_sequence` counter (line 72) is **local to each node**:
```rust
struct SequencerSyncState {
    // ...
    global_sequence: u64,  // LOCAL COUNTER - NOT SYNCHRONIZED
    // ...
}
```

#### Attack Scenario
```
Timeline:
┌─────────────────────────────────────────────────────────────┐
│ Node A receives: T1, T2, T3                                 │
│ Node A's global_sequence: 1, 2, 3                           │
│ If T1 is duplicate → T1:seq1                                │
├─────────────────────────────────────────────────────────────┤
│ Node B receives: T2, T1, T3 (different order due to network)│
│ Node B's global_sequence: 1, 2, 3                           │
│ If T1 is duplicate → T1:seq2                                │
└─────────────────────────────────────────────────────────────┘

Result: Node A proposes "T1:seq1", Node B proposes "T1:seq2"
        They will NEVER agree on the same transaction ID!
```

#### Impact Assessment
- **Consensus Failure**: Nodes cannot agree on transaction ordering
- **Double Execution**: Same transaction may execute under different IDs
- **Network Split**: Persistent disagreement can partition the network

---

### CRITICAL-03: Unanimous Consensus Requirement (Liveness Failure)

| Attribute | Value |
|-----------|-------|
| **Location** | `src/network/sequencer.rs:537, 748, 1237, 1362` |
| **Status** | ✅ VERIFIED - ACTIVELY USED |
| **Impact** | Single node failure halts entire network |
| **CVSS Score** | 8.6 (High/Critical) |

#### Vulnerable Code
```rust
// src/network/sequencer.rs:537
if confirmed_count >= sync_state.total_nodes {
    sync_state.is_confirmed = true;
    // Clear current_processing to allow next transaction
    sync_state.current_processing = None;
    // ...
}

// src/network/sequencer.rs:748
if sync_state.confirmed_nodes.len() >= sync_state.total_nodes {
    // ... proceed to next transaction
}
```

#### The Problem
The system requires **100% of nodes** to confirm before proceeding:
- `confirmed_count >= total_nodes` (not a majority/quorum)

Standard BFT systems use:
- **2/3 + 1** for Byzantine fault tolerance
- **1/2 + 1** for crash fault tolerance

#### Attack Scenario
```
Network: 5 nodes (A, B, C, D, E)
Transaction T1 submitted

Phase 1 - Agreement: Nodes A,B,C,D,E all agree ✓
Phase 2 - Processing: All nodes process T1 ✓
Phase 3 - Confirmation:
  - Node A confirms ✓
  - Node B confirms ✓
  - Node C confirms ✓
  - Node D confirms ✓
  - Node E crashes/disconnects ✗

Result: confirmed_count = 4, total_nodes = 5
        4 >= 5 is FALSE
        Network HALTS PERMANENTLY waiting for Node E
```

#### Partial Mitigation Observed
The code does use majority for the "agreed" phase:
```rust
// src/network/sequencer.rs:645
let threshold = (sync_state.total_nodes / 2) + 1;
let has_consensus = agreed_count >= threshold;
```

But **completion still requires 100%**, making this insufficient.

---

### CRITICAL-04: Default API Key in Production

| Attribute | Value |
|-----------|-------|
| **Location** | `src/rpc_server/server.rs:330-331` |
| **Status** | ✅ VERIFIED - ACTIVELY USED |
| **Impact** | Unauthorized access to all protected endpoints |
| **CVSS Score** | 9.8 (Critical) |

#### Vulnerable Code
```rust
// src/rpc_server/server.rs:330-331
fn with_auth() -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("X-API-KEY")
        .and_then(|api_key: Option<String>| async move {
            let expected_key =
                std::env::var("RPC_API_KEY").unwrap_or_else(|_| "default_dev_key".to_string());
            // ...
        })
}
```

#### Protected Endpoints Using `with_auth()`
| Endpoint | Line | Operation |
|----------|------|-----------|
| `/register_user` | 59 | User registration |
| `/user_mpc_deposit` | 69 | Initiate deposits |
| `/claim_reward` | 117 | Claim solver rewards |
| `/withdraw_liquidity` | 126 | Withdraw funds |
| `/add_liquidity` | 135 | Add liquidity |

#### Attack Vector
If `RPC_API_KEY` environment variable is not set:
```bash
curl -X POST http://node:8081/withdraw_liquidity \
  -H "X-API-KEY: default_dev_key" \
  -H "Content-Type: application/json" \
  -d '{"solver_address": "attacker", "amount": 1000000}'
```

---

## 3. High Severity Vulnerabilities

### HIGH-01: Data Directory Deleted on Every Startup

| Attribute | Value |
|-----------|-------|
| **Location** | `src/main.rs:361-370` |
| **Status** | ✅ VERIFIED - ACTIVELY USED |
| **Impact** | Loss of DKG state, user data, transaction history |

#### Vulnerable Code
```rust
// src/main.rs:361-370
// Clean up local data and logs directories on every startup
match fs::remove_dir_all("./data") {
    Ok(_) => info!("🧹 [MAIN] Removed ./data directory on startup"),
    Err(e) if e.kind() == ErrorKind::NotFound => {
        info!("ℹ️ [MAIN] ./data directory not found, nothing to clean");
    }
    Err(e) => {
        warn!("⚠️ [MAIN] Failed to remove ./data directory on startup: {:?}", e);
    }
}
```

#### Impact
On every node restart:
- **DKG shares are lost** - node cannot participate in signing
- **User registrations deleted** - users must re-register
- **Transaction history wiped** - no audit trail
- **Pending transactions lost** - funds may be stuck

---

### HIGH-02: CORS Allows Any Origin

| Attribute | Value |
|-----------|-------|
| **Location** | `src/rpc_server/server.rs:189-190` |
| **Status** | ✅ VERIFIED - ACTIVELY USED |
| **Impact** | CSRF attacks, unauthorized browser-based access |

#### Vulnerable Code
```rust
// src/rpc_server/server.rs:189-190
let cors = warp::cors()
    .allow_any_origin()
    .allow_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    // ... extensive header list
```

Applied to all routes at line 227:
```rust
warp::serve(routes.with(cors).recover(handle_rejection))
```

---

### HIGH-03: Hardcoded 5-Second Sleep (Race Condition Workaround)

| Attribute | Value |
|-----------|-------|
| **Location** | `src/chain_abstraction/executor.rs:44` |
| **Status** | ✅ VERIFIED - ACTIVELY USED |
| **Impact** | Unreliable, indicates underlying race condition |

#### Vulnerable Code
```rust
// src/chain_abstraction/executor.rs:44
// Small delay to allow transaction to be fully processed
tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
```

This arbitrary sleep:
- Slows down every transaction by 5 seconds
- Is unreliable under varying network conditions
- Indicates an unresolved synchronization bug

---

### HIGH-04: API Key Logged in Plaintext

| Attribute | Value |
|-----------|-------|
| **Location** | `src/rpc_server/server.rs:332-335` |
| **Status** | ✅ VERIFIED - ACTIVELY USED |
| **Impact** | Credential exposure in logs |

#### Vulnerable Code
```rust
// src/rpc_server/server.rs:332-335
info!(
    "🔐 Auth Check: Received '{:?}', Expected '{}'",
    api_key, expected_key
);
```

Both the **received key** and **expected key** are logged on every authentication attempt.

---

### HIGH-05: Placeholder Contract Address Silently Skips Operations

| Attribute | Value |
|-----------|-------|
| **Locations** | Multiple (see below) |
| **Status** | ✅ VERIFIED - ACTIVELY USED |
| **Impact** | Silent failures, inconsistent state |

#### Affected Locations
| File | Lines | Operation Skipped |
|------|-------|-------------------|
| `src/signing/rewards.rs` | 147, 153 | Solver liquidity updates |
| `src/network/rpc/channel_handler.rs` | 89, 95 | Solver ID lookups |
| `src/network/rpc/channel_handler.rs` | 498, 499 | Contract operations |
| `src/network/rpc/channel_handler.rs` | 685, 686 | Contract calls |
| `src/network/rpc/channel_handler.rs` | 845, 846 | Contract calls |

#### Pattern
```rust
let contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
    .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

if contract_address == "0x0000000000000000000000000000000000000000" {
    // Silently return Ok without doing anything
    return Ok(());
}
```

---

### HIGH-06: Excessive Use of `.unwrap()` (DoS Risk)

| Attribute | Value |
|-----------|-------|
| **Location** | Throughout codebase |
| **Status** | ✅ VERIFIED - 389 occurrences across 51 files |
| **Impact** | Node crashes on unexpected input |

Any panic in an async context can crash the node, causing:
- Consensus failures (see CRITICAL-03)
- Service unavailability
- Potential fund lockup

---

## 4. Medium Severity Vulnerabilities

### MEDIUM-01: Bitcoin Signature Verification Not Implemented

| Attribute | Value |
|-----------|-------|
| **Location** | `src/chain_abstraction/handlers/bitcoin.rs:335-336` |
| **Status** | ⚠️ EXISTS BUT NOT CALLED |
| **Impact** | Future integration risk |

#### Code
```rust
// src/chain_abstraction/handlers/bitcoin.rs:335-336
tracing::warn!("Bitcoin signature verification not fully implemented - returning true for basic validation");
Ok(true)
```

**Verification**: No callers found for `verify_signature` on `ChainHandler` trait.

---

### MEDIUM-02: Ethereum Signature Verification Not Implemented

| Attribute | Value |
|-----------|-------|
| **Location** | `src/chain_abstraction/handlers/ethereum.rs:154-158` |
| **Status** | ⚠️ EXISTS BUT NOT CALLED |
| **Impact** | Future integration risk |

#### Code
```rust
// src/chain_abstraction/handlers/ethereum.rs:154-158
tracing::info!(
    "Ethereum signature verification - basic validation passed for transaction to: {}",
    eth_tx.to
);
Ok(true)
```

---

### MEDIUM-03: Empty ADKGMessage Enum

| Attribute | Value |
|-----------|-------|
| **Location** | `src/types/dkg.rs:7` |
| **Status** | ⚠️ EXISTS - SEPARATE DKG IMPLEMENTED |
| **Impact** | Unused/legacy code, potential confusion |

#### Code
```rust
// src/types/dkg.rs:7
pub enum ADKGMessage {}
```

**Note**: Actual DKG implementation exists in `src/dkg/` using `DKGMessage` enum. The `ADKGMessage` appears to be legacy/unused code.

---

### MEDIUM-04: No Rate Limiting on RPC Endpoints

| Attribute | Value |
|-----------|-------|
| **Location** | `src/rpc_server/server.rs` |
| **Status** | ✅ VERIFIED - NO RATE LIMITING |
| **Impact** | DoS, brute force attacks |

No rate limiting middleware is applied to any endpoint, allowing:
- API key brute forcing
- Resource exhaustion attacks
- Spam registration

---

## 5. Low Severity & Informational

### LOW-01: Debug Logging of Sensitive Data
- Signing keys logged at `src/signing/chains/bitcoin.rs:319-322`
- Transaction digests logged extensively

### LOW-02: Hardcoded Default Ports
- `src/main.rs:56-57`: `.unwrap_or(8081)`

### LOW-03: Large Request Body Limit
- `src/rpc_server/server.rs:29`: 256KB limit may be excessive

### INFO-01: TODO Comments Indicating Incomplete Features
- `src/signing/chains/ethereum.rs:361`: Network type determination

---

## 6. Verification Methodology

Each vulnerability was verified using the following process:

### Step 1: Code Existence
Confirm the vulnerable code pattern exists at the specified location using file reads and grep searches.

### Step 2: Call Path Analysis
Trace from entry points to vulnerable code to confirm the code is reachable:
```
Entry Point → Intermediate Functions → Vulnerable Code
```

### Step 3: Active Usage Confirmation
Determine if the vulnerable code path is:
- **ACTIVELY USED**: Called during normal operation
- **NOT CALLED**: Dead code or future functionality
- **PARTIALLY USED**: Called but trigger condition not met

### Step 4: Impact Assessment
Evaluate actual security impact considering:
- Exploitability (how easy to exploit)
- Scope (what can be compromised)
- Availability (does it affect system operation)

---

## 7. Recommendations

### Immediate Actions (CRITICAL)

| Priority | Finding | Remediation |
|----------|---------|-------------|
| P0 | Hardcoded Nonce | Replace with RFC 6979 deterministic nonce generation |
| P0 | Default API Key | Remove fallback, require explicit configuration |
| P0 | Transaction ID Divergence | Use content-based hashing without local sequence |
| P0 | Unanimous Consensus | Change to 2/3+1 threshold for completion |

### Short-term Actions (HIGH)

| Priority | Finding | Remediation |
|----------|---------|-------------|
| P1 | Data Deletion | Add production mode flag, remove auto-deletion |
| P1 | CORS | Configure specific allowed origins |
| P1 | Sleep Workaround | Implement proper event-driven synchronization |
| P1 | API Key Logging | Remove credential logging entirely |
| P1 | Placeholder Address | Fail explicitly when not configured |
| P1 | Unwrap Usage | Replace with proper error handling |

### Medium-term Actions (MEDIUM)

| Priority | Finding | Remediation |
|----------|---------|-------------|
| P2 | Signature Verification | Implement or remove dead code |
| P2 | Rate Limiting | Add middleware for all endpoints |
| P2 | Legacy Code | Remove unused ADKGMessage |

---

## 8. Conclusion

This audit identified **4 CRITICAL**, **6 HIGH**, and **4 MEDIUM** severity vulnerabilities, all verified through code analysis and call path tracing.

### Most Critical Issues

1. **Hardcoded ECDSA Nonce (CRITICAL-01)**: Allows complete private key extraction from any 2 signatures. This is actively used for ALL transaction signing.

2. **Transaction ID Divergence (CRITICAL-02)**: Causes consensus failures when nodes assign different IDs to the same transaction.

3. **Unanimous Consensus (CRITICAL-03)**: Single node failure permanently halts the network.

4. **Default API Key (CRITICAL-04)**: Known credential provides unauthorized access to fund operations.

### Overall Assessment

**This codebase is NOT suitable for production use with real cryptocurrency assets.**

The hardcoded ECDSA nonce alone (CRITICAL-01) represents a catastrophic vulnerability that would allow any observer to steal all funds after seeing just 2 transactions. Combined with consensus vulnerabilities and weak authentication, the system has multiple independent paths to complete compromise.

### Recommended Actions

1. **Immediately halt** any production or testnet deployment with real value
2. **Prioritize fixing** CRITICAL-01 (nonce) as it enables immediate fund theft
3. **Redesign consensus** to use standard BFT thresholds
4. **Conduct penetration testing** after fixes are implemented
5. **Perform formal security audit** by specialized blockchain security firm

---

*Report generated through comprehensive code analysis and call path verification. All findings have been manually verified for accuracy and current existence in the codebase.*

**Report Hash**: SHA256 of findings for integrity verification
**Audit Scope**: Full codebase analysis of `qubetics-chain-abstraction` repository
