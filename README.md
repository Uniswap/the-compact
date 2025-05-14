# The Compact 🤝
 - **Compact** *[noun]*: an agreement or covenant between two or more parties.
 - **Compact** *[transitive verb]*: to make up by connecting or combining.
 - **Compact** *[adjective]*: occupying a small volume by reason of efficient use of space.

[![CI](https://github.com/Uniswap/the-compact/actions/workflows/test.yml/badge.svg?branch=v1)](https://github.com/Uniswap/the-compact/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/uniswap/the-compact/branch/v1/graph/badge.svg?token=BPcWGQYU53)](https://codecov.io/gh/uniswap/the-compact/tree/v1)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](./README.md)

> :warning: This is an early-stage contract under active development; it has not yet been properly tested, reviewed, or audited. Use at your own risk.

## Table of Contents
1. [Summary](#summary)
2. [Key Concepts](#key-concepts)
    - [Resource Locks](#resource-locks)
    - [Allocators](#allocators)
    - [Arbiters](#arbiters)
    - [Emissaries](#emissaries)
    - [Compacts & EIP-712 Payloads](#compacts--eip-712-payloads)
    - [Witness Structure](#witness-structure)
    - [Registration](#registration)
    - [Claimant Processing & Structure](#claimant-processing--structure)
    - [Forced Withdrawals](#forced-withdrawals)
    - [Signature Verification](#signature-verification)
3. [Key Events](#key-events)
4. [Key Data Structures](#key-data-structures)
5. [Setup](#setup)
6. [Usage (Flows by Actor)](#usage-flows-by-actor)
    - [Sponsors (Depositors)](#sponsors-depositors)
    - [Arbiters & Claimants (e.g. Fillers)](#arbiters--claimants-eg-fillers)
    - [Relayers](#relayers)
    - [Allocators (Infrastructure)](#allocators-infrastructure)
7. [View Functions](#view-functions)
8. [Core Interfaces Overview](#core-interfaces-overview)
    - [ITheCompact](#ithecompact)
    - [ITheCompactClaims](#ithecompactclaims)
    - [IAllocator (Interface)](#iallocator-interface)
    - [IEmissary (Interface)](#iemissary-interface)
9. [Contract Layout](#contract-layout)
10. [Credits](#credits)
11. [License](#license)


## Summary
The Compact is an ownerless ERC6909 contract that facilitates the voluntary formation and mediation of reusable **resource locks**. It enables tokens to be credibly committed to be spent in exchange for performing actions across arbitrary, asynchronous environments, and claimed once the specified conditions have been met.

Resource locks are entered into by ERC20 or native token holders (called the **depositor**). Once a resource lock has been established, the owner of the ERC6909 token representing a resource lock can act as a **sponsor** and create a **compact**. A compact is a commitment allowing interested parties to claim their tokens through the sponsor's indicated **arbiter**. The arbiter is then responsible for processing the claim once it has attested to the specified conditions of the compact having been met.

When depositing into a resource lock, the depositor assigns an **allocator** and a **reset period** for that lock. The allocator is tasked with providing additional authorization whenever the owner of the lock wishes to transfer their 6909 tokens, withdraw the underlying locked assets, or sponsor a compact utilizing the lock. Their primary role is essentially to protect **claimants**—entities that provide proof of having met the conditions and subsequently make a claim against a compact—by ensuring the credibility of commitments, such as preventing "double-spends" involving previously-committed locked balances.

Allocators can be purely onchain abstractions, or can involve hybrid (onchain + offchain) mechanics as part of their authorization procedure. Should an allocator erroneously or maliciously fail to authorize the use of an unallocated resource lock balance, the depositor can initiate a **forced withdrawal** for the lock in question; after waiting for the reset period indicated when depositing into the lock, they can withdraw their underlying balance at will _without_ the allocator's explicit permission.

Sponsors can also optionally assign an **emissary** to act as a fallback signer for authorizing claims against their compacts. This is particularly helpful for smart contract accounts or other scenarios where signing keys might change.

The Compact effectively "activates" any deposited tokens to be instantly spent or swapped across arbitrary, asynchronous environments as long as:
 - Claimants are confident that the allocator is sound and will not leave the resource lock underallocated.
 - Sponsors are confident that the allocator will not unduly censor fully allocated requests.
 - Sponsors are confident that the arbiter is sound and will not process claims where the conditions were not successfully met.
 - Claimants are confident that the arbiter is sound and will not *fail* to process claims where the conditions *were* successfully met.

## Key Concepts

### Resource Locks
Resource locks are the fundamental building blocks of The Compact protocol. They are created when a depositor places tokens (either native tokens or ERC20 tokens) into The Compact. Each resource lock has four key properties:

1.  The **underlying token** held in the resource lock.
2.  The **allocator** tasked with cosigning on claims against the resource locks (see [Allocators](#allocators)).
3.  The **scope** of the resource lock (either spendable on any chain or limited to a single chain).
4.  The **reset period** for forcibly exiting the lock (see [Forced Withdrawals](#forced-withdrawals)) and for emissary reassignment timelocks (see [Emissaries](#emissaries)).

Each unique combination of these four properties is represented by a fungible ERC6909 tokenID. The owner of these ERC6909 tokens can act as a sponsor and create compacts.

The `scope`, `resetPeriod`, and the `allocatorId` (obtained when an allocator is registered) are packed into a `bytes12 lockTag`. A resource lock's specific ID (the ERC6909 `tokenId`) is a concatenation of this `lockTag` and the underlying `token` address, represented as a `uint256` for ERC6909 compatibility. This `lockTag` is used throughout various interfaces to succinctly identify the parameters of a lock.

**Fee-on-Transfer and Rebasing Token Handling:**
-   **Fee-on-Transfer:** The Compact correctly handles fee-on-transfer tokens for both deposits and withdrawals. The amount of ERC6909 tokens minted or burned is based on the *actual balance change* in The Compact contract, not just the specified amount. This ensures ERC6909 tokens accurately represent the underlying assets.
-   **Rebasing Tokens:** **Rebasing tokens (e.g., stETH) are NOT supported in The Compact V1.** Any yield or other balance changes occurring *after* deposit will not accrue to the depositor's ERC6909 tokens. For such assets, use their wrapped, non-rebasing counterparts (e.g., wstETH) to avoid loss of value.

### Allocators
Each resource lock is mediated by an **allocator**. Their primary responsibilities include:
1.  **Preventing Double-Spending:** Ensuring sponsors don't commit the same tokens to multiple compacts or transfer away committed funds.
2.  **Validating Transfers:** Attesting to standard ERC6909 transfers of resource lock tokens (via `IAllocator.attest`).
3.  **Authorizing Claims:** Validating claims against resource locks (via `IAllocator.authorizeClaim`).
4.  **Nonce Management:** Ensuring nonces are not reused for claims and (optionally) consuming nonces directly on The Compact using [`consume`](./src/interfaces/ITheCompact.sol#L550).

Allocators must be registered with The Compact via [`__registerAllocator`](./src/interfaces/ITheCompact.sol#L561) before they can be assigned to locks. They must implement the [`IAllocator`](./src/interfaces/IAllocator.sol) interface.

The trust assumptions around allocators are important:
-   Claimants must trust that the allocator is sound and will not allow resource locks to become underfunded.
-   Sponsors must trust that the allocator will not unduly censor valid requests against fully funded locks. However, the sponsor can always initiate a forced withdrawal if the allocator fails to authorize the sponsor's requests. The allocator cannot steal or otherwise unilaterally move anyone's funds.

### Arbiters
Arbiters are responsible for verifying and submitting claims. When a sponsor creates a compact, they designate an arbiter who will:
1.  Verify that the specified conditions of the compact have been met (these conditions can be implicitly understood or explicitly defined via witness data).
2.  Process the claim by calling the appropriate function on The Compact (from [`ITheCompactClaims`](./src/interfaces/ITheCompactClaims.sol)).
3.  Specify which claimants are entitled to the committed resources and in what form each claimant's portion will be issued (i.e., direct transfer, withdrawal, or conversion) as part of the claim payload.

The trust assumptions around arbiters are also important:
-   Sponsors must trust that the arbiter will not process claims where conditions weren't met.
-   Claimants must trust that the arbiter will not fail to process claims where conditions *were* met.

Often, the entity fulfilling an off-chain condition (like a filler or solver) might interface directly with the arbiter.

### Emissaries
Emissaries provide a fallback verification mechanism for sponsors when authorizing claims. This is particularly useful for:
1.  Smart contract accounts that might update their EIP-1271 signature verification logic.
2.  Accounts using EIP-7702 delegation that leverages EIP-1271.
3.  Situations where the sponsor wants to delegate claim verification to a trusted third party.

A sponsor assigns an emissary for a specific `lockTag` using [`assignEmissary`](./src/interfaces/ITheCompact.sol#L532). The emissary must implement the [`IEmissary`](./src/interfaces/IEmissary.sol) interface, specifically the `verifyClaim` function.

To change an emissary after one has been assigned, the sponsor must first call [`scheduleEmissaryAssignment`](./src/interfaces/ITheCompact.sol#L542), wait for the `resetPeriod` associated with the `lockTag` to elapse, and then call `assignEmissary` again with the new emissary's address (or `address(0)` to remove).

### Compacts & EIP-712 Payloads
A **compact** is the agreement created by a sponsor that allows their locked resources to be claimed under specified conditions. The Compact protocol uses EIP-712 typed structured data for creating and verifying signatures for these agreements.

There are three main EIP-712 payload types a sponsor can sign:
1.  **`Compact`**: For single resource lock operations on a single chain.
    ```solidity
    // Defined in src/types/EIP712Types.sol
    struct Compact {
        address arbiter;    // The account tasked with verifying and submitting the claim.
        address sponsor;    // The account to source the tokens from.
        uint256 nonce;      // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires;    // The time at which the claim expires.
        uint256 id;         // The token ID of the ERC6909 token to allocate.
        uint256 amount;     // The amount of ERC6909 tokens to allocate.
        // (Optional) Witness data may follow:
        Mandate mandate;
    }
    ```

2.  **`BatchCompact`**: For allocating multiple resource locks on a single chain.
    ```solidity
    // Defined in src/types/EIP712Types.sol
    struct BatchCompact {
        address arbiter;            // The account tasked with verifying and submitting the claim.
        address sponsor;            // The account to source the tokens from.
        uint256 nonce;              // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires;            // The time at which the claim expires.
        uint256[2][] idsAndAmounts; // The allocated token IDs and amounts.
        // (Optional) Witness data may follow:
        // Mandate mandate;
    }
    ```

3.  **`MultichainCompact`**: For allocating one or more resource locks across multiple chains.
    ```solidity
    // Defined in src/types/EIP712Types.sol
    struct MultichainCompact {
        address sponsor;     // The account to source the tokens from.
        uint256 nonce;       // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires;     // The time at which the claim expires.
        Element[] elements;  // Arbiter, chainId, ids & amounts, and mandate for each chain.
    }

    // Defined in src/types/EIP712Types.sol
    struct Element {
        address arbiter;            // The account tasked with verifying and submitting the claim.
        uint256 chainId;            // The chainId where the tokens are located.
        uint256[2][] idsAndAmounts; // The allocated token IDs and amounts.
        // Witness data MUST follow (mandatory for multichain compacts):
        // Mandate mandate;
    }
    ```
The `Mandate` struct within these payloads is for [Witness Structure](#witness-structure). The EIP-712 typehash for these structures is constructed dynamically; empty `Mandate` structs result in a typestring without witness data. Witness data is optional _except_ in a `MultichainCompact`; a multichain compact's elements **must** include a witness.

**Permit2 Integration Payloads:**
The Compact also supports integration with Permit2 for gasless deposits, using additional EIP-712 structures for witness data within Permit2 messages:
-   `CompactDeposit(bytes12 lockTag,address recipient)`: For basic Permit2 deposits.
-   `Activation(uint256 id,Compact compact)Compact(...)Mandate(...)`: Combines deposits with single compact registration.
-   `BatchActivation(uint256[] ids,Compact compact)Compact(...)Mandate(...)`: Combines deposits with batch compact registration.

### Witness Structure
The witness mechanism (`Mandate` struct) allows extending compacts with additional data for specifying conditions or parameters for a claim. The Compact protocol itself doesn't interpret the `Mandate`'s content; this is the responsibility of the arbiter. However, The Compact uses the hash of the witness data and its reconstructed EIP-712 typestring to derive the final claim hash for validation.

**Format:**
The witness is always a `Mandate` struct appended to the compact.

```solidity
Compact(..., Mandate mandate)Mandate(uint256 myArg, bytes32 otherArg)
```

The `witnessTypestring` provided during a claim should be the arguments *inside* the `Mandate` struct (e.g., `uint256 myArg,bytes32 otherArg`), followed by any nested structs. Note that there are no assumptions made by the protocol about the shape of the `Mandate` or any nested structs within it.

**Nested Structs:**
EIP-712 requires nested structs to be ordered alphanumerically after the top-level struct in the typestring. We recommend prefixing nested structs with "Mandate" (e.g., `MandateCondition`) to ensure correct ordering. Failure to do so will result in an _invalid_ EIP-712 typestring.

For example, the correct witness typestring for `Mandate(MandateCondition condition,uint256 arg)MandateCondition(bool flag,uint256 val)` would be `MandateCondition condition,uint256 arg)MandateCondition(bool flag,uint256 val` (_without_ a closing parenthesis).

> ☝️ Note the missing closing parenthesis in the above example. It will be added by the protocol during the dynamic typestring construction, so **do not include the closing parenthesis in your witness typestring.** This is crucial, otherwise the generated typestring _will be invalid_.

### Registration
As an alternative to sponsors signing EIP-712 payloads, compacts can be *registered* directly on The Compact contract. This involves submitting a `claimHash` (derived from the intended compact details) and its `typehash`.
This supports:
-   Sponsors without direct signing capabilities (e.g., DAOs, protocols).
-   Smart wallet / EIP-7702 enabled sponsors with alternative signature logic.
-   Chained deposit-and-register operations.

Registration can be done by the sponsor or a third party (if they provide the sponsor's signature for `registerFor` type functions, or if they are providing the deposited tokens). When registering, the duration is inferred from the _shortest_ reset period of the involved locks. Registered compacts cannot be unregistered; they can be invalidated by the allocator consuming the nonce or by letting them expire.

### Claimant Processing & Structure
When an arbiter submits a claim, they provide an array of `Component` structs. Each `Component` specifies an `amount` and a `claimant`.
```solidity
// Defined in src/types/Components.sol
struct Component {
    uint256 claimant; // The lockTag + recipient of the transfer or withdrawal.
    uint256 amount;   // The amount of tokens to transfer or withdraw.
}
```
The `claimant` field encodes both the `recipient` address (lower 160 bits) and a `bytes12 lockTag` (upper 96 bits): `claimant = (lockTag << 160) | recipient`.

This encoding determines how The Compact processes each component of the claim:
1.  **Direct ERC6909 Transfer:** If the encoded `lockTag` matches the `lockTag` of the resource lock being claimed, the `amount` of ERC6909 tokens is transferred directly to the `recipient`.
2.  **Convert Between Resource Locks:** If the encoded `lockTag` is non-zero and *different* from the claimed lock's tag, The Compact attempts to _convert_ the claimed resource lock to a new one defined by the encoded `lockTag` for the `recipient`. This allows changing allocator, reset period, or scope.
3.  **Withdraw Underlying Tokens:** If the encoded `lockTag` is `bytes12(0)`, The Compact attempts to withdraw the underlying tokens (native or ERC20) from the resource lock and send them to the `recipient`.

**Withdrawal Fallback Mechanism:**
To prevent griefing (e.g., via malicious receive hooks during withdrawals, or relayed claims that intentionally underpay the necessary amount of gas), The Compact first attempts withdrawals with half the available gas. If this fails (and sufficient gas remains above a benchmarked stipend), it falls back to a direct ERC6909 transfer to the recipient. Stipends can be queried via [`getRequiredWithdrawalFallbackStipends`](./src/interfaces/ITheCompact.sol#L650). Benchmarking for these stipends is done via a call to `__benchmark` post-deployment, which meters cold account access and typical ERC20 and native transfers. This benchmark can be re-run by anyone at any time.

### Forced Withdrawals
This mechanism provides sponsors recourse if an allocator becomes unresponsive or censors requests.
1.  **Enable:** Sponsor calls [`enableForcedWithdrawal(uint256 id)`](./src/interfaces/ITheCompact.sol#L500).
2.  **Wait:** The `resetPeriod` for that resource lock must elapse.
3.  **Withdraw:** Sponsor calls [`forcedWithdrawal(uint256 id, address recipient, uint256 amount)`](./src/interfaces/ITheCompact.sol#L521) to retrieve the underlying tokens.

The forced withdrawal state can be reversed with [`disableForcedWithdrawal(uint256 id)`](./src/interfaces/ITheCompact.sol#L508).

### Signature Verification
When a claim is submitted for a non-registered compact (i.e., one relying on a sponsor's signature), The Compact verifies the sponsor's authorization in the following order:
1.  **Caller is Sponsor:** If `msg.sender == sponsor`, authorization is granted.
2.  **ECDSA Signature:** Attempt standard ECDSA signature verification.
3.  **EIP-1271 `isValidSignature`:** If ECDSA fails, call `isValidSignature` on the sponsor's address (if it's a contract) with half the remaining gas.
4.  **Emissary `verifyClaim`:** If EIP-1271 fails or isn't applicable, and an emissary is assigned for the sponsor and `lockTag`, call the emissary's [`verifyClaim`](./src/interfaces/IEmissary.sol#L13) function.

Sponsors cannot unilaterally cancel a signed compact; only allocators can effectively do so by consuming the nonce. This is vital to upholding the equivocation guarantees for claimants.

## Key Events
The Compact emits several events to signal important state changes:

-   `Claim(address indexed sponsor, address indexed allocator, address indexed arbiter, bytes32 claimHash, uint256 nonce)`: Emitted when a claim is successfully processed via [`ITheCompactClaims`](./src/interfaces/ITheCompactClaims.sol) functions. ([`ITheCompact.sol#L35`](./src/interfaces/ITheCompact.sol#L35))
-   `NonceConsumedDirectly(address indexed allocator, uint256 nonce)`: Emitted when an allocator directly consumes a nonce via [`consume`](./src/interfaces/ITheCompact.sol#L550). ([`ITheCompact.sol#L44`](./src/interfaces/ITheCompact.sol#L44))
-   `ForcedWithdrawalStatusUpdated(address indexed account, uint256 indexed id, bool activating, uint256 withdrawableAt)`: Emitted when `enableForcedWithdrawal` or `disableForcedWithdrawal` is called. ([`ITheCompact.sol#L53`](./src/interfaces/ITheCompact.sol#L53))
-   `CompactRegistered(address indexed sponsor, bytes32 claimHash, bytes32 typehash)`: Emitted when a compact is registered via `register`, `registerMultiple`, or combined deposit-and-register functions. ([`ITheCompact.sol#L63`](./src/interfaces/ITheCompact.sol#L63))
-   `AllocatorRegistered(uint96 allocatorId, address allocator)`: Emitted when a new allocator is registered via [`__registerAllocator`](./src/interfaces/ITheCompact.sol#L561). ([`ITheCompact.sol#L70`](./src/interfaces/ITheCompact.sol#L70))
-   `EmissaryAssigned(address indexed sponsor, bytes12 indexed lockTag, address emissary)`: Emitted when a sponsor assigns or changes an emissary via [`assignEmissary`](./src/interfaces/ITheCompact.sol#L532). ([`EmissaryLib.sol#L46`](./src/lib/EmissaryLib.sol#L46))

Standard `ERC6909.Transfer` events are also emitted for mints, burns, and transfers of resource lock tokens.

## Key Data Structures
Many functions in The Compact use custom structs for their calldata. Here are some of the most important ones:

-   **For Claims (passed to `ITheCompactClaims` functions):**
    -   `Claim` ([`src/types/Claims.sol`](./src/types/Claims.sol)): For claims involving a single resource lock on a single chain.
        ```solidity
        // Defined in src/types/Claims.sol
        struct Claim {
            bytes allocatorData;
            bytes sponsorSignature;
            address sponsor;
            uint256 nonce;
            uint256 expires;
            bytes32 witness;
            string witnessTypestring;
            uint256 id;
            uint256 allocatedAmount;
            Component[] claimants;
        }
        ```
    -   `BatchClaim` ([`src/types/BatchClaims.sol`](./src/types/BatchClaims.sol)): For multiple resource locks on a single chain.
    -   `MultichainClaim` ([`src/types/MultichainClaims.sol`](./src/types/MultichainClaims.sol)): For single resource lock claims on the notarized (i.e., origin) chain of a multichain compact.
    -   `ExogenousMultichainClaim` ([`src/types/MultichainClaims.sol`](./src/types/MultichainClaims.sol)): For single resource lock claims on an exogenous chain (i.e., any chain _other than_ the notarized chain).
    -   `BatchMultichainClaim` ([`src/types/BatchMultichainClaims.sol`](./src/types/BatchMultichainClaims.sol)): For multiple resource locks on the notarized chain.
    -   `ExogenousBatchMultichainClaim` ([`src/types/BatchMultichainClaims.sol`](./src/types/BatchMultichainClaims.sol)): For multiple resource locks on an exogenous chain.
    -   `BatchClaimComponent` ([`src/types/Components.sol`](./src/types/Components.sol)): Used within batch claim structs.
        ```solidity
        // Defined in src/types/Components.sol
        struct BatchClaimComponent {
            uint256 id;
            uint256 allocatedAmount;
            Component[] portions;
        }
        ```

-   **For Allocated Transfers (passed to `ITheCompact.allocatedTransfer` etc.):**
    -   `AllocatedTransfer` ([`src/types/Claims.sol`](./src/types/Claims.sol)): For transferring a single ID to multiple recipients with allocator approval.
        ```solidity
        // Defined in src/types/Claims.sol
        struct AllocatedTransfer {
            bytes allocatorData;
            uint256 nonce;
            uint256 expires;
            uint256 id;
            Component[] recipients;
        }
        ```
    -   `AllocatedBatchTransfer` ([`src/types/BatchClaims.sol`](./src/types/BatchClaims.sol)): For transferring multiple IDs.

-   **For Deposits (used with Permit2):**
    -   `DepositDetails` ([`src/types/DepositDetails.sol`](./src/types/DepositDetails.sol)): Helper for batch Permit2 deposits.

Refer to the files in `src/types/` for all struct definitions.

## Setup
```
# install foundry if needed
$ curl -L https://foundry.paradigm.xyz | bash

# clone repo
$ git clone git@github.com:Uniswap/the-compact.git && cd the-compact

# install dependencies & libraries
$ forge install

# run the tests & gas snapshots
$ forge test -v

# run coverage & generate report
$ forge coverage
```

## Usage (Flows by Actor)

The Compact V1 facilitates interactions between several key actors. Here's how typical participants might use the system. See the full interface definitions in [`src/interfaces/`](./src/interfaces/) and detailed explanations in [Key Concepts](#key-concepts).

### Sponsors (Depositors)

Sponsors own the underlying assets and create resource locks to make them available under specific conditions.

**1. Create a Resource Lock (Deposit Tokens):**
    - A sponsor starts by depositing assets (native tokens or ERC20s) into The Compact. This action creates ERC6909 tokens representing ownership of the resource lock.
    - During deposit, the sponsor defines the lock's properties: the **allocator** (who must be registered first, see [Allocators (Infrastructure)](#allocators-infrastructure) and [Key Concepts: Allocators](#allocators)), the **scope** (single-chain or multichain), and the **reset period** (for forced withdrawals and emissary replacements). These are packed into a `bytes12 lockTag`. A resource lock's ID is a combination of its lock tag and the underlying token's address.
    - Deposit methods (see [`ITheCompact.sol`](./src/interfaces/ITheCompact.sol)):
        - Native tokens: [`depositNative`](./src/interfaces/ITheCompact.sol#L81)
        - ERC20 tokens (requires direct approval): [`depositERC20`](./src/interfaces/ITheCompact.sol#L97)
        - Batch deposits (native + ERC20): [`batchDeposit`](./src/interfaces/ITheCompact.sol#L114)
        - Via Permit2 (optionally gasless): [`depositERC20ViaPermit2`](./src/interfaces/ITheCompact.sol#L131), [`batchDepositViaPermit2`](./src/interfaces/ITheCompact.sol#L157)
    - See [Key Concepts: Resource Locks](#resource-locks) for details on token handling.

**2. Create a Compact:**
    - To make locked funds available for claiming, a sponsor creates a compact, defining terms and designating an **arbiter**.
    - **Option A: Signing an EIP-712 Payload:** The sponsor signs a `Compact`, `BatchCompact`, or `MultichainCompact` payload. This signed payload is given to the arbiter. See [Key Concepts: Compacts & EIP-712 Payloads](#compacts--eip-712-payloads).
    - **Option B: Registering the Compact:** The sponsor (or a third party with an existing sponsor signature) registers the *hash* of the intended compact details using [`register`](./src/interfaces/ITheCompact.sol#L204) or combined deposit-and-register functions. It is also possible to deposit tokens on behalf of a sponsor and register a compact using only the deposited tokens without the sponsor's signature using the `depositAndRegisterFor` (or the batch and permit2 variants). See [Key Concepts: Registration](#registration).

**3. (Optional) Transfer Resource Lock Ownership:**
    - Sponsors can transfer their ERC6909 tokens, provided they have authorization from the allocator.
    - Standard ERC6909 transfers require allocator [`attest`](./src/interfaces/IAllocator.sol#L14).
    - Alternatively, use [`allocatedTransfer`](./src/interfaces/ITheCompact.sol#L177) or [`allocatedBatchTransfer`](./src/interfaces/ITheCompact.sol#L193) with explicit `allocatorData`.

**4. (Optional) Assign an Emissary:**
    - Designate an [`IEmissary`](./src/interfaces/IEmissary.sol) using [`assignEmissary`](./src/interfaces/ITheCompact.sol#L532) as a fallback authorizer. See [Key Concepts: Emissaries](#emissaries).

**5. (Optional) Initiate Forced Withdrawal:**
    - If an allocator is unresponsive, use [`enableForcedWithdrawal`](./src/interfaces/ITheCompact.sol#L500), wait `resetPeriod`, then [`forcedWithdrawal`](./src/interfaces/ITheCompact.sol#L521). See [Key Concepts: Forced Withdrawals](#forced-withdrawals).

### Arbiters & Claimants (e.g. Fillers)

Arbiters verify conditions and process claims. Claimants are the recipients.

**1. Receive Compact Details:**
    - Obtain compact details (signed payload or registered compact info).

**2. Fulfill Compact Conditions:**
    - Perform the action defined by the compact (often off-chain).

**3. Obtain Allocator Authorization:**
    - This relies on the allocator's on-chain `authorizeClaim` logic. Note that the arbiter may submit `allocatorData` (i.e., an allocator's signature or other proof the allocator understands) which the allocator can evaluate as part of its authorization flow.

**4. Submit the Claim:**
    - Call the appropriate claim function on [`ITheCompactClaims`](./src/interfaces/ITheCompactClaims.sol) with the claim payload (e.g., `Claim`, `BatchClaim`).
    - The payload includes `allocatorData`, `sponsorSignature` (if not registered), lock details, and `claimants` array.
    - See [Key Concepts: Claimant Processing & Structure](#claimant-processing--structure) for how claims are processed.
    - Successful execution emits a `Claim` event and consumes the nonce.

### Relayers

Relayers can perform certain interactions on behalf of sponsors and/or claimants.

**1. Relaying Permit2 Interactions:**
    - Submit user-signed Permit2 messages for deposits/registrations (e.g., [`depositERC20ViaPermit2`](./src/interfaces/ITheCompact.sol#L131), [`depositERC20AndRegisterViaPermit2`](./src/interfaces/ITheCompact.sol#L451), or the batch variants). For the register variants, this role is called the `Activator` and the registration is authorized by the sponsor as part of the Permit2 witness data.

**2. Relaying Registrations-for-Sponsor:**
    - Submit sponsor-signed registration details using `registerFor` functions (e.g., [`registerFor`](./src/interfaces/ITheCompact.sol#L229)).

**3. Relaying Claims:**
    - Submit authorized claims on behalf of a claimant using the standard `claim` functions. This would generally be performed by the arbiter of the claim being relayed.

### Allocators (Infrastructure)

Allocators are crucial infrastructure for ensuring resource lock integrity.

**1. Registration:**
    - Register via [`__registerAllocator`](./src/interfaces/ITheCompact.sol#L561) to get an `allocatorId`. This is a required step that must be performed before the allocator may be assigned to a resource lock. Anyone can register an allocator if one of three conditions is met: the caller is the allocator address being registered; the allocator address contains code; or a proof is supplied representing valid create2 deployment parameters.

**2. Implement `IAllocator` Interface:**
    - Deploy a contract implementing [`IAllocator`](./src/interfaces/IAllocator.sol).
    - `attest`: Called during ERC6909 transfers. Must verify safety and return `IAllocator.attest.selector`.
    - `authorizeClaim` / `isClaimAuthorized`: Core logic to validate claims against sponsor balances and nonces. `authorizeClaim` returns `IAllocator.authorizeClaim.selector` for on-chain validation.

**3. (Optional) Off-chain Logic / `allocatorData` Generation:**
    - Allocators may have off-chain systems that track balances, validate requests, generate `allocatorData` (e.g., signatures), and/or manage nonces.
    - The Compact is unopinionated about the particulars of allocator implementations.
    - Two basic sample implementations have been provided: [Smallocator](https://github.com/uniswap/smallocator) and [Autocator](https://github.com/uniswap/autocator).

**4. (Optional) Consuming Nonces:**
    - Proactively invalidate compacts using [`consume`](./src/interfaces/ITheCompact.sol#L550) on The Compact contract.

## View Functions
The Compact provides several view functions defined in the [`ITheCompact`](./src/interfaces/ITheCompact.sol) interface for querying state:
-   [`getLockDetails`](./src/interfaces/ITheCompact.sol#L582): Retrieves details (token, allocator, reset period, scope, lockTag) for a resource lock ID.
-   [`getRegistrationStatus`](./src/interfaces/ITheCompact.sol#L598): Checks if a compact is registered and its registration time.
-   [`getForcedWithdrawalStatus`](./src/interfaces/ITheCompact.sol#L613): Checks the current forced withdrawal status (Disabled, Pending, Enabled) for an account and lock ID.
-   [`getEmissaryStatus`](./src/interfaces/ITheCompact.sol#L628): Gets the current emissary status (Disabled, Scheduled, Enabled) for a sponsor and lock tag.
-   [`hasConsumedAllocatorNonce`](./src/interfaces/ITheCompact.sol#L640): Checks if an allocator has consumed a specific nonce.
-   [`getRequiredWithdrawalFallbackStipends`](./src/interfaces/ITheCompact.sol#L650): Returns gas stipends needed for withdrawal fallbacks.
-   [`DOMAIN_SEPARATOR`](./src/interfaces/ITheCompact.sol#L659): Returns the EIP-712 domain separator for the contract.
-   [`name`](./src/interfaces/ITheCompact.sol#L665): Returns the contract name ("TheCompact").

All standard ERC6909 ([EIP-6909](https://eips.ethereum.org/EIPS/eip-6909)) and ERC165 ([EIP-165](https://eips.ethereum.org/EIPS/eip-165)) functions are also supported, as well as [Extslod](./src/lib/Extsload.sol) to allow arbitrary sload/tload by slot. 

## Core Interfaces Overview

### ITheCompact
[`src/interfaces/ITheCompact.sol`](./src/interfaces/ITheCompact.sol)

The core interface for The Compact protocol. It provides functions for:
-   **Deposits:** `depositNative`, `depositERC20`, `batchDeposit`, and their Permit2 variants (`depositERC20ViaPermit2`, `batchDepositViaPermit2`).
-   **Allocated Transfers:** `allocatedTransfer`, `allocatedBatchTransfer` for moving ERC6909 tokens with allocator approval.
-   **Registration:** `register`, `registerMultiple`, `registerFor`, `registerBatchFor`, `registerMultichainFor` to register compacts.
-   **Combined Deposit & Registration:** Numerous functions like `depositNativeAndRegister`, `depositERC20AndRegisterFor`, and their Permit2 variants.
-   **Forced Withdrawals:** `enableForcedWithdrawal`, `disableForcedWithdrawal`, `forcedWithdrawal`.
-   **Emissary Management:** `assignEmissary`, `scheduleEmissaryAssignment`.
-   **Allocator Management:** `__registerAllocator`, `consume` (for allocators to consume nonces).
-   **View Functions:** As listed in the [View Functions](#view-functions) section.

### ITheCompactClaims
[`src/interfaces/ITheCompactClaims.sol`](./src/interfaces/ITheCompactClaims.sol)

The claims interface, providing endpoints for arbiters to settle compacts.
-   **Single Chain Claims:**
    -   `claim(Claim calldata claimPayload)`: For standard single-chain, single-ID claims.
    -   `batchClaim(BatchClaim calldata claimPayload)`: For multiple IDs on a single chain.
-   **Multichain Claims:**
    -   `multichainClaim(MultichainClaim calldata claimPayload)`: For the notarized chain of a multichain compact.
    -   `exogenousClaim(ExogenousMultichainClaim calldata claimPayload)`: For an exogenous chain of a multichain compact.
    -   `batchMultichainClaim(BatchMultichainClaim calldata claimPayload)`: Batch version for the notarized chain.
    -   `exogenousBatchClaim(ExogenousBatchMultichainClaim calldata claimPayload)`: Batch version for an exogenous chain.

Multichain claims involve "elements" defining commitments per chain. The "notarized chain" is the first element's chain, matching the EIP-712 domain of the sponsor's signature. "Exogenous chains" are all other chains specified in a multichain compact. Note that exogenous claims require locks with a `Multichain` scope; it is not possible to claim chain-specific resource locks on any exogenous chain.

### IAllocator (Interface)
[`src/interfaces/IAllocator.sol`](./src/interfaces/IAllocator.sol)

Interface that allocators must implement.
-   `attest(address operator, address from, address to, uint256 id, uint256 amount) external returns (bytes4)`: Called on standard ERC6909 transfers to validate them. Must return `IAllocator.attest.selector`.
-   `authorizeClaim(bytes32 claimHash, address arbiter, address sponsor, uint256 nonce, uint256 expires, uint256[2][] calldata idsAndAmounts, bytes calldata allocatorData) external returns (bytes4)`: Called by The Compact during claim processing for on-chain authorization. Must return `IAllocator.authorizeClaim.selector`.
-   `isClaimAuthorized(...) external view returns (bool)`: Off-chain view function to check if a given claim _would_ be authorized. It should perform the same authorization checks as `authorizeClaim`.

### IEmissary (Interface)
[`src/interfaces/IEmissary.sol`](./src/interfaces/IEmissary.sol)

Interface for emissaries, providing fallback claim verification.
-   `verifyClaim(address sponsor, bytes32 claimHash, bytes calldata signature, bytes12 lockTag) external view returns (bytes4)`: Called by The Compact during claim processing _only if all other sponsor verification methods fail_. Must return `IEmissary.verifyClaim.selector`.

## Contract Layout
The Compact V1 is deployed as a single contract (`src/TheCompact.sol`), with the exception of a metadata renderer that surfaces metadata for resource locks (`src/lib/MetadataRenderer.sol`). The deployed contract is comprised of multiple inherited logic contracts which in turn make extensive use of specialized libraries (see `src/lib/TheCompactLogic.sol`). A shared set of struct and enum types are utilized throughout the codebase and as a component in many function interfaces.

## Credits
The Compact was developed by [@0age](https://github.com/0age), [@ccashwell](https://github.com/ccashwell) and [@mgretzke](https://github.com/mgretzke) ([Uniswap Labs](https://uniswap.org)), with significant contributions from [@zeroknots](https://github.com/zeroknots) ([Rhinetone](https://rhinestone.wtf)) and [@reednaa](https://github.com/reednaa) ([LI.FI](https://li.fi)).

## License
The Compact is published under the MIT License. See the [LICENSE](LICENSE.md) file for full details.
