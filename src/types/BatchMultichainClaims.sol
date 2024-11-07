// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BatchClaimComponent, SplitBatchClaimComponent } from "./Components.sol";

struct BatchMultichainClaim {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    BatchClaimComponent[] claims; // IDs and amounts.
    address claimant; // The claim recipient; specified by the arbiter.
}

struct QualifiedBatchMultichainClaim {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 qualificationTypehash; // Typehash of the qualification payload.
    bytes qualificationPayload; // Data used to derive qualification hash.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    BatchClaimComponent[] claims; // IDs and amounts.
    address claimant; // The claim recipient; specified by the arbiter.
}

struct BatchMultichainClaimWithWitness {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    BatchClaimComponent[] claims; // IDs and amounts.
    address claimant; // The claim recipient; specified by the arbiter.
}

struct QualifiedBatchMultichainClaimWithWitness {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32 qualificationTypehash; // Typehash of the qualification payload.
    bytes qualificationPayload; // Data used to derive qualification hash.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    BatchClaimComponent[] claims; // IDs and amounts.
    address claimant; // The claim recipient; specified by the arbiter.
}

struct SplitBatchMultichainClaim {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    SplitBatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}

struct SplitBatchMultichainClaimWithWitness {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    SplitBatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}

struct QualifiedSplitBatchMultichainClaim {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 qualificationTypehash; // Typehash of the qualification payload.
    bytes qualificationPayload; // Data used to derive qualification hash.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    SplitBatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}

struct QualifiedSplitBatchMultichainClaimWithWitness {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32 qualificationTypehash; // Typehash of the qualification payload.
    bytes qualificationPayload; // Data used to derive qualification hash.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    SplitBatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}

struct ExogenousBatchMultichainClaim {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    uint256 chainIndex; // The index after which to insert the current allocation hash.
    uint256 notarizedChainId; // The chain id used to sign the multichain claim.
    BatchClaimComponent[] claims; // IDs and amounts.
    address claimant; // The claim recipient; specified by the arbiter.
}

struct ExogenousQualifiedBatchMultichainClaim {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 qualificationTypehash; // Typehash of the qualification payload.
    bytes qualificationPayload; // Data used to derive qualification hash.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    uint256 chainIndex; // The index after which to insert the current allocation hash.
    uint256 notarizedChainId; // The chain id used to sign the multichain claim.
    BatchClaimComponent[] claims; // IDs and amounts.
    address claimant; // The claim recipient; specified by the arbiter.
}

struct ExogenousBatchMultichainClaimWithWitness {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    uint256 chainIndex; // The index after which to insert the current allocation hash.
    uint256 notarizedChainId; // The chain id used to sign the multichain claim.
    BatchClaimComponent[] claims; // IDs and amounts.
    address claimant; // The claim recipient; specified by the arbiter.
}

struct ExogenousQualifiedBatchMultichainClaimWithWitness {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32 qualificationTypehash; // Typehash of the qualification payload.
    bytes qualificationPayload; // Data used to derive qualification hash.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    uint256 chainIndex; // The index after which to insert the current allocation hash.
    uint256 notarizedChainId; // The chain id used to sign the multichain claim.
    BatchClaimComponent[] claims; // IDs and amounts.
    address claimant; // The claim recipient; specified by the arbiter.
}

struct ExogenousSplitBatchMultichainClaim {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    uint256 chainIndex; // The index after which to insert the current allocation hash.
    uint256 notarizedChainId; // The chain id used to sign the multichain claim.
    SplitBatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}

struct ExogenousSplitBatchMultichainClaimWithWitness {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    uint256 chainIndex; // The index after which to insert the current allocation hash.
    uint256 notarizedChainId; // The chain id used to sign the multichain claim.
    SplitBatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}

struct ExogenousQualifiedSplitBatchMultichainClaim {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 qualificationTypehash; // Typehash of the qualification payload.
    bytes qualificationPayload; // Data used to derive qualification hash.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    uint256 chainIndex; // The index after which to insert the current allocation hash.
    uint256 notarizedChainId; // The chain id used to sign the multichain claim.
    SplitBatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}

struct ExogenousQualifiedSplitBatchMultichainClaimWithWitness {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32 qualificationTypehash; // Typehash of the qualification payload.
    bytes qualificationPayload; // Data used to derive qualification hash.
    bytes32[] additionalChains; // The allocation hashes from additional chains.
    uint256 chainIndex; // The index after which to insert the current allocation hash.
    uint256 notarizedChainId; // The chain id used to sign the multichain claim.
    SplitBatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}
