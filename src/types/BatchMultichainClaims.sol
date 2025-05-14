// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BatchClaimComponent } from "./Components.sol";

struct BatchMultichainClaim {
    bytes allocatorData; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32[] additionalChains; // The element hashes from additional chains.
    BatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}

struct ExogenousBatchMultichainClaim {
    bytes allocatorData; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32[] additionalChains; // The element hashes from additional chains.
    uint256 chainIndex; // The index after which to insert the current element hash.
    uint256 notarizedChainId; // The chain id used to sign the multichain claim.
    BatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}
