// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Component } from "./Components.sol";

struct MultichainClaim {
    bytes allocatorData; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    bytes32[] additionalChains; // The element hashes from additional chains.
    uint256 id; // The token ID of the ERC6909 token to allocate.
    uint256 allocatedAmount; // The original allocated amount of ERC6909 tokens.
    Component[] claimants; // The claim recipients and amounts; specified by the arbiter.
}

struct ExogenousMultichainClaim {
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
    uint256 id; // The token ID of the ERC6909 token to allocate.
    uint256 allocatedAmount; // The original allocated amount of ERC6909 tokens.
    Component[] claimants; // The claim recipients and amounts; specified by the arbiter.
}
