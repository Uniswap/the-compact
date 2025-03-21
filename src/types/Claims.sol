// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { SplitComponent } from "./Components.sol";

struct BasicTransfer {
    bytes allocatorSignature; // Authorization from the allocator.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the transfer or withdrawal expires.
    uint256 id; // The token ID of the ERC6909 token to transfer or withdraw.
    uint256 amount; // The token amount to transfer or withdraw.
    address recipient; // The recipient of the transfer or withdrawal.
}

struct SplitTransfer {
    bytes allocatorSignature; // Authorization from the allocator.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the transfer or withdrawal expires.
    uint256 id; // The token ID of the ERC6909 token to transfer or withdraw.
    SplitComponent[] recipients; // The recipients and amounts of each transfer.
}

struct Claim {
    bytes allocatorSignature; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    uint256 id; // The token ID of the ERC6909 token to allocate.
    uint256 allocatedAmount; // The original allocated amount of ERC6909 tokens.
    SplitComponent[] claimants; // The claim recipients and amounts; specified by the arbiter.
}
