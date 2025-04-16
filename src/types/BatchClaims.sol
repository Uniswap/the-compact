// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { SplitByIdComponent, SplitBatchClaimComponent } from "./Components.sol";

struct SplitBatchTransfer {
    bytes allocatorData; // Authorization from the allocator.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the transfer or withdrawal expires.
    SplitByIdComponent[] transfers; // The recipients and amounts of each transfer for each ID.
}

struct BatchClaim {
    bytes allocatorData; // Authorization from the allocator.
    bytes sponsorSignature; // Authorization from the sponsor.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    bytes32 witness; // Hash of the witness data.
    string witnessTypestring; // Witness typestring appended to existing typestring.
    SplitBatchClaimComponent[] claims; // The claim token IDs, recipients and amounts.
}
