// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

interface ISignDelegator {
    // verify a claim. Called from The Compact as part of claim processing.
    function verifyClaim(
        address sponsor, // the sponsor of the claim
        bytes32 claimHash, // The message hash representing the claim.
        bytes calldata signature
    ) external returns (bytes4); // Must return the function selector.
}
