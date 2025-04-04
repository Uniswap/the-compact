// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResetPeriod } from "../types/ResetPeriod.sol";

// NOTE: Allocators with smart contract implementations should also implement EIP1271.
interface IAllocator {
    // Called on standard transfers; must return this function selector (0x1a808f91).
    function attest(address operator, address from, address to, uint256 id, uint256 amount) external returns (bytes4);

    // Authorize a claim. Called from The Compact as part of claim processing.
    function authorizeClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address arbiter, // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256 nonce, // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) external returns (bytes4); // Must return the function selector.

    // Check if given allocatorData authorizes a claim. Intented to be called offchain.
    function isClaimAuthorized(
        bytes32 claimHash, // The message hash representing the claim.
        address arbiter, // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256 nonce, // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) external view returns (bool);
}
