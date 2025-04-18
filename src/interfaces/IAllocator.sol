// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

interface IAllocator {
    /**
     * @notice Called on standard transfers to validate the transfer.
     * @param operator The address performing the transfer.
     * @param from     The address tokens are being transferred from.
     * @param to       The address tokens are being transferred to.
     * @param id       The ERC6909 token identifier being transferred.
     * @param amount   The amount of tokens being transferred.
     * @return         Must return this function selector (0x1a808f91).
     */
    function attest(address operator, address from, address to, uint256 id, uint256 amount) external returns (bytes4);

    /**
     * @notice Authorize a claim. Called from The Compact as part of claim processing.
     * @param claimHash      The message hash representing the claim.
     * @param arbiter        The account tasked with verifying and submitting the claim.
     * @param sponsor        The account to source the tokens from.
     * @param nonce          A parameter to enforce replay protection, scoped to allocator.
     * @param expires        The time at which the claim expires.
     * @param idsAndAmounts  The allocated token IDs and amounts.
     * @param allocatorData  Arbitrary data provided by the arbiter.
     * @return               Must return the function selector (0x7bb023f7).
     */
    function authorizeClaim(
        bytes32 claimHash,
        address arbiter,
        address sponsor,
        uint256 nonce,
        uint256 expires,
        uint256[2][] calldata idsAndAmounts,
        bytes calldata allocatorData
    ) external returns (bytes4);

    /**
     * @notice Check if given allocatorData authorizes a claim. Intended to be called offchain.
     * @param claimHash      The message hash representing the claim.
     * @param arbiter        The account tasked with verifying and submitting the claim.
     * @param sponsor        The account to source the tokens from.
     * @param nonce          A parameter to enforce replay protection, scoped to allocator.
     * @param expires        The time at which the claim expires.
     * @param idsAndAmounts  The allocated token IDs and amounts.
     * @param allocatorData  Arbitrary data provided by the arbiter.
     * @return               A boolean indicating whether the claim is authorized.
     */
    function isClaimAuthorized(
        bytes32 claimHash,
        address arbiter,
        address sponsor,
        uint256 nonce,
        uint256 expires,
        uint256[2][] calldata idsAndAmounts,
        bytes calldata allocatorData
    ) external view returns (bool);
}
