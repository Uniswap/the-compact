// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Claim } from "../types/Claims.sol";

import { BatchClaim } from "../types/BatchClaims.sol";

import { MultichainClaim, ExogenousMultichainClaim } from "../types/MultichainClaims.sol";

import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../types/BatchMultichainClaims.sol";

/**
 * @title The Compact — Claims Interface
 * @custom:version 1
 * @author 0age (0age.eth)
 * @notice Claim endpoints can only be called by the arbiter indicated on the associated
 * compact, and are used to settle the compact in question. There are 6 endpoints in total,
 * based on the following factors:
 *  - whether or not to utilize a "batch" of resource locks on a specific chain: When the
 *    sponsor is utilizing multiple resource locks on a specific chain, they will sign or
 *    register a `BatchCompact` EIP-712 payload. (Single-chain claims sign or register a
 *    `Compact` EIP-712 payload).
 *  - whether or not to include resource locks on a single chain or multiple chains; in
 *    the event of a multichain compact, there are _two_ additional endpoints per option,
 *    one for claims against the first referenced chain where the domain matches the one
 *    signed for or registered against (the "notarized" chain) and one for claims against
 *    other chains where the resource locks indicate a multichain scope (the "exogenous"
 *    chains). When the sponsor is utilizing multiple resource locks across multiple chains,
 *    they will sign a `MultichainCompact` EIP-712 payload. When claiming these for the
 *    notarized chain, an array of bytes32 values representing additional chain "elements"
 *    is provided. When claiming against an exogenous chain, the additional chains array
 *    begins with the notarized chain and then includes values for all exogenous chains
 *    excluding the one being claimed against, and a chain index is supplied indicating the
 *    location in the list of elements of the current chain (a value of 0 means that it is)
 *    the first exogenous chain) as well as a `notarizedChainId` representing the chainId
 *    for the domain that the multichain claim was signed against.
 */
interface ITheCompactClaims {
    /**
     * @notice Process a standard single-chain claim.
     * @param claimPayload The claim data containing signature, allocator data, and compact details.
     * @return claimHash   The hash of the processed claim.
     */
    function claim(Claim calldata claimPayload) external returns (bytes32 claimHash);

    /**
     * @notice Process a batch claim for multiple resource locks on a single chain.
     * @param claimPayload The batch claim data containing signature, allocator data, and compact details.
     * @return claimHash   The hash of the processed batch claim.
     */
    function batchClaim(BatchClaim calldata claimPayload) external returns (bytes32 claimHash);

    /**
     * @notice Process a multichain claim for the notarized chain (where domain matches the one signed for).
     * @param claimPayload The multichain claim data containing signature, allocator data, compact details, and chain elements.
     * @return claimHash   The hash of the processed multichain claim.
     */
    function multichainClaim(MultichainClaim calldata claimPayload) external returns (bytes32 claimHash);

    /**
     * @notice Process a multichain claim for an exogenous chain (not the notarized chain).
     * @param claimPayload The exogenous multichain claim data containing signature, allocator data, compact details, chain index, and notarized chain ID.
     * @return claimHash   The hash of the processed exogenous multichain claim.
     */
    function exogenousClaim(ExogenousMultichainClaim calldata claimPayload) external returns (bytes32 claimHash);

    /**
     * @notice Process a batch multichain claim for multiple resource locks on the notarized chain.
     * @param claimPayload The batch multichain claim data containing signature, allocator data, compact details, and chain elements.
     * @return claimHash   The hash of the processed batch multichain claim.
     */
    function batchMultichainClaim(BatchMultichainClaim calldata claimPayload) external returns (bytes32 claimHash);

    /**
     * @notice Process a batch multichain claim for multiple resource locks on an exogenous chain.
     * @param claimPayload The exogenous batch multichain claim data containing signature, allocator data, compact details, chain index, and notarized chain ID.
     * @return claimHash   The hash of the processed exogenous batch multichain claim.
     */
    function exogenousBatchClaim(ExogenousBatchMultichainClaim calldata claimPayload)
        external
        returns (bytes32 claimHash);
}
