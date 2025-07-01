// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITheCompactClaims } from "../interfaces/ITheCompactClaims.sol";
import { ClaimProcessorLogic } from "./ClaimProcessorLogic.sol";

import { Claim } from "../types/Claims.sol";

import { BatchClaim } from "../types/BatchClaims.sol";

import { MultichainClaim, ExogenousMultichainClaim } from "../types/MultichainClaims.sol";

import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../types/BatchMultichainClaims.sol";

/**
 * @title ClaimProcessor
 * @notice Inherited contract implementing external functions for processing claims against
 * a signed or registered compact. Each of these functions is only callable by the arbiter
 * indicated by the respective compact.
 */
contract ClaimProcessor is ITheCompactClaims, ClaimProcessorLogic {
    /**
     * @notice Process a basic claim with a single resource lock on a single chain.
     * @param claimPayload The claim data containing signature, allocator data, and compact details.
     * @return claimHash   The hash of the processed claim.
     */
    function claim(Claim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processClaim(claimPayload);
    }

    /**
     * @notice Process a batch claim for multiple resource locks on a single chain.
     * @param claimPayload The batch claim data containing signature, allocator data, and compact details.
     * @return claimHash   The hash of the processed batch claim.
     */
    function batchClaim(BatchClaim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processBatchClaim(claimPayload);
    }

    /**
     * @notice Process a multichain claim for an element with a single resource lock on the notarized chain (where domain matches the one signed for).
     * @param claimPayload The multichain claim data containing signature, allocator data, compact details, and relevant chain elements.
     * @return claimHash   The hash of the processed multichain claim.
     */
    function multichainClaim(MultichainClaim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processMultichainClaim(claimPayload);
    }

    /**
     * @notice Process a multichain claim for an element with a single resource lock on an exogenous chain (not the notarized chain).
     * @param claimPayload The exogenous multichain claim data containing signature, allocator data, compact details, chain index, and notarized chain ID, and relevant chain elements.
     * @return claimHash   The hash of the processed exogenous multichain claim.
     */
    function exogenousClaim(ExogenousMultichainClaim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processExogenousMultichainClaim(claimPayload);
    }

    /**
     * @notice Process a multichain claim for an element with multiple resource locks on the notarized chain (where domain matches the one signed for).
     * @param claimPayload The multichain claim data containing signature, allocator data, compact details, and relevant chain elements.
     * @return claimHash   The hash of the processed multichain claim.
     */
    function batchMultichainClaim(BatchMultichainClaim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processBatchMultichainClaim(claimPayload);
    }

    /**
     * @notice Process a multichain claim for an element with multiple resource locks on an exogenous chain (not the notarized chain).
     * @param claimPayload The exogenous multichain claim data containing signature, allocator data, compact details, chain index, and notarized chain ID, and relevant chain elements.
     * @return claimHash   The hash of the processed exogenous multichain claim.
     */
    function exogenousBatchClaim(ExogenousBatchMultichainClaim calldata claimPayload)
        external
        returns (bytes32 claimHash)
    {
        return _processExogenousBatchMultichainClaim(claimPayload);
    }
}
