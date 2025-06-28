// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Claim, ClaimsLib } from "../types/Claims.sol";
import { BatchClaim, BatchClaimsLib } from "../types/BatchClaims.sol";
import { MultichainClaim, ExogenousMultichainClaim, MultichainClaimsLib } from "../types/MultichainClaims.sol";
import {
    BatchMultichainClaim,
    ExogenousBatchMultichainClaim,
    BatchMultichainClaimsLib
} from "../types/BatchMultichainClaims.sol";

import { ComponentLib } from "./ComponentLib.sol";
import { ClaimHashLib } from "./ClaimHashLib.sol";
import { ClaimProcessorLib } from "./ClaimProcessorLib.sol";
import { ClaimProcessorFunctionCastLib } from "./ClaimProcessorFunctionCastLib.sol";
import { DomainLib } from "./DomainLib.sol";
import { ConstructorLogic } from "./ConstructorLogic.sol";

/**
 * @title ClaimProcessorLogic
 * @notice Inherited contract implementing internal functions with logic for processing
 * claims against a signed or registered compact. Each function derives the respective
 * claim hash as well as a typehash if applicable, then processes the claim.
 * @dev IMPORTANT NOTE: this logic assumes that the utilized structs are formatted in a
 * very specific manner — if parameters are rearranged or new parameters are inserted,
 * much of this functionality will break. Proceed with caution when making any changes.
 */
contract ClaimProcessorLogic is ConstructorLogic {
    using ComponentLib for bytes32;
    using ClaimsLib for Claim;
    using BatchClaimsLib for BatchClaim;
    using MultichainClaimsLib for MultichainClaim;
    using MultichainClaimsLib for ExogenousMultichainClaim;
    using BatchMultichainClaimsLib for BatchMultichainClaim;
    using BatchMultichainClaimsLib for ExogenousBatchMultichainClaim;
    using ClaimHashLib for Claim;
    using ClaimHashLib for BatchClaim;
    using ClaimHashLib for MultichainClaim;
    using ClaimHashLib for ExogenousMultichainClaim;
    using ClaimHashLib for BatchMultichainClaim;
    using ClaimHashLib for ExogenousBatchMultichainClaim;
    using ClaimProcessorFunctionCastLib for function(bytes32, uint256, bytes32, bytes32, bytes32) internal;
    using ClaimProcessorFunctionCastLib for function(bytes32, uint256, bytes32, bytes32) internal;
    using DomainLib for uint256;

    ///// 1. Claims /////
    function _processClaim(Claim calldata claimPayload) internal returns (bytes32 claimHash) {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        bytes32 typehash;
        (claimHash, typehash) = claimPayload.toClaimHashAndTypehash();
        claimHash.processClaimWithComponents(claimPayload.asRawPtr(), 0, typehash, _domainSeparator());

        // Clear the reentrancy guard.
        _clearReentrancyGuard();
    }

    ///// 2. Batch Claims /////
    function _processBatchClaim(BatchClaim calldata claimPayload) internal returns (bytes32 claimHash) {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        bytes32 typehash;
        (claimHash, typehash) = claimPayload.toClaimHashAndTypehash();
        claimHash.processClaimWithBatchComponents(claimPayload.asRawPtr(), 0, typehash, _domainSeparator());

        // Clear the reentrancy guard.
        _clearReentrancyGuard();
    }

    ///// 3. Multichain Claims /////
    function _processMultichainClaim(MultichainClaim calldata claimPayload) internal returns (bytes32 claimHash) {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        bytes32 typehash;
        (claimHash, typehash) = claimPayload.toClaimHashAndTypehash();
        claimHash.processClaimWithComponents(claimPayload.asRawPtr(), 0, typehash, _domainSeparator());

        // Clear the reentrancy guard.
        _clearReentrancyGuard();
    }

    ///// 4. Batch Multichain Claims /////
    function _processBatchMultichainClaim(BatchMultichainClaim calldata claimPayload)
        internal
        returns (bytes32 claimHash)
    {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        bytes32 typehash;
        (claimHash, typehash) = claimPayload.toClaimHashAndTypehash();
        claimHash.processClaimWithBatchComponents(claimPayload.asRawPtr(), 0, typehash, _domainSeparator());

        // Clear the reentrancy guard.
        _clearReentrancyGuard();
    }

    ///// 5. Exogenous Multichain Claims /////
    function _processExogenousMultichainClaim(ExogenousMultichainClaim calldata claimPayload)
        internal
        returns (bytes32 claimHash)
    {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        bytes32 typehash;
        (claimHash, typehash) = claimPayload.toClaimHashAndTypehash();
        claimHash.processClaimWithComponents(
            claimPayload.asRawPtr(),
            claimPayload.notarizedChainId.toNotarizedDomainSeparator(),
            typehash,
            _domainSeparator()
        );

        // Clear the reentrancy guard.
        _clearReentrancyGuard();
    }

    ///// 6. Exogenous Batch Multichain Claims /////
    function _processExogenousBatchMultichainClaim(ExogenousBatchMultichainClaim calldata claimPayload)
        internal
        returns (bytes32 claimHash)
    {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        bytes32 typehash;
        (claimHash, typehash) = claimPayload.toClaimHashAndTypehash();
        claimHash.processClaimWithBatchComponents(
            claimPayload.asRawPtr(),
            claimPayload.notarizedChainId.toNotarizedDomainSeparator(),
            typehash,
            _domainSeparator()
        );

        // Clear the reentrancy guard.
        _clearReentrancyGuard();
    }
}
