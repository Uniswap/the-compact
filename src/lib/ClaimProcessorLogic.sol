// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Claim } from "../types/Claims.sol";
import { BatchClaim } from "../types/BatchClaims.sol";
import { MultichainClaim, ExogenousMultichainClaim } from "../types/MultichainClaims.sol";
import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../types/BatchMultichainClaims.sol";

import { ClaimHashLib } from "./ClaimHashLib.sol";
import { ClaimProcessorLib } from "./ClaimProcessorLib.sol";
import { ClaimProcessorFunctionCastLib } from "./ClaimProcessorFunctionCastLib.sol";
import { DomainLib } from "./DomainLib.sol";
import { HashLib } from "./HashLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { SharedLogic } from "./SharedLogic.sol";
import { ValidityLib } from "./ValidityLib.sol";

/**
 * @title ClaimProcessorLogic
 * @notice Inherited contract implementing internal functions with logic for processing
 * claims against a signed or registered compact. Each function derives the respective
 * claim hash as well as a typehash if applicable, then processes the claim.
 * @dev IMPORTANT NOTE: this logic assumes that the utilized structs are formatted in a
 * very specific manner — if parameters are rearranged or new parameters are inserted,
 * much of this functionality will break. Proceed with caution when making any changes.
 */
contract ClaimProcessorLogic is SharedLogic {
    using ClaimHashLib for Claim;
    using ClaimHashLib for BatchClaim;
    using ClaimHashLib for MultichainClaim;
    using ClaimHashLib for ExogenousMultichainClaim;
    using ClaimHashLib for BatchMultichainClaim;
    using ClaimHashLib for ExogenousBatchMultichainClaim;
    using ClaimProcessorLib for uint256;
    using ClaimProcessorFunctionCastLib for function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool);
    using ClaimProcessorFunctionCastLib for function(bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool);
    using ClaimProcessorFunctionCastLib for function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool);
    using ClaimProcessorFunctionCastLib for function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool);
    using DomainLib for uint256;
    using HashLib for uint256;
    using EfficiencyLib for uint256;
    using ValidityLib for uint96;
    using ValidityLib for uint256;
    using ValidityLib for bytes32;

    ///// 1. Claims /////
    function _processClaim(Claim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitClaim.usingClaim()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    ///// 2. Batch Claims /////
    function _processBatchClaim(BatchClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitBatchClaim.usingBatchClaim()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    ///// 3. Multichain Claims /////
    function _processMultichainClaim(MultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitClaim.usingMultichainClaim()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }

    ///// 4. Batch Multichain Claims /////
    function _processBatchMultichainClaim(BatchMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitBatchClaim.usingBatchMultichainClaim()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }

    ///// 5. Exogenous Multichain Claims /////
    function _processExogenousMultichainClaim(ExogenousMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitClaimWithSponsorDomain.usingExogenousMultichainClaim()(
            messageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }

    ///// 6. Exogenous Batch Multichain Claims /////
    function _processExogenousBatchMultichainClaim(ExogenousBatchMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitBatchClaimWithSponsorDomain.usingExogenousBatchMultichainClaim()(
            messageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }
}
