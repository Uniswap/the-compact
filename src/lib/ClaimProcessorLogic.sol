// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ClaimWithWitness, SplitClaimWithWitness } from "../types/Claims.sol";
import {
    BatchClaimWithWitness,
    SplitBatchClaimWithWitness
} from "../types/BatchClaims.sol";
import {
    MultichainClaimWithWitness,
    SplitMultichainClaimWithWitness,
    ExogenousMultichainClaimWithWitness,
    ExogenousSplitMultichainClaimWithWitness
} from "../types/MultichainClaims.sol";
import {
    BatchMultichainClaimWithWitness,
    SplitBatchMultichainClaimWithWitness,
    ExogenousBatchMultichainClaimWithWitness,
    ExogenousSplitBatchMultichainClaimWithWitness
} from "../types/BatchMultichainClaims.sol";

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
 * claim hash as well as a qualification hash or typehash if applicable, then processes
 * the claim.
 * @dev IMPORTANT NOTE: this logic assumes that the utilized structs are formatted in a
 * very specific manner — if parameters are rearranged or new parameters are inserted,
 * much of this functionality will break. Proceed with caution when making any changes.
 */
contract ClaimProcessorLogic is SharedLogic {
    using ClaimHashLib for ClaimWithWitness;
    using ClaimHashLib for SplitClaimWithWitness;
    using ClaimHashLib for BatchClaimWithWitness;
    using ClaimHashLib for SplitBatchClaimWithWitness;
    using ClaimHashLib for MultichainClaimWithWitness;
    using ClaimHashLib for SplitMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousSplitMultichainClaimWithWitness;
    using ClaimHashLib for BatchMultichainClaimWithWitness;
    using ClaimHashLib for SplitBatchMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousBatchMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousSplitBatchMultichainClaimWithWitness;
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
    function _processClaimWithWitness(ClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleClaim.usingClaimWithWitness()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    function _processSplitClaimWithWitness(SplitClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitClaim.usingSplitClaimWithWitness()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    ///// 2. Batch Claims /////
    function _processBatchClaimWithWitness(BatchClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleBatchClaim.usingBatchClaimWithWitness()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    function _processSplitBatchClaimWithWitness(SplitBatchClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitBatchClaim.usingSplitBatchClaimWithWitness()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    ///// 3. Multichain Claims /////
    function _processMultichainClaimWithWitness(MultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleClaim.usingMultichainClaimWithWitness()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }

    function _processSplitMultichainClaimWithWitness(SplitMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitClaim.usingSplitMultichainClaimWithWitness()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }

    ///// 4. Batch Multichain Claims /////
    function _processBatchMultichainClaimWithWitness(BatchMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleBatchClaim.usingBatchMultichainClaimWithWitness()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }

    function _processSplitBatchMultichainClaimWithWitness(SplitBatchMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitBatchClaim.usingSplitBatchMultichainClaimWithWitness()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }


    ///// 5. Exogenous Multichain Claims /////
    function _processExogenousMultichainClaimWithWitness(ExogenousMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processClaimWithSponsorDomain.usingExogenousMultichainClaimWithWitness()(
            messageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }

    function _processExogenousSplitMultichainClaimWithWitness(ExogenousSplitMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitClaimWithSponsorDomain.usingExogenousSplitMultichainClaimWithWitness()(
            messageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }

    ///// 6. Exogenous Batch Multichain Claims /////
    function _processExogenousBatchMultichainClaimWithWitness(ExogenousBatchMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processBatchClaimWithSponsorDomain.usingExogenousBatchMultichainClaimWithWitness()(
            messageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }

    function _processExogenousSplitBatchMultichainClaimWithWitness(
        ExogenousSplitBatchMultichainClaimWithWitness calldata claimPayload,
        function(address, address, uint256, uint256) internal returns (bool) operation
    ) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitBatchClaimWithSponsorDomain.usingExogenousSplitBatchMultichainClaimWithWitness()(
            messageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }
}
