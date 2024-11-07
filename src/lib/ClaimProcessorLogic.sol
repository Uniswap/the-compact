// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BasicClaim, QualifiedClaim, ClaimWithWitness, QualifiedClaimWithWitness, SplitClaim, SplitClaimWithWitness, QualifiedSplitClaim, QualifiedSplitClaimWithWitness } from "../types/Claims.sol";
import {
    BatchClaim,
    QualifiedBatchClaim,
    BatchClaimWithWitness,
    QualifiedBatchClaimWithWitness,
    SplitBatchClaim,
    SplitBatchClaimWithWitness,
    QualifiedSplitBatchClaim,
    QualifiedSplitBatchClaimWithWitness
} from "../types/BatchClaims.sol";
import {
    MultichainClaim,
    QualifiedMultichainClaim,
    MultichainClaimWithWitness,
    QualifiedMultichainClaimWithWitness,
    SplitMultichainClaim,
    SplitMultichainClaimWithWitness,
    QualifiedSplitMultichainClaim,
    QualifiedSplitMultichainClaimWithWitness,
    ExogenousMultichainClaim,
    ExogenousQualifiedMultichainClaim,
    ExogenousMultichainClaimWithWitness,
    ExogenousQualifiedMultichainClaimWithWitness,
    ExogenousSplitMultichainClaim,
    ExogenousSplitMultichainClaimWithWitness,
    ExogenousQualifiedSplitMultichainClaim,
    ExogenousQualifiedSplitMultichainClaimWithWitness
} from "../types/MultichainClaims.sol";
import {
    BatchMultichainClaim,
    QualifiedBatchMultichainClaim,
    BatchMultichainClaimWithWitness,
    QualifiedBatchMultichainClaimWithWitness,
    SplitBatchMultichainClaim,
    SplitBatchMultichainClaimWithWitness,
    QualifiedSplitBatchMultichainClaim,
    QualifiedSplitBatchMultichainClaimWithWitness,
    ExogenousBatchMultichainClaim,
    ExogenousQualifiedBatchMultichainClaim,
    ExogenousBatchMultichainClaimWithWitness,
    ExogenousQualifiedBatchMultichainClaimWithWitness,
    ExogenousSplitBatchMultichainClaim,
    ExogenousSplitBatchMultichainClaimWithWitness,
    ExogenousQualifiedSplitBatchMultichainClaim,
    ExogenousQualifiedSplitBatchMultichainClaimWithWitness
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
    using ClaimHashLib for BasicClaim;
    using ClaimHashLib for QualifiedClaim;
    using ClaimHashLib for ClaimWithWitness;
    using ClaimHashLib for QualifiedClaimWithWitness;
    using ClaimHashLib for SplitClaim;
    using ClaimHashLib for SplitClaimWithWitness;
    using ClaimHashLib for QualifiedSplitClaim;
    using ClaimHashLib for QualifiedSplitClaimWithWitness;
    using ClaimHashLib for BatchClaim;
    using ClaimHashLib for QualifiedBatchClaim;
    using ClaimHashLib for BatchClaimWithWitness;
    using ClaimHashLib for QualifiedBatchClaimWithWitness;
    using ClaimHashLib for SplitBatchClaim;
    using ClaimHashLib for SplitBatchClaimWithWitness;
    using ClaimHashLib for QualifiedSplitBatchClaim;
    using ClaimHashLib for QualifiedSplitBatchClaimWithWitness;
    using ClaimHashLib for MultichainClaim;
    using ClaimHashLib for QualifiedMultichainClaim;
    using ClaimHashLib for MultichainClaimWithWitness;
    using ClaimHashLib for QualifiedMultichainClaimWithWitness;
    using ClaimHashLib for SplitMultichainClaim;
    using ClaimHashLib for SplitMultichainClaimWithWitness;
    using ClaimHashLib for QualifiedSplitMultichainClaim;
    using ClaimHashLib for QualifiedSplitMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousMultichainClaim;
    using ClaimHashLib for ExogenousQualifiedMultichainClaim;
    using ClaimHashLib for ExogenousMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousQualifiedMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousSplitMultichainClaim;
    using ClaimHashLib for ExogenousSplitMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousQualifiedSplitMultichainClaim;
    using ClaimHashLib for ExogenousQualifiedSplitMultichainClaimWithWitness;
    using ClaimHashLib for BatchMultichainClaim;
    using ClaimHashLib for QualifiedBatchMultichainClaim;
    using ClaimHashLib for BatchMultichainClaimWithWitness;
    using ClaimHashLib for QualifiedBatchMultichainClaimWithWitness;
    using ClaimHashLib for SplitBatchMultichainClaim;
    using ClaimHashLib for SplitBatchMultichainClaimWithWitness;
    using ClaimHashLib for QualifiedSplitBatchMultichainClaim;
    using ClaimHashLib for QualifiedSplitBatchMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousBatchMultichainClaim;
    using ClaimHashLib for ExogenousQualifiedBatchMultichainClaim;
    using ClaimHashLib for ExogenousBatchMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousQualifiedBatchMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousSplitBatchMultichainClaim;
    using ClaimHashLib for ExogenousSplitBatchMultichainClaimWithWitness;
    using ClaimHashLib for ExogenousQualifiedSplitBatchMultichainClaim;
    using ClaimHashLib for ExogenousQualifiedSplitBatchMultichainClaimWithWitness;
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
    function _processBasicClaim(BasicClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processSimpleClaim.usingBasicClaim()(claimPayload.toClaimHash(), claimPayload, uint256(0xa0).asStubborn(), uint256(0).asStubborn().typehashes(), _domainSeparator(), operation);
    }

    function _processQualifiedClaim(QualifiedClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return
            ClaimProcessorLib.processClaimWithQualification.usingQualifiedClaim()(messageHash, qualificationMessageHash, claimPayload, 0xe0, uint256(0).asStubborn().typehashes(), _domainSeparator(), operation);
    }

    function _processClaimWithWitness(ClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleClaim.usingClaimWithWitness()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    function _processQualifiedClaimWithWitness(QualifiedClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processClaimWithQualification.usingQualifiedClaimWithWitness()(messageHash, qualificationMessageHash, claimPayload, 0x120, typehash, _domainSeparator(), operation);
    }

    function _processSplitClaim(SplitClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processSimpleSplitClaim.usingSplitClaim()(claimPayload.toClaimHash(), claimPayload, 0xa0, uint256(0).asStubborn().typehashes(), _domainSeparator(), operation);
    }

    function _processQualifiedSplitClaim(QualifiedSplitClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitClaimWithQualification.usingQualifiedSplitClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0xe0, uint256(0).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processSplitClaimWithWitness(SplitClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitClaim.usingSplitClaimWithWitness()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    function _processQualifiedSplitClaimWithWitness(QualifiedSplitClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitClaimWithQualification.usingQualifiedSplitClaimWithWitness()(messageHash, qualificationMessageHash, claimPayload, 0x120, typehash, _domainSeparator(), operation);
    }

    ///// 2. Batch Claims /////
    function _processBatchClaim(BatchClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processSimpleBatchClaim.usingBatchClaim()(claimPayload.toClaimHash(), claimPayload, 0xa0, uint256(1).asStubborn().typehashes(), _domainSeparator(), operation);
    }

    function _processQualifiedBatchClaim(QualifiedBatchClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processBatchClaimWithQualification.usingQualifiedBatchClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0xe0, uint256(1).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processBatchClaimWithWitness(BatchClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleBatchClaim.usingBatchClaimWithWitness()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    function _processQualifiedBatchClaimWithWitness(QualifiedBatchClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processBatchClaimWithQualification.usingQualifiedBatchClaimWithWitness()(messageHash, qualificationMessageHash, claimPayload, 0x120, typehash, _domainSeparator(), operation);
    }

    function _processSplitBatchClaim(SplitBatchClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processSimpleSplitBatchClaim.usingSplitBatchClaim()(claimPayload.toClaimHash(), claimPayload, 0xa0, uint256(1).asStubborn().typehashes(), _domainSeparator(), operation);
    }

    function _processQualifiedSplitBatchClaim(QualifiedSplitBatchClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitBatchClaimWithQualification.usingQualifiedSplitBatchClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0xe0, uint256(1).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processSplitBatchClaimWithWitness(SplitBatchClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitBatchClaim.usingSplitBatchClaimWithWitness()(messageHash, claimPayload, 0xe0, typehash, _domainSeparator(), operation);
    }

    function _processQualifiedSplitBatchClaimWithWitness(QualifiedSplitBatchClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitBatchClaimWithQualification.usingQualifiedSplitBatchClaimWithWitness()(
            messageHash, qualificationMessageHash, claimPayload, 0x120, typehash, _domainSeparator(), operation
        );
    }

    ///// 3. Multichain Claims /////
    function _processMultichainClaim(MultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processSimpleClaim.usingMultichainClaim()(claimPayload.toClaimHash(), claimPayload, 0xc0, uint256(2).asStubborn().typehashes(), _domainSeparator(), operation);
    }

    function _processQualifiedMultichainClaim(QualifiedMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processClaimWithQualification.usingQualifiedMultichainClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0x100, uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processMultichainClaimWithWitness(MultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleClaim.usingMultichainClaimWithWitness()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }

    function _processQualifiedMultichainClaimWithWitness(QualifiedMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processClaimWithQualification.usingQualifiedMultichainClaimWithWitness()(messageHash, qualificationMessageHash, claimPayload, 0x140, typehash, _domainSeparator(), operation);
    }

    function _processSplitMultichainClaim(SplitMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processSimpleSplitClaim.usingSplitMultichainClaim()(claimPayload.toClaimHash(), claimPayload, 0xc0, uint256(2).asStubborn().typehashes(), _domainSeparator(), operation);
    }

    function _processQualifiedSplitMultichainClaim(QualifiedSplitMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitClaimWithQualification.usingQualifiedSplitMultichainClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0x100, uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processSplitMultichainClaimWithWitness(SplitMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitClaim.usingSplitMultichainClaimWithWitness()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }

    function _processQualifiedSplitMultichainClaimWithWitness(QualifiedSplitMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitClaimWithQualification.usingQualifiedSplitMultichainClaimWithWitness()(
            messageHash, qualificationMessageHash, claimPayload, 0x140, typehash, _domainSeparator(), operation
        );
    }

    ///// 4. Batch Multichain Claims /////
    function _processBatchMultichainClaim(BatchMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processSimpleBatchClaim.usingBatchMultichainClaim()(claimPayload.toClaimHash(), claimPayload, 0xc0, uint256(2).asStubborn().typehashes(), _domainSeparator(), operation);
    }

    function _processQualifiedBatchMultichainClaim(QualifiedBatchMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processBatchClaimWithQualification.usingQualifiedBatchMultichainClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0x100, uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processBatchMultichainClaimWithWitness(BatchMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleBatchClaim.usingBatchMultichainClaimWithWitness()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }

    function _processQualifiedBatchMultichainClaimWithWitness(QualifiedBatchMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processBatchClaimWithQualification.usingQualifiedBatchMultichainClaimWithWitness()(
            messageHash, qualificationMessageHash, claimPayload, 0x140, typehash, _domainSeparator(), operation
        );
    }

    function _processSplitBatchMultichainClaim(SplitBatchMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return
            ClaimProcessorLib.processSimpleSplitBatchClaim.usingSplitBatchMultichainClaim()(claimPayload.toClaimHash(), claimPayload, 0xc0, uint256(2).asStubborn().typehashes(), _domainSeparator(), operation);
    }

    function _processQualifiedSplitBatchMultichainClaim(QualifiedSplitBatchMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitBatchClaimWithQualification.usingQualifiedSplitBatchMultichainClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0x100, uint256(1).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processSplitBatchMultichainClaimWithWitness(SplitBatchMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSimpleSplitBatchClaim.usingSplitBatchMultichainClaimWithWitness()(messageHash, claimPayload, 0x100, typehash, _domainSeparator(), operation);
    }

    function _processQualifiedSplitBatchMultichainClaimWithWitness(
        QualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload,
        function(address, address, uint256, uint256) internal returns (bool) operation
    ) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitBatchClaimWithQualification.usingQualifiedSplitBatchMultichainClaimWithWitness()(
            messageHash, qualificationMessageHash, claimPayload, 0x140, typehash, _domainSeparator(), operation
        );
    }

    ///// 5. Exogenous Multichain Claims /////
    function _processExogenousMultichainClaim(ExogenousMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processClaimWithSponsorDomain.usingExogenousMultichainClaim()(
            claimPayload.toClaimHash(), claimPayload, 0x100, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processExogenousQualifiedMultichainClaim(ExogenousQualifiedMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processClaimWithQualificationAndSponsorDomain.usingExogenousQualifiedMultichainClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processExogenousMultichainClaimWithWitness(ExogenousMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processClaimWithSponsorDomain.usingExogenousMultichainClaimWithWitness()(
            messageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }

    function _processExogenousQualifiedMultichainClaimWithWitness(
        ExogenousQualifiedMultichainClaimWithWitness calldata claimPayload,
        function(address, address, uint256, uint256) internal returns (bool) operation
    ) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processClaimWithQualificationAndSponsorDomain.usingExogenousQualifiedMultichainClaimWithWitness()(
            messageHash, qualificationMessageHash, claimPayload, 0x180, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }

    function _processExogenousSplitMultichainClaim(ExogenousSplitMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processSplitClaimWithSponsorDomain.usingExogenousSplitMultichainClaim()(
            claimPayload.toClaimHash(), claimPayload, 0x100, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processExogenousQualifiedSplitMultichainClaim(ExogenousQualifiedSplitMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitClaimWithQualificationAndSponsorDomain.usingExogenousQualifiedSplitMultichainClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
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

    function _processExogenousQualifiedSplitMultichainClaimWithWitness(
        ExogenousQualifiedSplitMultichainClaimWithWitness calldata claimPayload,
        function(address, address, uint256, uint256) internal returns (bool) operation
    ) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitClaimWithQualificationAndSponsorDomain.usingExogenousQualifiedSplitMultichainClaimWithWitness()(
            messageHash, qualificationMessageHash, claimPayload, 0x180, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }

    ///// 6. Exogenous Batch Multichain Claims /////
    function _processExogenousBatchMultichainClaim(ExogenousBatchMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        return ClaimProcessorLib.processBatchClaimWithSponsorDomain.usingExogenousBatchMultichainClaim()(
            claimPayload.toClaimHash(), claimPayload, 0x100, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processExogenousQualifiedBatchMultichainClaim(ExogenousQualifiedBatchMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processBatchClaimWithQualificationAndSponsorDomain.usingExogenousQualifiedBatchMultichainClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processExogenousBatchMultichainClaimWithWitness(ExogenousBatchMultichainClaimWithWitness calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        (bytes32 messageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processBatchClaimWithSponsorDomain.usingExogenousBatchMultichainClaimWithWitness()(
            messageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }

    function _processExogenousQualifiedBatchMultichainClaimWithWitness(
        ExogenousQualifiedBatchMultichainClaimWithWitness calldata claimPayload,
        function(address, address, uint256, uint256) internal returns (bool) operation
    ) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processBatchClaimWithQualificationAndSponsorDomain.usingExogenousQualifiedBatchMultichainClaimWithWitness()(
            messageHash, qualificationMessageHash, claimPayload, 0x180, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }

    function _processExogenousSplitBatchMultichainClaim(ExogenousSplitBatchMultichainClaim calldata claimPayload, function(address, address, uint256, uint256) internal returns (bool) operation)
        internal
        returns (bool)
    {
        return ClaimProcessorLib.processSplitBatchClaimWithSponsorDomain.usingExogenousSplitBatchMultichainClaim()(
            claimPayload.toClaimHash(), claimPayload, 0x100, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
        );
    }

    function _processExogenousQualifiedSplitBatchMultichainClaim(
        ExogenousQualifiedSplitBatchMultichainClaim calldata claimPayload,
        function(address, address, uint256, uint256) internal returns (bool) operation
    ) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitBatchClaimWithQualificationAndSponsorDomain.usingExogenousQualifiedSplitBatchMultichainClaim()(
            messageHash, qualificationMessageHash, claimPayload, 0x140, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), uint256(2).asStubborn().typehashes(), _domainSeparator(), operation
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

    function _processExogenousQualifiedSplitBatchMultichainClaimWithWitness(
        ExogenousQualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload,
        function(address, address, uint256, uint256) internal returns (bool) operation
    ) internal returns (bool) {
        (bytes32 messageHash, bytes32 qualificationMessageHash, bytes32 typehash) = claimPayload.toMessageHashes();
        return ClaimProcessorLib.processSplitBatchClaimWithQualificationAndSponsorDomain.usingExogenousQualifiedSplitBatchMultichainClaimWithWitness()(
            messageHash, qualificationMessageHash, claimPayload, 0x180, claimPayload.notarizedChainId.toNotarizedDomainSeparator(), typehash, _domainSeparator(), operation
        );
    }
}
