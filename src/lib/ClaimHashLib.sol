// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    BasicTransfer,
    SplitTransfer,
    BasicClaim,
    QualifiedClaim,
    ClaimWithWitness,
    QualifiedClaimWithWitness,
    SplitClaim,
    SplitClaimWithWitness,
    QualifiedSplitClaim,
    QualifiedSplitClaimWithWitness
} from "../types/Claims.sol";

import {
    BatchTransfer,
    SplitBatchTransfer,
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

import { BatchClaimComponent, SplitBatchClaimComponent } from "../types/Components.sol";

import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";

import { EfficiencyLib } from "./EfficiencyLib.sol";
import { ClaimHashFunctionCastLib } from "./ClaimHashFunctionCastLib.sol";
import { HashLib } from "./HashLib.sol";

/**
 * @title ClaimHashLib
 * @notice Library contract implementing logic for deriving hashes as part of processing
 * claims, allocated transfers, and withdrawals.
 */
library ClaimHashLib {
    using ClaimHashFunctionCastLib for function(uint256, uint256) internal pure returns (uint256);
    using ClaimHashFunctionCastLib for function(uint256, uint256) internal view returns (bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(uint256, uint256, function(uint256, uint256) internal view returns (bytes32)) internal view returns (bytes32);
    using ClaimHashFunctionCastLib for function(uint256, uint256, function(uint256, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(uint256, uint256, function(uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(uint256, uint256, function(uint256, uint256) internal view returns (bytes32, bytes32)) internal view returns (bytes32, bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(uint256, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(BasicClaim calldata) internal view returns (bytes32);
    using ClaimHashFunctionCastLib for function(MultichainClaim calldata) internal view returns (bytes32);
    using ClaimHashFunctionCastLib for function(ExogenousMultichainClaim calldata) internal view returns (bytes32);
    using ClaimHashFunctionCastLib for function(QualifiedClaim calldata) internal view returns (bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(QualifiedMultichainClaim calldata) internal view returns (bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(ExogenousQualifiedMultichainClaim calldata) internal view returns (bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(MultichainClaimWithWitness calldata) internal view returns (bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(ExogenousMultichainClaimWithWitness calldata) internal view returns (bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(QualifiedClaimWithWitness calldata) internal view returns (bytes32, bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(QualifiedMultichainClaimWithWitness calldata) internal view returns (bytes32, bytes32, bytes32);
    using ClaimHashFunctionCastLib for function(ExogenousQualifiedMultichainClaimWithWitness calldata) internal view returns (bytes32, bytes32, bytes32);
    using EfficiencyLib for uint256;
    using HashLib for uint256;
    using HashLib for BatchClaimComponent[];
    using HashLib for SplitBatchClaimComponent[];
    using HashLib for BasicTransfer;
    using HashLib for SplitTransfer;
    using HashLib for BatchTransfer;
    using HashLib for SplitBatchTransfer;

    ///// CATEGORY 1: Transfer claim hashes /////
    function toClaimHash(BasicTransfer calldata transfer) internal view returns (bytes32 claimHash) {
        return transfer.toBasicTransferMessageHash();
    }

    function toClaimHash(SplitTransfer calldata transfer) internal view returns (bytes32 claimHash) {
        return transfer.toSplitTransferMessageHash();
    }

    function toClaimHash(BatchTransfer calldata transfer) internal view returns (bytes32 claimHash) {
        return transfer.toBatchTransferMessageHash();
    }

    function toClaimHash(SplitBatchTransfer calldata transfer) internal view returns (bytes32 claimHash) {
        return transfer.toSplitBatchTransferMessageHash();
    }

    ///// CATEGORY 2: "Simple" Claim hashes /////
    function toClaimHash(BasicClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toBasicMessageHash(claim);
    }

    function toClaimHash(SplitClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toBasicMessageHash.usingSplitClaim()(claim);
    }

    function toClaimHash(BatchClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toGenericMessageHash.usingBatchClaim()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toBatchMessageHash);
    }

    function toClaimHash(SplitBatchClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toGenericMessageHash.usingSplitBatchClaim()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toBatchMessageHash);
    }

    function toClaimHash(MultichainClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toMultichainMessageHash(claim);
    }

    function toClaimHash(SplitMultichainClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toMultichainMessageHash.usingSplitMultichainClaim()(claim);
    }

    function toClaimHash(BatchMultichainClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toGenericMessageHash.usingBatchMultichainClaim()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toSimpleMultichainClaimMessageHash);
    }

    function toClaimHash(SplitBatchMultichainClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toGenericMessageHash.usingSplitBatchMultichainClaim()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toSimpleMultichainClaimMessageHash);
    }

    function toClaimHash(ExogenousMultichainClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toExogenousMultichainMessageHash(claim);
    }

    function toClaimHash(ExogenousSplitMultichainClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toExogenousMultichainMessageHash.usingExogenousSplitMultichainClaim()(claim);
    }

    function toClaimHash(ExogenousBatchMultichainClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toGenericMessageHash.usingExogenousBatchMultichainClaim()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toSimpleExogenousMultichainClaimMessageHash);
    }

    function toClaimHash(ExogenousSplitBatchMultichainClaim calldata claim) internal view returns (bytes32 claimHash) {
        return _toGenericMessageHash.usingExogenousSplitBatchMultichainClaim()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toSimpleExogenousMultichainClaimMessageHash);
    }

    ///// CATEGORY 3: Qualified claim message & qualification hashes /////
    function toMessageHashes(QualifiedClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toQualifiedMessageHash(claim);
    }

    function toMessageHashes(QualifiedSplitClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toQualifiedMessageHash.usingQualifiedSplitClaim()(claim);
    }

    function toMessageHashes(QualifiedBatchClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toGenericMessageHashWithQualificationHash.usingQualifiedBatchClaim()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toBatchMessageHash);
    }

    function toMessageHashes(QualifiedSplitBatchClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toGenericMessageHashWithQualificationHash.usingQualifiedSplitBatchClaim()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toBatchMessageHash);
    }

    function toMessageHashes(QualifiedMultichainClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toQualifiedMultichainMessageHash(claim);
    }

    function toMessageHashes(QualifiedSplitMultichainClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toQualifiedMultichainMessageHash.usingQualifiedSplitMultichainClaim()(claim);
    }

    function toMessageHashes(QualifiedBatchMultichainClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toGenericMessageHashWithQualificationHash.usingQualifiedBatchMultichainClaim()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toQualifiedMultichainClaimMessageHash);
    }

    function toMessageHashes(QualifiedSplitBatchMultichainClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toGenericMessageHashWithQualificationHash.usingQualifiedSplitBatchMultichainClaim()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toQualifiedMultichainClaimMessageHash);
    }

    function toMessageHashes(ExogenousQualifiedMultichainClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toExogenousQualifiedMultichainMessageHash(claim);
    }

    function toMessageHashes(ExogenousQualifiedSplitMultichainClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toExogenousQualifiedMultichainMessageHash.usingExogenousQualifiedSplitMultichainClaim()(claim);
    }

    function toMessageHashes(ExogenousQualifiedBatchMultichainClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toGenericMessageHashWithQualificationHash.usingExogenousQualifiedBatchMultichainClaim()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toExogenousQualifiedMultichainClaimMessageHash);
    }

    function toMessageHashes(ExogenousQualifiedSplitBatchMultichainClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return
            _toGenericMessageHashWithQualificationHash.usingExogenousQualifiedSplitBatchMultichainClaim()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toExogenousQualifiedMultichainClaimMessageHash);
    }

    ///// CATEGORY 4: Claim with witness message & type hashes /////
    function toMessageHashes(ClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return HashLib.toMessageHashWithWitness.usingClaimWithWitness()(claim, 0);
    }

    function toMessageHashes(SplitClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return HashLib.toMessageHashWithWitness.usingSplitClaimWithWitness()(claim, 0);
    }

    function toMessageHashes(BatchClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return HashLib.toBatchClaimWithWitnessMessageHash.usingBatchClaimWithWitness()(claim, claim.claims.toIdsAndAmountsHash());
    }

    function toMessageHashes(SplitBatchClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return HashLib.toBatchClaimWithWitnessMessageHash.usingSplitBatchClaimWithWitness()(claim, claim.claims.toSplitIdsAndAmountsHash());
    }

    function toMessageHashes(MultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toMultichainClaimWithWitnessMessageHash(claim);
    }

    function toMessageHashes(SplitMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toMultichainClaimWithWitnessMessageHash.usingSplitMultichainClaimWithWitness()(claim);
    }

    function toMessageHashes(BatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingBatchMultichainClaimWithWitness()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toMultichainClaimMessageHash);
    }

    function toMessageHashes(SplitBatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingSplitBatchMultichainClaimWithWitness()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toMultichainClaimMessageHash);
    }

    function toMessageHashes(ExogenousMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toExogenousMultichainClaimWithWitnessMessageHash(claim);
    }

    function toMessageHashes(ExogenousSplitMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toExogenousMultichainClaimWithWitnessMessageHash.usingExogenousSplitMultichainClaimWithWitness()(claim);
    }

    function toMessageHashes(ExogenousBatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingExogenousBatchMultichainClaimWithWitness()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toExogenousMultichainClaimMessageHash);
    }

    function toMessageHashes(ExogenousSplitBatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingExogenousSplitBatchMultichainClaimWithWitness()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toExogenousMultichainClaimMessageHash);
    }

    ///// CATEGORY 5: Qualified claim with witness message, qualification, & type hashes /////
    function toMessageHashes(QualifiedClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toQualifiedClaimWithWitnessMessageHash(claim);
    }

    function toMessageHashes(QualifiedSplitClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toQualifiedClaimWithWitnessMessageHash.usingQualifiedSplitClaimWithWitness()(claim);
    }

    function toMessageHashes(QualifiedBatchClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toGenericQualifiedClaimWithWitnessMessageHash.usingQualifiedBatchClaimWithWitness()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toBatchClaimWithWitnessMessageHash);
    }

    function toMessageHashes(QualifiedSplitBatchClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toGenericQualifiedClaimWithWitnessMessageHash.usingQualifiedSplitBatchClaimWithWitness()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toBatchClaimWithWitnessMessageHash);
    }

    function toMessageHashes(QualifiedMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toQualifiedMultichainClaimWithWitnessMessageHash(claim);
    }

    function toMessageHashes(QualifiedSplitMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toQualifiedMultichainClaimWithWitnessMessageHash.usingQualifiedSplitMultichainClaimWithWitness()(claim);
    }

    function toMessageHashes(QualifiedBatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toGenericQualifiedMultichainClaimWithWitnessMessageHash.usingQualifiedBatchMultichainClaimWithWitness()(claim, claim.claims.toIdsAndAmountsHash(), HashLib.toMultichainClaimMessageHash);
    }

    function toMessageHashes(QualifiedSplitBatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toGenericQualifiedMultichainClaimWithWitnessMessageHash.usingQualifiedSplitBatchMultichainClaimWithWitness()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toMultichainClaimMessageHash);
    }

    function toMessageHashes(ExogenousQualifiedMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toExogenousQualifiedMultichainClaimWithWitnessMessageHash(claim);
    }

    function toMessageHashes(ExogenousQualifiedSplitMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toExogenousQualifiedMultichainClaimWithWitnessMessageHash.usingExogenousQualifiedSplitMultichainClaimWithWitness()(claim);
    }

    function toMessageHashes(ExogenousQualifiedBatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toGenericQualifiedMultichainClaimWithWitnessMessageHash.usingExogenousQualifiedBatchMultichainClaimWithWitness()(
            claim, claim.claims.toIdsAndAmountsHash(), HashLib.toExogenousMultichainClaimMessageHash
        );
    }

    function toMessageHashes(ExogenousQualifiedSplitBatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toGenericQualifiedMultichainClaimWithWitnessMessageHash.usingExogenousQualifiedSplitBatchMultichainClaimWithWitness()(
            claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toExogenousMultichainClaimMessageHash
        );
    }

    ///// Private helper functions /////
    function _toGenericMessageHash(uint256 claim, uint256 additionalInput, function(uint256, uint256) internal view returns (bytes32) hashFn) private view returns (bytes32 claimHash) {
        return hashFn(claim, additionalInput);
    }

    function _toBasicMessageHash(BasicClaim calldata claim) private view returns (bytes32 claimHash) {
        return _toGenericMessageHash.usingBasicClaim()(claim, uint256(0).asStubborn(), HashLib.toClaimMessageHash);
    }

    function _toMultichainMessageHash(MultichainClaim calldata claim) private view returns (bytes32 claimHash) {
        return _toGenericMessageHash.usingMultichainClaim()(claim, HashLib.toSingleIdAndAmountHash.usingMultichainClaim()(claim, 0), HashLib.toSimpleMultichainClaimMessageHash);
    }

    function _toExogenousMultichainMessageHash(ExogenousMultichainClaim calldata claim) private view returns (bytes32 claimHash) {
        return _toGenericMessageHash.usingExogenousMultichainClaim()(
            claim, HashLib.toSingleIdAndAmountHash.usingExogenousMultichainClaim()(claim, uint256(0x40).asStubborn()), HashLib.toSimpleExogenousMultichainClaimMessageHash
        );
    }

    function _toGenericMessageHashWithQualificationHash(uint256 claim, uint256 additionalInput, function(uint256, uint256) internal view returns (bytes32) hashFn)
        private
        view
        returns (bytes32 claimHash, bytes32 qualificationHash)
    {
        claimHash = _toGenericMessageHash(claim, additionalInput, hashFn);
        return (claimHash, claim.toQualificationMessageHash(claimHash, uint256(0).asStubborn()));
    }

    function _toQualifiedMessageHash(QualifiedClaim calldata claim) private view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toGenericMessageHashWithQualificationHash.usingQualifiedClaim()(claim, uint256(0x40).asStubborn(), HashLib.toClaimMessageHash);
    }

    function _toQualifiedMultichainMessageHash(QualifiedMultichainClaim calldata claim) private view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toGenericMessageHashWithQualificationHash.usingQualifiedMultichainClaim()(
            claim, HashLib.toSingleIdAndAmountHash.usingQualifiedMultichainClaim()(claim, uint256(0x40).asStubborn()), HashLib.toQualifiedMultichainClaimMessageHash
        );
    }

    function _toExogenousQualifiedMultichainMessageHash(ExogenousQualifiedMultichainClaim calldata claim) private view returns (bytes32 claimHash, bytes32 qualificationHash) {
        return _toGenericMessageHashWithQualificationHash.usingExogenousQualifiedMultichainClaim()(
            claim, HashLib.toSingleIdAndAmountHash.usingExogenousQualifiedMultichainClaim()(claim, uint256(0x80).asStubborn()), HashLib.toExogenousQualifiedMultichainClaimMessageHash
        );
    }

    function _toGenericMultichainClaimWithWitnessMessageHash(uint256 claim, uint256 additionalInput, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32) hashFn)
        private
        view
        returns (bytes32 claimHash, bytes32 /* typehash */ )
    {
        (bytes32 allocationTypehash, bytes32 typehash) = claim.toMultichainTypehashes();
        return (hashFn(claim, uint256(0x40).asStubborn(), allocationTypehash, typehash, additionalInput), typehash);
    }

    function _toGenericMultichainClaimWithWitnessMessageHashPriorToQualification(
        uint256 claim,
        uint256 additionalInput,
        function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32) hashFn
    ) private view returns (bytes32 claimHash, bytes32 /* typehash */ ) {
        (bytes32 allocationTypehash, bytes32 typehash) = claim.toMultichainTypehashes();
        return (hashFn(claim, uint256(0x80).asStubborn(), allocationTypehash, typehash, additionalInput), typehash);
    }

    function _toMultichainClaimWithWitnessMessageHash(MultichainClaimWithWitness calldata claim) private view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingMultichainClaimWithWitness()(
            claim, HashLib.toSingleIdAndAmountHash.usingMultichainClaimWithWitness()(claim, uint256(0x40).asStubborn()), HashLib.toMultichainClaimMessageHash
        );
    }

    function _toExogenousMultichainClaimWithWitnessMessageHash(ExogenousMultichainClaimWithWitness calldata claim) private view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingExogenousMultichainClaimWithWitness()(
            claim, HashLib.toSingleIdAndAmountHash.usingExogenousMultichainClaimWithWitness()(claim, uint256(0x80).asStubborn()), HashLib.toExogenousMultichainClaimMessageHash
        );
    }

    function _toGenericQualifiedClaimWithWitnessMessageHash(uint256 claim, uint256 additionalInput, function (uint256, uint256) internal view returns (bytes32, bytes32) hashFn)
        private
        view
        returns (bytes32, /* claimHash */ bytes32 qualificationHash, bytes32 /* typehash */ )
    {
        (bytes32 messageHash, bytes32 typehash) = hashFn(claim, additionalInput);
        return (messageHash, claim.toQualificationMessageHash(messageHash, uint256(0x40).asStubborn()), typehash);
    }

    function _toQualifiedClaimWithWitnessMessageHash(QualifiedClaimWithWitness calldata claim) private view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toGenericQualifiedClaimWithWitnessMessageHash.usingQualifiedClaimWithWitness()(claim, uint256(0x40).asStubborn(), HashLib.toMessageHashWithWitness);
    }

    function _toGenericQualifiedMultichainClaimWithWitnessMessageHash(uint256 claim, uint256 additionalInput, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32) hashFn)
        private
        view
        returns (bytes32, /* claimHash */ bytes32 qualificationHash, bytes32 /* typehash */ )
    {
        (bytes32 messageHash, bytes32 typehash) = _toGenericMultichainClaimWithWitnessMessageHashPriorToQualification(claim, additionalInput, hashFn);
        return (messageHash, claim.toQualificationMessageHash(messageHash, uint256(0x40).asStubborn()), typehash);
    }

    function _toQualifiedMultichainClaimWithWitnessMessageHash(QualifiedMultichainClaimWithWitness calldata claim) private view returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash) {
        return _toGenericQualifiedMultichainClaimWithWitnessMessageHash.usingQualifiedMultichainClaimWithWitness()(
            claim, HashLib.toSingleIdAndAmountHash.usingQualifiedMultichainClaimWithWitness()(claim, uint256(0x80).asStubborn()), HashLib.toMultichainClaimMessageHash
        );
    }

    function _toExogenousQualifiedMultichainClaimWithWitnessMessageHash(ExogenousQualifiedMultichainClaimWithWitness calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 qualificationHash, bytes32 typehash)
    {
        return _toGenericQualifiedMultichainClaimWithWitnessMessageHash.usingExogenousQualifiedMultichainClaimWithWitness()(
            claim, HashLib.toSingleIdAndAmountHash.usingExogenousQualifiedMultichainClaimWithWitness()(claim, uint256(0xc0).asStubborn()), HashLib.toExogenousMultichainClaimMessageHash
        );
    }
}
