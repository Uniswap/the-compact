// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BasicTransfer, SplitTransfer, SplitClaimWithWitness } from "../types/Claims.sol";

import { BatchTransfer, SplitBatchTransfer, SplitBatchClaimWithWitness } from "../types/BatchClaims.sol";

import {
    SplitMultichainClaimWithWitness,
    ExogenousSplitMultichainClaimWithWitness
} from "../types/MultichainClaims.sol";

import {
    SplitBatchMultichainClaimWithWitness,
    ExogenousSplitBatchMultichainClaimWithWitness
} from "../types/BatchMultichainClaims.sol";

import { SplitBatchClaimComponent } from "../types/Components.sol";

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
    using EfficiencyLib for uint256;
    using HashLib for uint256;
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

    ///// CATEGORY 2: Claim with witness message & type hashes /////
    function toMessageHashes(SplitClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return HashLib.toMessageHashWithWitness.usingSplitClaimWithWitness()(claim, 0);
    }

    function toMessageHashes(SplitBatchClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return HashLib.toBatchClaimWithWitnessMessageHash.usingSplitBatchClaimWithWitness()(claim, claim.claims.toSplitIdsAndAmountsHash());
    }

    function toMessageHashes(SplitMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toMultichainClaimWithWitnessMessageHash(claim);
    }

    function toMessageHashes(SplitBatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingSplitBatchMultichainClaimWithWitness()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toMultichainClaimMessageHash);
    }

    function toMessageHashes(ExogenousSplitMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toExogenousMultichainClaimWithWitnessMessageHash(claim);
    }

    function toMessageHashes(ExogenousSplitBatchMultichainClaimWithWitness calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingExogenousSplitBatchMultichainClaimWithWitness()(claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toExogenousMultichainClaimMessageHash);
    }

    ///// Private helper functions /////
    function _toGenericMessageHash(uint256 claim, uint256 additionalInput, function(uint256, uint256) internal view returns (bytes32) hashFn) private view returns (bytes32 claimHash) {
        return hashFn(claim, additionalInput);
    }

    function _toGenericMultichainClaimWithWitnessMessageHash(uint256 claim, uint256 additionalInput, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32) hashFn)
        private
        view
        returns (bytes32 claimHash, bytes32 /* typehash */ )
    {
        (bytes32 allocationTypehash, bytes32 typehash) = claim.toMultichainTypehashes();
        return (hashFn(claim, uint256(0x40).asStubborn(), allocationTypehash, typehash, additionalInput), typehash);
    }

    function _toMultichainClaimWithWitnessMessageHash(SplitMultichainClaimWithWitness calldata claim) private view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingMultichainClaimWithWitness()(
            claim, HashLib.toSingleIdAndAmountHash.usingMultichainClaimWithWitness()(claim, uint256(0x40).asStubborn()), HashLib.toMultichainClaimMessageHash
        );
    }

    function _toExogenousMultichainClaimWithWitnessMessageHash(ExogenousSplitMultichainClaimWithWitness calldata claim) private view returns (bytes32 claimHash, bytes32 typehash) {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingExogenousMultichainClaimWithWitness()(
            claim, HashLib.toSingleIdAndAmountHash.usingExogenousMultichainClaimWithWitness()(claim, uint256(0x80).asStubborn()), HashLib.toExogenousMultichainClaimMessageHash
        );
    }
}
