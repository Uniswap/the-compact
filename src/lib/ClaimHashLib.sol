// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BasicTransfer, SplitTransfer, Claim } from "../types/Claims.sol";

import { BatchTransfer, SplitBatchTransfer, BatchClaim } from "../types/BatchClaims.sol";

import { MultichainClaim, ExogenousMultichainClaim } from "../types/MultichainClaims.sol";

import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../types/BatchMultichainClaims.sol";

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
    using
    ClaimHashFunctionCastLib
    for
        function(uint256, uint256, function(uint256, uint256) internal view returns (bytes32)) internal view returns (bytes32);
    using
    ClaimHashFunctionCastLib
    for
        function(uint256, uint256, function(uint256, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32);
    using
    ClaimHashFunctionCastLib
    for
        function(uint256, uint256, function(uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32);
    using
    ClaimHashFunctionCastLib
    for
        function(uint256, uint256, function(uint256, uint256) internal view returns (bytes32, bytes32)) internal view returns (bytes32, bytes32, bytes32);
    using
    ClaimHashFunctionCastLib
    for
        function(uint256, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32, bytes32);
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
    function toMessageHashes(Claim calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return HashLib.toMessageHashWithWitness.usingClaim()(claim, 0);
    }

    function toMessageHashes(BatchClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return
            HashLib.toBatchClaimWithWitnessMessageHash.usingBatchClaim()(claim, claim.claims.toSplitIdsAndAmountsHash());
    }

    function toMessageHashes(MultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toMultichainClaimWithWitnessMessageHash(claim);
    }

    function toMessageHashes(BatchMultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingBatchMultichainClaim()(
            claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toMultichainClaimMessageHash
        );
    }

    function toMessageHashes(ExogenousMultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toExogenousMultichainClaimWithWitnessMessageHash(claim);
    }

    function toMessageHashes(ExogenousBatchMultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingExogenousBatchMultichainClaim()(
            claim, claim.claims.toSplitIdsAndAmountsHash(), HashLib.toExogenousMultichainClaimMessageHash
        );
    }

    ///// Private helper functions /////
    function _toGenericMultichainClaimWithWitnessMessageHash(
        uint256 claim,
        uint256 additionalInput,
        function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32) hashFn
    ) private view returns (bytes32 claimHash, bytes32 /* typehash */ ) {
        (bytes32 allocationTypehash, bytes32 typehash) = claim.toMultichainTypehashes();
        return (hashFn(claim, uint256(0x40), allocationTypehash, typehash, additionalInput), typehash);
    }

    function _toMultichainClaimWithWitnessMessageHash(MultichainClaim calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingMultichainClaimWithWitness()(
            claim,
            HashLib.toSingleIdAndAmountHash.usingMultichainClaimWithWitness()(claim, uint256(0x40)),
            HashLib.toMultichainClaimMessageHash
        );
    }

    function _toExogenousMultichainClaimWithWitnessMessageHash(ExogenousMultichainClaim calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingExogenousMultichainClaimWithWitness()(
            claim,
            HashLib.toSingleIdAndAmountHash.usingExogenousMultichainClaimWithWitness()(claim, uint256(0x80)),
            HashLib.toExogenousMultichainClaimMessageHash
        );
    }
}
