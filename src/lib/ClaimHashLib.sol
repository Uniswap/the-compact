// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocatedTransfer, Claim } from "../types/Claims.sol";

import { AllocatedBatchTransfer, BatchClaim } from "../types/BatchClaims.sol";

import { MultichainClaim, ExogenousMultichainClaim } from "../types/MultichainClaims.sol";

import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../types/BatchMultichainClaims.sol";

import { BatchClaimComponent } from "../types/Components.sol";

import { EfficiencyLib } from "./EfficiencyLib.sol";
import { ClaimHashFunctionCastLib } from "./ClaimHashFunctionCastLib.sol";
import { HashLib } from "./HashLib.sol";

/**
 * @title ClaimHashLib
 * @notice Library contract implementing logic for deriving hashes as part of processing
 * claims, allocated transfers, and withdrawals.
 */
library ClaimHashLib {
    using ClaimHashFunctionCastLib for function(uint256) internal pure returns (uint256);
    using ClaimHashFunctionCastLib for function(uint256) internal view returns (bytes32, bytes32);
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
    using HashLib for BatchClaimComponent[];
    using HashLib for AllocatedTransfer;
    using HashLib for AllocatedBatchTransfer;

    ///// CATEGORY 1: Transfer claim hashes /////
    function toClaimHash(AllocatedTransfer calldata transfer) internal view returns (bytes32 claimHash) {
        return transfer.toTransferMessageHash();
    }

    function toClaimHash(AllocatedBatchTransfer calldata transfer) internal view returns (bytes32 claimHash) {
        return transfer.toBatchTransferMessageHash();
    }

    ///// CATEGORY 2: Claim with witness message & type hashes /////
    function toMessageHashes(Claim calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return HashLib.toClaimHash.usingClaim()(claim);
    }

    function toMessageHashes(BatchClaim calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return HashLib.toBatchClaimHash.usingBatchClaim()(claim, claim.claims.toCommitmentsHash());
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
        return _toBatchMultichainClaimWithWitnessMessageHash(claim);
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
        return _toExogenousBatchMultichainClaimWithWitnessMessageHash(claim);
    }

    ///// Private helper functions /////
    function _toGenericMultichainClaimWithWitnessMessageHash(
        uint256 claim,
        uint256 additionalInput,
        function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32) hashFn
    ) private view returns (bytes32 claimHash, bytes32 /* typehash */ ) {
        (bytes32 allocationTypehash, bytes32 typehash) = claim.toMultichainTypehashes();
        return (hashFn(claim, 0xa0, allocationTypehash, typehash, additionalInput), typehash);
    }

    function _toGenericBatchMultichainClaimWithWitnessMessageHash(
        uint256 claim,
        uint256 additionalInput,
        function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32) hashFn
    ) private view returns (bytes32 claimHash, bytes32 /* typehash */ ) {
        (bytes32 allocationTypehash, bytes32 typehash) = claim.toMultichainTypehashes();
        return (hashFn(claim, 0x60, allocationTypehash, typehash, additionalInput), typehash);
    }

    function _toMultichainClaimWithWitnessMessageHash(MultichainClaim calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericMultichainClaimWithWitnessMessageHash.usingMultichainClaimWithWitness()(
            claim,
            HashLib.toCommitmentsHashFromSingleLock.usingMultichainClaimWithWitness()(claim),
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
            HashLib.toCommitmentsHashFromSingleLock.usingExogenousMultichainClaimWithWitness()(claim),
            HashLib.toExogenousMultichainClaimMessageHash
        );
    }

    function _toBatchMultichainClaimWithWitnessMessageHash(BatchMultichainClaim calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericBatchMultichainClaimWithWitnessMessageHash.usingBatchMultichainClaim()(
            claim, claim.claims.toCommitmentsHash(), HashLib.toMultichainClaimMessageHash
        );
    }

    function _toExogenousBatchMultichainClaimWithWitnessMessageHash(ExogenousBatchMultichainClaim calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericBatchMultichainClaimWithWitnessMessageHash.usingExogenousBatchMultichainClaim()(
            claim, claim.claims.toCommitmentsHash(), HashLib.toExogenousMultichainClaimMessageHash
        );
    }
}
