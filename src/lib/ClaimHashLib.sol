// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocatedTransfer, Claim } from "../types/Claims.sol";

import { AllocatedBatchTransfer, BatchClaim } from "../types/BatchClaims.sol";

import { MultichainClaim, ExogenousMultichainClaim } from "../types/MultichainClaims.sol";

import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../types/BatchMultichainClaims.sol";

import { BatchClaimComponent } from "../types/Components.sol";

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
        function(uint256, uint256, function(uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32);
    using HashLib for uint256;
    using HashLib for Claim;
    using HashLib for BatchClaim;
    using HashLib for BatchClaimComponent[];
    using HashLib for AllocatedTransfer;
    using HashLib for AllocatedBatchTransfer;

    ///// CATEGORY 1: Transfer claim hashes /////
    function toClaimHash(AllocatedTransfer calldata transfer) internal view returns (bytes32 claimHash) {
        return transfer.toTransferClaimHash();
    }

    function toClaimHash(AllocatedBatchTransfer calldata transfer) internal view returns (bytes32 claimHash) {
        return transfer.toBatchTransferClaimHash();
    }

    ///// CATEGORY 2: Claim hashes & type hashes /////
    function toClaimHashAndTypehash(Claim calldata claim) internal view returns (bytes32 claimHash, bytes32 typehash) {
        return claim.toClaimHash();
    }

    function toClaimHashAndTypehash(BatchClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return claim.toBatchClaimHash(claim.claims.toCommitmentsHash());
    }

    function toClaimHashAndTypehash(MultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toMultichainClaimHashAndTypehash(claim);
    }

    function toClaimHashAndTypehash(BatchMultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toBatchMultichainClaimHashAndTypehash(claim);
    }

    function toClaimHashAndTypehash(ExogenousMultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toExogenousMultichainClaimHashAndTypehash(claim);
    }

    function toClaimHashAndTypehash(ExogenousBatchMultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toExogenousBatchMultichainClaimHashAndTypehash(claim);
    }

    ///// Private helper functions /////
    function _toGenericMultichainClaimHashAndTypehash(
        uint256 claim,
        uint256 additionalInput,
        function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32) hashFn
    ) private view returns (bytes32 claimHash, bytes32 /* typehash */ ) {
        (bytes32 allocationTypehash, bytes32 typehash) = claim.toMultichainTypehashes();
        return (hashFn(claim, 0xa0, allocationTypehash, typehash, additionalInput), typehash);
    }

    function _toGenericBatchMultichainClaimHashAndTypehash(
        uint256 claim,
        uint256 additionalInput,
        function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32) hashFn
    ) private view returns (bytes32 claimHash, bytes32 /* typehash */ ) {
        (bytes32 allocationTypehash, bytes32 typehash) = claim.toMultichainTypehashes();
        return (hashFn(claim, 0x60, allocationTypehash, typehash, additionalInput), typehash);
    }

    function _toMultichainClaimHashAndTypehash(MultichainClaim calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericMultichainClaimHashAndTypehash.usingMultichainClaim()(
            claim, HashLib.toCommitmentsHashFromSingleLock.usingMultichainClaim()(claim), HashLib.toMultichainClaimHash
        );
    }

    function _toExogenousMultichainClaimHashAndTypehash(ExogenousMultichainClaim calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericMultichainClaimHashAndTypehash.usingExogenousMultichainClaim()(
            claim,
            HashLib.toCommitmentsHashFromSingleLock.usingExogenousMultichainClaim()(claim),
            HashLib.toExogenousMultichainClaimHash
        );
    }

    function _toBatchMultichainClaimHashAndTypehash(BatchMultichainClaim calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericBatchMultichainClaimHashAndTypehash.usingBatchMultichainClaim()(
            claim, claim.claims.toCommitmentsHash(), HashLib.toMultichainClaimHash
        );
    }

    function _toExogenousBatchMultichainClaimHashAndTypehash(ExogenousBatchMultichainClaim calldata claim)
        private
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return _toGenericBatchMultichainClaimHashAndTypehash.usingExogenousBatchMultichainClaim()(
            claim, claim.claims.toCommitmentsHash(), HashLib.toExogenousMultichainClaimHash
        );
    }
}
