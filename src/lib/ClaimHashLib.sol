// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocatedTransfer, Claim, ClaimsLib } from "../types/Claims.sol";

import { AllocatedBatchTransfer, BatchClaim, BatchClaimsLib } from "../types/BatchClaims.sol";

import { MultichainClaim, ExogenousMultichainClaim, MultichainClaimsLib } from "../types/MultichainClaims.sol";

import {
    BatchMultichainClaim,
    ExogenousBatchMultichainClaim,
    BatchMultichainClaimsLib
} from "../types/BatchMultichainClaims.sol";

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
    using ClaimsLib for Claim;
    using BatchClaimsLib for BatchClaim;
    using MultichainClaimsLib for MultichainClaim;
    using MultichainClaimsLib for ExogenousMultichainClaim;
    using BatchMultichainClaimsLib for BatchMultichainClaim;
    using BatchMultichainClaimsLib for ExogenousBatchMultichainClaim;

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
        uint256 commitmentsHash = claim.asRawPtr().toCommitmentsHashFromSingleLock();
        (bytes32 allocationTypehash, bytes32 compactTypehash) = claim.asRawPtr().toMultichainTypehashes();
        return (
            claim.asRawPtr().toMultichainClaimHash(0xa0, allocationTypehash, compactTypehash, commitmentsHash),
            compactTypehash
        );
    }

    function toClaimHashAndTypehash(BatchMultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        uint256 commitmentsHash = claim.claims.toCommitmentsHash();
        (bytes32 allocationTypehash, bytes32 compactTypehash) = claim.asRawPtr().toMultichainTypehashes();
        return (
            claim.asRawPtr().toMultichainClaimHash(0x60, allocationTypehash, compactTypehash, commitmentsHash),
            compactTypehash
        );
    }

    function toClaimHashAndTypehash(ExogenousMultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        uint256 commitmentsHash = claim.asRawPtr().toCommitmentsHashFromSingleLock();
        (bytes32 allocationTypehash, bytes32 compactTypehash) = claim.asRawPtr().toMultichainTypehashes();
        return (
            claim.asRawPtr().toExogenousMultichainClaimHash(0xa0, allocationTypehash, compactTypehash, commitmentsHash),
            compactTypehash
        );
    }

    function toClaimHashAndTypehash(ExogenousBatchMultichainClaim calldata claim)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        uint256 commitmentsHash = claim.claims.toCommitmentsHash();
        (bytes32 allocationTypehash, bytes32 compactTypehash) = claim.asRawPtr().toMultichainTypehashes();
        return (
            claim.asRawPtr().toExogenousMultichainClaimHash(0x60, allocationTypehash, compactTypehash, commitmentsHash),
            compactTypehash
        );
    }
}
