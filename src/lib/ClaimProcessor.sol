// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITheCompactClaims } from "../interfaces/ITheCompactClaims.sol";
import { ClaimProcessorLogic } from "./ClaimProcessorLogic.sol";

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

/**
 * @title ClaimProcessor
 * @notice Inherited contract implementing external functions for processing claims against
 * a signed or registered compact. Each of these functions is only callable by the arbiter
 * indicated by the respective compact.
 */
contract ClaimProcessor is ITheCompactClaims, ClaimProcessorLogic {
    function claim(BasicClaim calldata claimPayload) external returns (bool) {
        return _processBasicClaim(claimPayload, _release);
    }

    function claimAndWithdraw(BasicClaim calldata claimPayload) external returns (bool) {
        return _processBasicClaim(claimPayload, _withdraw);
    }

    function claim(QualifiedClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedClaim(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedClaim(claimPayload, _withdraw);
    }

    function claim(ClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(ClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(QualifiedClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(SplitClaim calldata claimPayload) external returns (bool) {
        return _processSplitClaim(claimPayload, _release);
    }

    function claimAndWithdraw(SplitClaim calldata claimPayload) external returns (bool) {
        return _processSplitClaim(claimPayload, _withdraw);
    }

    function claim(QualifiedSplitClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitClaim(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedSplitClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitClaim(claimPayload, _withdraw);
    }

    function claim(SplitClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(SplitClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(QualifiedSplitClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedSplitClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(BatchClaim calldata claimPayload) external returns (bool) {
        return _processBatchClaim(claimPayload, _release);
    }

    function claimAndWithdraw(BatchClaim calldata claimPayload) external returns (bool) {
        return _processBatchClaim(claimPayload, _withdraw);
    }

    function claim(QualifiedBatchClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedBatchClaim(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedBatchClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedBatchClaim(claimPayload, _withdraw);
    }

    function claim(BatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processBatchClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(BatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processBatchClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(QualifiedBatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedBatchClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedBatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedBatchClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(SplitBatchClaim calldata claimPayload) external returns (bool) {
        return _processSplitBatchClaim(claimPayload, _release);
    }

    function claimAndWithdraw(SplitBatchClaim calldata claimPayload) external returns (bool) {
        return _processSplitBatchClaim(claimPayload, _withdraw);
    }

    function claim(QualifiedSplitBatchClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitBatchClaim(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedSplitBatchClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitBatchClaim(claimPayload, _withdraw);
    }

    function claim(SplitBatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitBatchClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(SplitBatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitBatchClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(QualifiedSplitBatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitBatchClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedSplitBatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitBatchClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(MultichainClaim calldata claimPayload) external returns (bool) {
        return _processMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(MultichainClaim calldata claimPayload) external returns (bool) {
        return _processMultichainClaim(claimPayload, _withdraw);
    }

    function claim(ExogenousMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousMultichainClaim(claimPayload, _withdraw);
    }

    function claim(QualifiedMultichainClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedMultichainClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedMultichainClaim(claimPayload, _withdraw);
    }

    function claim(ExogenousQualifiedMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousQualifiedMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedMultichainClaim(claimPayload, _withdraw);
    }

    function claim(MultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(MultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(ExogenousMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(QualifiedMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(ExogenousQualifiedMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousQualifiedMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(SplitMultichainClaim calldata claimPayload) external returns (bool) {
        return _processSplitMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(SplitMultichainClaim calldata claimPayload) external returns (bool) {
        return _processSplitMultichainClaim(claimPayload, _withdraw);
    }

    function claim(ExogenousSplitMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousSplitMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousSplitMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousSplitMultichainClaim(claimPayload, _withdraw);
    }

    function claim(QualifiedSplitMultichainClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedSplitMultichainClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitMultichainClaim(claimPayload, _withdraw);
    }

    function claim(ExogenousQualifiedSplitMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedSplitMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousQualifiedSplitMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedSplitMultichainClaim(claimPayload, _withdraw);
    }

    function claim(SplitMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(SplitMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(ExogenousSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousSplitMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousSplitMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(QualifiedSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(ExogenousQualifiedSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedSplitMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousQualifiedSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedSplitMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(BatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processBatchMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(BatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processBatchMultichainClaim(claimPayload, _withdraw);
    }

    function claim(ExogenousBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousBatchMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousBatchMultichainClaim(claimPayload, _withdraw);
    }

    function claim(QualifiedBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedBatchMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedBatchMultichainClaim(claimPayload, _withdraw);
    }

    function claim(ExogenousQualifiedBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedBatchMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousQualifiedBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedBatchMultichainClaim(claimPayload, _withdraw);
    }

    function claim(BatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processBatchMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(BatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processBatchMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(ExogenousBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousBatchMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousBatchMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(QualifiedBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedBatchMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedBatchMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(ExogenousQualifiedBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedBatchMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousQualifiedBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedBatchMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(SplitBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processSplitBatchMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(SplitBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processSplitBatchMultichainClaim(claimPayload, _withdraw);
    }

    function claim(ExogenousSplitBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousSplitBatchMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousSplitBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousSplitBatchMultichainClaim(claimPayload, _withdraw);
    }

    function claim(QualifiedSplitBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitBatchMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedSplitBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitBatchMultichainClaim(claimPayload, _withdraw);
    }

    function claim(ExogenousQualifiedSplitBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedSplitBatchMultichainClaim(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousQualifiedSplitBatchMultichainClaim calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedSplitBatchMultichainClaim(claimPayload, _withdraw);
    }

    function claim(SplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitBatchMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(SplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitBatchMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(ExogenousSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousSplitBatchMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousSplitBatchMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(QualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitBatchMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(QualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processQualifiedSplitBatchMultichainClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(ExogenousQualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedSplitBatchMultichainClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(ExogenousQualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processExogenousQualifiedSplitBatchMultichainClaimWithWitness(claimPayload, _withdraw);
    }
}
