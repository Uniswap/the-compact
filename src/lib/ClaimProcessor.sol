// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITheCompactClaims } from "../interfaces/ITheCompactClaims.sol";
import { ClaimProcessorLogic } from "./ClaimProcessorLogic.sol";

import { SplitClaimWithWitness } from "../types/Claims.sol";

import { SplitBatchClaimWithWitness } from "../types/BatchClaims.sol";

import {
    SplitMultichainClaimWithWitness,
    ExogenousSplitMultichainClaimWithWitness
} from "../types/MultichainClaims.sol";

import {
    SplitBatchMultichainClaimWithWitness,
    ExogenousSplitBatchMultichainClaimWithWitness
} from "../types/BatchMultichainClaims.sol";

/**
 * @title ClaimProcessor
 * @notice Inherited contract implementing external functions for processing claims against
 * a signed or registered compact. Each of these functions is only callable by the arbiter
 * indicated by the respective compact.
 */
contract ClaimProcessor is ITheCompactClaims, ClaimProcessorLogic {
    function claim(SplitClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(SplitClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitClaimWithWitness(claimPayload, _withdraw);
    }

    function claim(SplitBatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitBatchClaimWithWitness(claimPayload, _release);
    }

    function claimAndWithdraw(SplitBatchClaimWithWitness calldata claimPayload) external returns (bool) {
        return _processSplitBatchClaimWithWitness(claimPayload, _withdraw);
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
}
