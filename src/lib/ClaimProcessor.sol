// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITheCompactClaims } from "../interfaces/ITheCompactClaims.sol";
import { ClaimProcessorLogic } from "./ClaimProcessorLogic.sol";

import { Claim } from "../types/Claims.sol";

import { BatchClaim } from "../types/BatchClaims.sol";

import { MultichainClaim, ExogenousMultichainClaim } from "../types/MultichainClaims.sol";

import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../types/BatchMultichainClaims.sol";

/**
 * @title ClaimProcessor
 * @notice Inherited contract implementing external functions for processing claims against
 * a signed or registered compact. Each of these functions is only callable by the arbiter
 * indicated by the respective compact.
 */
contract ClaimProcessor is ITheCompactClaims, ClaimProcessorLogic {
    function claim(Claim calldata claimPayload) external returns (bool) {
        return _processClaim(claimPayload, _release);
    }

    function claimAndWithdraw(Claim calldata claimPayload) external returns (bool) {
        return _processClaim(claimPayload, _withdraw);
    }

    function claim(BatchClaim calldata claimPayload) external returns (bool) {
        return _processBatchClaim(claimPayload, _release);
    }

    function claimAndWithdraw(BatchClaim calldata claimPayload) external returns (bool) {
        return _processBatchClaim(claimPayload, _withdraw);
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
}
