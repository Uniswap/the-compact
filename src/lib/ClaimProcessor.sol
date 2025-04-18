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
    function claim(Claim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processClaim(claimPayload);
    }

    function claim(BatchClaim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processBatchClaim(claimPayload);
    }

    function claim(MultichainClaim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processMultichainClaim(claimPayload);
    }

    function claim(ExogenousMultichainClaim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processExogenousMultichainClaim(claimPayload);
    }

    function claim(BatchMultichainClaim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processBatchMultichainClaim(claimPayload);
    }

    function claim(ExogenousBatchMultichainClaim calldata claimPayload) external returns (bytes32 claimHash) {
        return _processExogenousBatchMultichainClaim(claimPayload);
    }
}
