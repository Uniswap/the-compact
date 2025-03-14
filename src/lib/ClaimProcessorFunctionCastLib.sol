// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ClaimWithWitness, SplitClaimWithWitness } from "../types/Claims.sol";

import {
    BatchClaimWithWitness,
    SplitBatchClaimWithWitness
} from "../types/BatchClaims.sol";

import {
    MultichainClaimWithWitness,
    SplitMultichainClaimWithWitness,
    ExogenousMultichainClaimWithWitness,
    ExogenousSplitMultichainClaimWithWitness
} from "../types/MultichainClaims.sol";

import {
    BatchMultichainClaimWithWitness,
    SplitBatchMultichainClaimWithWitness,
    ExogenousBatchMultichainClaimWithWitness,
    ExogenousSplitBatchMultichainClaimWithWitness
} from "../types/BatchMultichainClaims.sol";

/**
 * @title ClaimProcessorFunctionCastLib
 * @notice Library contract implementing function casts used in ClaimProcessorLogic.
 * The input function operates on a function that takes some argument that differs
 * from what is currently available. The output function modifies one or more
 * argument types so that they match the arguments that are being used to call the
 * function. Note that from the perspective of the function being modified, the
 * original type is still in force; great care should be taken to preserve offsets
 * and general structure between the two structs.
 * @dev Note that some of these function casts may no longer be in use.
 */
library ClaimProcessorFunctionCastLib {
    /**
     * @notice Function cast to provide a ClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processClaimWithWitness`.
     */
    function usingClaimWithWitness(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, ClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleSplitClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processSplitClaimWithWitness`.
     */
    function usingSplitClaimWithWitness(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, SplitClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a BatchClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleBatchClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processBatchClaimWithWitness`.
     */
    function usingBatchClaimWithWitness(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, BatchClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitBatchClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleSplitBatchClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processSplitBatchClaimWithWitness`.
     */
    function usingSplitBatchClaimWithWitness(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, SplitBatchClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a MultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processMultichainClaimWithWitness`.
     */
    function usingMultichainClaimWithWitness(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, MultichainClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleSplitClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processSplitMultichainClaimWithWitness`.
     */
    function usingSplitMultichainClaimWithWitness(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, SplitMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a BatchMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleBatchClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processBatchMultichainClaimWithWitness`.
     */
    function usingBatchMultichainClaimWithWitness(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, BatchMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }


    /**
     * @notice Function cast to provide a SplitBatchMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleSplitBatchClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processSplitBatchMultichainClaimWithWitness`.
     */
    function usingSplitBatchMultichainClaimWithWitness(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, SplitBatchMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processClaimWithSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousMultichainClaimWithWitness`.
     */
    function usingExogenousMultichainClaimWithWitness(
        function(bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, ExogenousMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousSplitMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitClaimWithSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousSplitMultichainClaimWithWitness`.
     */
    function usingExogenousSplitMultichainClaimWithWitness(
        function(bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, ExogenousSplitMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousBatchMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processBatchClaimWithSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousBatchMultichainClaimWithWitness`.
     */
    function usingExogenousBatchMultichainClaimWithWitness(
        function(bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, ExogenousBatchMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousSplitBatchMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitBatchClaimWithSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousSplitBatchMultichainClaimWithWitness`.
     */
    function usingExogenousSplitBatchMultichainClaimWithWitness(
        function(bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, ExogenousSplitBatchMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool)
            fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }
}
