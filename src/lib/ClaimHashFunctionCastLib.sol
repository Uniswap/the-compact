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
 * @title ClaimHashFunctionCastLib
 * @notice Library contract implementing function casts used throughout the codebase,
 * particularly as part of processing claims. The input function operates on a
 * function that takes some argument that differs from what is currently available.
 * The output function modifies one or more argument types so that they match the
 * arguments that are being used to call the function. Note that from the perspective
 * of the function being modified, the original type is still in force; great care
 * should be taken to preserve offsets and general structure between the two structs.
 * @dev Note that some of these function casts may no longer be in use.
 */
library ClaimHashFunctionCastLib {
    /**
     * @notice Function cast to provide a MultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location with witness data.
     * @param fnIn   Function pointer to `ClaimHashLib._toGenericMultichainClaimWithWitnessMessageHash`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(MultichainClaimWithWitness calldata)`.
     */
    function usingMultichainClaimWithWitness(function (uint256, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnIn)
        internal
        pure
        returns (function (MultichainClaimWithWitness calldata, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitMultichainClaimWithWitness calldata struct while
     * treating it as a MultichainClaimWithWitness calldata struct.
     * @param fnIn   Function pointer to `ClaimHashLib._toMultichainClaimWithWitnessMessageHash(MultichainClaimWithWitness calldata)`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(MultichainClaimWithWitness calldata)`.
     */
    function usingSplitMultichainClaimWithWitness(function (MultichainClaimWithWitness calldata) internal view returns (bytes32, bytes32) fnIn)
        internal
        pure
        returns (function (SplitMultichainClaimWithWitness calldata) internal view returns (bytes32, bytes32) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a BatchMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location with witness data.
     * @param fnIn   Function pointer to `ClaimHashLib._toGenericMultichainClaimWithWitnessMessageHash`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(BatchMultichainClaimWithWitness calldata)`.
     */
    function usingBatchMultichainClaimWithWitness(
        function (uint256, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnIn
    )
        internal
        pure
        returns (
            function (BatchMultichainClaimWithWitness calldata, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitBatchMultichainClaimWithWitness calldata struct
     * while treating it as a uint256 representing a calldata pointer location with witness data.
     * @param fnIn   Function pointer to `ClaimHashLib._toGenericMultichainClaimWithWitnessMessageHash`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(SplitBatchMultichainClaimWithWitness calldata)`.
     */
    function usingSplitBatchMultichainClaimWithWitness(
        function (uint256, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnIn
    )
        internal
        pure
        returns (
            function (SplitBatchMultichainClaimWithWitness calldata, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide an ExogenousMultichainClaimWithWitness calldata struct
     * while treating it as a uint256 representing a calldata pointer location with witness data.
     * @param fnIn   Function pointer to `ClaimHashLib._toGenericMultichainClaimWithWitnessMessageHash`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(ExogenousMultichainClaimWithWitness calldata)`.
     */
    function usingExogenousMultichainClaimWithWitness(
        function (uint256, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnIn
    )
        internal
        pure
        returns (
            function (ExogenousMultichainClaimWithWitness calldata, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide an ExogenousSplitMultichainClaimWithWitness calldata
     * struct while treating it as an ExogenousMultichainClaimWithWitness calldata struct.
     * @param fnIn   Function pointer to `ClaimHashLib._toExogenousMultichainClaimWithWitnessMessageHash(ExogenousMultichainClaimWithWitness calldata)`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(ExogenousSplitMultichainClaimWithWitness calldata)`.
     */
    function usingExogenousSplitMultichainClaimWithWitness(function (ExogenousMultichainClaimWithWitness calldata) internal view returns (bytes32, bytes32) fnIn)
        internal
        pure
        returns (function (ExogenousSplitMultichainClaimWithWitness calldata) internal view returns (bytes32, bytes32) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide an ExogenousBatchMultichainClaimWithWitness calldata
     * struct while treating it as a uint256 representing a calldata pointer location with witness data.
     * @param fnIn   Function pointer to `ClaimHashLib._toGenericMultichainClaimWithWitnessMessageHash`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(ExogenousBatchMultichainClaimWithWitness calldata)`.
     */
    function usingExogenousBatchMultichainClaimWithWitness(
        function (uint256, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnIn
    )
        internal
        pure
        returns (
            function (ExogenousBatchMultichainClaimWithWitness calldata, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide an ExogenousSplitBatchMultichainClaimWithWitness calldata
     * struct while treating it as a uint256 representing a calldata pointer location with witness data.
     * @param fnIn   Function pointer to `ClaimHashLib._toGenericMultichainClaimWithWitnessMessageHash`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(ExogenousSplitBatchMultichainClaimWithWitness calldata)`.
     */
    function usingExogenousSplitBatchMultichainClaimWithWitness(
        function (uint256, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32) fnIn
    )
        internal
        pure
        returns (
            function (ExogenousSplitBatchMultichainClaimWithWitness calldata, uint256, function (uint256, uint256, bytes32, bytes32, uint256) internal view returns (bytes32)) internal view returns (bytes32, bytes32)
                fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `HashLib.toMessageHashWithWitness(uint256, uint256)`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(ClaimWithWitness calldata)`.
     */
    function usingClaimWithWitness(function (uint256, uint256) internal view returns (bytes32, bytes32) fnIn)
        internal
        pure
        returns (function (ClaimWithWitness calldata, uint256) internal view returns (bytes32, bytes32) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `HashLib.toMessageHashWithWitness(uint256, uint256)`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(SplitClaimWithWitness calldata)`.
     */
    function usingSplitClaimWithWitness(function (uint256, uint256) internal view returns (bytes32, bytes32) fnIn)
        internal
        pure
        returns (function (SplitClaimWithWitness calldata, uint256) internal view returns (bytes32, bytes32) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a BatchClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `HashLib.toMessageHashWithWitness(uint256, uint256)`.
     * @return fnOut Modified function used in `ClaimHashLib.toMessageHashes(BatchClaimWithWitness calldata)`.
     */
    function usingBatchClaimWithWitness(function (uint256, uint256) internal view returns (bytes32, bytes32) fnIn)
        internal
        pure
        returns (function (BatchClaimWithWitness calldata, uint256) internal view returns (bytes32, bytes32) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitBatchClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `HashLib.toMessageHashWithWitness(uint256, uint256)`.
     * @return fnOut Modified function used in `SplitBatchClaimWithWitness.toMessageHashes(BatchClaimWithWitness calldata)`.
     */
    function usingSplitBatchClaimWithWitness(function (uint256, uint256) internal view returns (bytes32, bytes32) fnIn)
        internal
        pure
        returns (function (SplitBatchClaimWithWitness calldata, uint256) internal view returns (bytes32, bytes32) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a MultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimHashLib._toMultichainClaimWithWitnessMessageHash(MultichainClaimWithWitness calldata)`.
     * @return fnOut Modified function used in `ClaimHashLib._toMultichainClaimWithWitnessMessageHash(MultichainClaimWithWitness calldata)`.
     */
    function usingMultichainClaimWithWitness(function (uint256, uint256) internal pure returns (uint256) fnIn)
        internal
        pure
        returns (function (MultichainClaimWithWitness calldata, uint256) internal pure returns (uint256) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide an ExogenousMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimHashLib._toExogenousMultichainClaimWithWitnessMessageHash(ExogenousMultichainClaimWithWitness calldata)`.
     * @return fnOut Modified function used in `ClaimHashLib._toExogenousMultichainClaimWithWitnessMessageHash(ExogenousMultichainClaimWithWitness calldata)`.
     */
    function usingExogenousMultichainClaimWithWitness(function (uint256, uint256) internal pure returns (uint256) fnIn)
        internal
        pure
        returns (function (ExogenousMultichainClaimWithWitness calldata, uint256) internal pure returns (uint256) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }
}
