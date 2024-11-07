// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

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
     * @notice Function cast to provide a BasicClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processBasicClaim`.
     */
    function usingBasicClaim(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, BasicClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a QualifiedClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedClaim`.
     */
    function usingQualifiedClaim(function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, bytes32, QualifiedClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

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
     * @notice Function cast to provide a QualifiedClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedClaimWithWitness`.
     */
    function usingQualifiedClaimWithWitness(function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, bytes32, QualifiedClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleSplitClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processSplitClaim`.
     */
    function usingSplitClaim(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, SplitClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a QualifiedSplitClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedSplitClaim`.
     */
    function usingQualifiedSplitClaim(function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, bytes32, QualifiedSplitClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
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
     * @notice Function cast to provide a QualifiedSplitClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedSplitClaimWithWitness`.
     */
    function usingQualifiedSplitClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedSplitClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a BatchClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleBatchClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processBatchClaim`.
     */
    function usingBatchClaim(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, BatchClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a QualifiedBatchClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processBatchClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedBatchClaim`.
     */
    function usingQualifiedBatchClaim(function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, bytes32, QualifiedBatchClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
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
     * @notice Function cast to provide a QualifiedBatchClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processBatchClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedBatchClaimWithWitness`.
     */
    function usingQualifiedBatchClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedBatchClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitBatchClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleSplitBatchClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processSplitBatchClaim`.
     */
    function usingSplitBatchClaim(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, SplitBatchClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a QualifiedSplitBatchClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitBatchClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedSplitBatchClaim`.
     */
    function usingQualifiedSplitBatchClaim(function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, bytes32, QualifiedSplitBatchClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
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
     * @notice Function cast to provide a QualifiedSplitBatchClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitBatchClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedSplitBatchClaimWithWitness`.
     */
    function usingQualifiedSplitBatchClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedSplitBatchClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a MultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processMultichainClaim`.
     */
    function usingMultichainClaim(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, MultichainClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a QualifiedMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedMultichainClaim`.
     */
    function usingQualifiedMultichainClaim(function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, bytes32, QualifiedMultichainClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
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
     * @notice Function cast to provide a QualifiedMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedMultichainClaimWithWitness`.
     */
    function usingQualifiedMultichainClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleSplitClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processSplitMultichainClaim`.
     */
    function usingSplitMultichainClaim(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, SplitMultichainClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a QualifiedSplitMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedSplitMultichainClaim`.
     */
    function usingQualifiedSplitMultichainClaim(function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedSplitMultichainClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
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
     * @notice Function cast to provide a QualifiedSplitMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedSplitMultichainClaimWithWitness`.
     */
    function usingQualifiedSplitMultichainClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedSplitMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a BatchMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleBatchClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processBatchMultichainClaim`.
     */
    function usingBatchMultichainClaim(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, BatchMultichainClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a QualifiedBatchMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processBatchClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedBatchMultichainClaim`.
     */
    function usingQualifiedBatchMultichainClaim(function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedBatchMultichainClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
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
     * @notice Function cast to provide a QualifiedBatchMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processBatchClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedBatchMultichainClaimWithWitness`.
     */
    function usingQualifiedBatchMultichainClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedBatchMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a SplitBatchMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSimpleSplitBatchClaim`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processSplitBatchMultichainClaim`.
     */
    function usingSplitBatchMultichainClaim(function(bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, SplitBatchMultichainClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a QualifiedSplitBatchMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitBatchClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedSplitBatchMultichainClaim`.
     */
    function usingQualifiedSplitBatchMultichainClaim(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedSplitBatchMultichainClaim calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
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
     * @notice Function cast to provide a QualifiedSplitBatchMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitBatchClaimWithQualification`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processQualifiedSplitBatchMultichainClaimWithWitness`.
     */
    function usingQualifiedSplitBatchMultichainClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, QualifiedSplitBatchMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool)
            fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processClaimWithSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousMultichainClaim`.
     */
    function usingExogenousMultichainClaim(function(bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (function(bytes32, ExogenousMultichainClaim calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousQualifiedMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processClaimWithQualificationAndSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousQualifiedMultichainClaim`.
     */
    function usingExogenousQualifiedMultichainClaim(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, ExogenousQualifiedMultichainClaim calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
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
     * @notice Function cast to provide a ExogenousQualifiedMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processClaimWithQualificationAndSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousQualifiedMultichainClaimWithWitness`.
     */
    function usingExogenousQualifiedMultichainClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, ExogenousQualifiedMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool)
            fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousSplitMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitClaimWithSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousSplitMultichainClaim`.
     */
    function usingExogenousSplitMultichainClaim(function(bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (
            function(bytes32, ExogenousSplitMultichainClaim calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousQualifiedSplitMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitClaimWithQualificationAndSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousQualifiedSplitMultichainClaim`.
     */
    function usingExogenousQualifiedSplitMultichainClaim(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, ExogenousQualifiedSplitMultichainClaim calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool)
            fnOut
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
     * @notice Function cast to provide a ExogenousQualifiedSplitMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitClaimWithQualificationAndSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousQualifiedSplitMultichainClaimWithWitness`.
     */
    function usingExogenousQualifiedSplitMultichainClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, ExogenousQualifiedSplitMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool)
            fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousBatchMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processBatchClaimWithSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousBatchMultichainClaim`.
     */
    function usingExogenousBatchMultichainClaim(function(bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn)
        internal
        pure
        returns (
            function(bytes32, ExogenousBatchMultichainClaim calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousQualifiedBatchMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processBatchClaimWithQualificationAndSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousQualifiedBatchMultichainClaim`.
     */
    function usingExogenousQualifiedBatchMultichainClaim(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, ExogenousQualifiedBatchMultichainClaim calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool)
            fnOut
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
     * @notice Function cast to provide a ExogenousQualifiedBatchMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processBatchClaimWithQualificationAndSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousQualifiedBatchMultichainClaimWithWitness`.
     */
    function usingExogenousQualifiedBatchMultichainClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, ExogenousQualifiedBatchMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool)
            fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousSplitBatchMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitBatchClaimWithSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousSplitBatchMultichainClaim`.
     */
    function usingExogenousSplitBatchMultichainClaim(
        function(bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, ExogenousSplitBatchMultichainClaim calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    /**
     * @notice Function cast to provide a ExogenousQualifiedSplitBatchMultichainClaim calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitBatchClaimWithQualificationAndSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousQualifiedSplitBatchMultichainClaim`.
     */
    function usingExogenousQualifiedSplitBatchMultichainClaim(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, ExogenousQualifiedSplitBatchMultichainClaim calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool)
            fnOut
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

    /**
     * @notice Function cast to provide a ExogenousQualifiedSplitBatchMultichainClaimWithWitness calldata struct while
     * treating it as a uint256 representing a calldata pointer location.
     * @param fnIn   Function pointer to `ClaimProcessorLib.processSplitBatchClaimWithQualificationAndSponsorDomain`.
     * @return fnOut Modified function used in `ClaimProcessorLogic._processExogenousQualifiedSplitBatchMultichainClaimWithWitness`.
     */
    function usingExogenousQualifiedSplitBatchMultichainClaimWithWitness(
        function(bytes32, bytes32, uint256, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool) fnIn
    )
        internal
        pure
        returns (
            function(bytes32, bytes32, ExogenousQualifiedSplitBatchMultichainClaimWithWitness calldata, uint256, bytes32, bytes32, bytes32, function(address, address, uint256, uint256) internal returns (bool)) internal returns (bool)
            fnOut
        )
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }
}
