// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocatedBatchTransfer } from "../types/BatchClaims.sol";
import { AllocatedTransfer } from "../types/Claims.sol";
import { TransferComponent, ComponentsById } from "../types/Components.sol";

/**
 * @title TransferFunctionCastLib
 * @notice Library contract implementing function casts used in TransferLogic as well as
 * in HashLib. The input function operates on a function that takes some argument that
 * differs from what is currently available. The output function modifies one or more
 * argument types so that they match the arguments that are being used to call the
 * function. Note that from the perspective of the function being modified, the original
 * type is still in force; great care should be taken to preserve offsets and general
 * structure between the two structs.
 */
library TransferFunctionCastLib {
    /**
     * @notice Function cast to provide a BatchTransfer calldata struct while
     * treating it as a BasicTransfer calldata struct.
     * @param fnIn   Function pointer to `TransferLogic._notExpiredAndAuthorizedByAllocator`.
     * @return fnOut Modified function used in `TransferLogic._processBatchTransfer`.
     */
    function usingBatchTransfer(
        function (bytes32, address, AllocatedTransfer calldata, uint256[2][] memory) internal fnIn
    )
        internal
        pure
        returns (function (bytes32, address, AllocatedBatchTransfer calldata, uint256[2][] memory) internal fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }
}
