// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IAllocator } from "../interfaces/IAllocator.sol";
import { IERC1271 } from "permit2/src/interfaces/IERC1271.sol";

contract AlwaysOKAllocator is IAllocator, IERC1271 {
    function attest(address, address, address, uint256, uint256) external pure returns (bytes4) {
        return IAllocator.attest.selector;
    }

    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return IERC1271.isValidSignature.selector;
    }
}
