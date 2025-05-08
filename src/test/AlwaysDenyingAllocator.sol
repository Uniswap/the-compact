// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IAllocator } from "../interfaces/IAllocator.sol";
import { IERC1271 } from "permit2/src/interfaces/IERC1271.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";

contract AlwaysDenyingAllocator is IAllocator, IERC1271 {
    function attest(address, address, address, uint256, uint256) external pure virtual returns (bytes4) {
        return bytes4(0);
    }

    function authorizeClaim(bytes32, address, address, uint256, uint256, uint256[2][] calldata, bytes calldata)
        external
        pure
        virtual
        returns (bytes4)
    {
        return bytes4(0);
    }

    function isClaimAuthorized(bytes32, address, address, uint256, uint256, uint256[2][] calldata, bytes calldata)
        external
        pure
        virtual
        returns (bool)
    {
        return false;
    }

    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return bytes4(0);
    }
}
