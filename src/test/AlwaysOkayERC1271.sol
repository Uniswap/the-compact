// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC1271 } from "permit2/src/interfaces/IERC1271.sol";

contract AlwaysOkayERC1271 is IERC1271 {
    function isValidSignature(bytes32, bytes memory) public pure override returns (bytes4) {
        return 0x1626ba7e;
    }
}
