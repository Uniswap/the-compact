// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ISignDelegator } from "src/interfaces/ISignDelegator.sol";

contract AlwaysOkDelegator is ISignDelegator {
    function verifyClaim(address sponsor, bytes32 claimHash, bytes calldata signature) external override returns (bytes4) {
        return ISignDelegator.verifyClaim.selector;
    }
}
