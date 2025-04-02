// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IEmissary } from "src/interfaces/IEmissary.sol";

contract AlwaysOKEmissary is IEmissary {
    function verifyClaim(address, /* sponsor */ bytes32, /* claimHash */ bytes calldata, /* signature */ uint256 /* allocatorId */ ) external pure override returns (bytes4) {
        return IEmissary.verifyClaim.selector;
    }
}
