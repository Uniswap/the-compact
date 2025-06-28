// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ERC20 } from "solady/tokens/ERC20.sol";
import { console } from "forge-std/console.sol";

contract AlwaysDenyingToken is ERC20 {
    error AlwaysDenyingTokenTransferNotAllowed();

    address public blockedAccount;

    constructor(address blockedAccount_, address mintTo) {
        // Set the blocked account to a random address so a mint (from address(0) is possible)
        blockedAccount = address(0xbeef);
        _mint(mintTo, 1 ether);
        // Block only after minting
        blockedAccount = blockedAccount_;
    }

    function name() public view virtual override returns (string memory) {
        return "AlwaysDenyingToken";
    }

    function symbol() public view virtual override returns (string memory) {
        return "ADT";
    }

    function _afterTokenTransfer(address from, address, uint256) internal virtual override {
        if (from == blockedAccount) {
            revert AlwaysDenyingTokenTransferNotAllowed();
        }
    }
}
