// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ERC20 } from "solady/tokens/ERC20.sol";

contract ExcessiveToken is ERC20 {
    mapping(address => uint256) public transferCount;
    mapping(address => uint256) public transferAmount;
    mapping(address => uint256) public receivedAmount;

    constructor(address target) {
        _mint(target, 1 ether);
    }

    function name() public view virtual override returns (string memory) {
        return "ExcessiveToken";
    }

    function symbol() public view virtual override returns (string memory) {
        return "EXC";
    }

    function _afterTokenTransfer(address from, address to, uint256 amount) internal virtual override {
        // Excessive token transfer to trigger benchmark
        transferCount[from]++;
        transferAmount[from] += amount;
        receivedAmount[to] += amount;
    }
}
