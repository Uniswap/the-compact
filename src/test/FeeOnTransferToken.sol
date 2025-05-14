// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ERC20 } from "solady/tokens/ERC20.sol";

contract FeeOnTransferToken is ERC20 {
    string private _name;
    string private _symbol;
    uint8 private immutable _decimals;
    uint8 private immutable _fee;

    constructor(string memory name_, string memory symbol_, uint8 decimals_, uint8 fee_) {
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        _fee = fee_;
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    function _afterTokenTransfer(address from, address to, uint256) internal override {
        if (from != address(0) && to != address(0)) {
            _burn(to, _fee);
        }
    }

    /// @dev Returns the name of the token.
    function name() public view override returns (string memory) {
        return _name;
    }

    /// @dev Returns the symbol of the token.
    function symbol() public view override returns (string memory) {
        return _symbol;
    }

    /// @dev Returns the decimals places of the token.
    function decimals() public view override returns (uint8) {
        return _decimals;
    }
}
