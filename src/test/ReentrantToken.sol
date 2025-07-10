// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ERC20 } from "solady/tokens/ERC20.sol";

contract ReentrantToken is ERC20 {
    string private _name;
    string private _symbol;
    uint8 private immutable _decimals;
    address private immutable _theCompact;
    bytes private _reentrantData;

    error ReentrantCallFailed();

    constructor(string memory name_, string memory symbol_, uint8 decimals_, address theCompact_, bytes memory data_) {
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        _theCompact = theCompact_;
        _reentrantData = data_;
    }

    function setReentrantData(bytes memory data_) public {
        _reentrantData = data_;
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (to == _theCompact) {
            (bool success,) = _theCompact.call(_reentrantData);
            if (!success) {
                revert ReentrantCallFailed();
            }
        }
        return super.transferFrom(from, to, amount);
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
