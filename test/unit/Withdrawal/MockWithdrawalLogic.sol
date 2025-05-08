// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "src/lib/TheCompactLogic.sol";
import "src/lib/WithdrawalLogic.sol";
import "src/lib/TransferLib.sol";
import "src/lib/EventLib.sol";
import "src/lib/IdLib.sol";
import "src/types/ForcedWithdrawalStatus.sol";

contract MockWithdrawalLogic is TheCompactLogic {
    using IdLib for uint256;
    using IdLib for ResetPeriod;
    using EventLib for uint256;
    using TransferLib for address;

    // Mock token balances
    mapping(address => mapping(uint256 => uint256)) private balances;

    // Mock token minting function for tests
    function mint(address account, uint256 id, uint256 amount) external {
        balances[account][id] += amount;
    }

    // Mock balance query function for tests
    function balanceOf(address account, uint256 id) external view returns (uint256) {
        return balances[account][id];
    }

    // Expose internal functions for testing
    function enableForcedWithdrawal(uint256 id) external returns (uint256) {
        return _enableForcedWithdrawal(id);
    }

    function disableForcedWithdrawal(uint256 id) external {
        _disableForcedWithdrawal(id);
    }

    function processForcedWithdrawal(uint256 id, address recipient, uint256 amount) external {
        // Mock the withdraw function to update balances
        balances[msg.sender][id] -= amount;
        _processForcedWithdrawal(id, recipient, amount);
    }

    function getForcedWithdrawalStatus(address account, uint256 id)
        external
        view
        returns (ForcedWithdrawalStatus status, uint256 enabledAt)
    {
        return _getForcedWithdrawalStatus(account, id);
    }
}
