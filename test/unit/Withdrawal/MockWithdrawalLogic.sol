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

    // Storage slot seed for ERC6909 state, used in computing balance slots.
    uint256 private constant _ERC6909_MASTER_SLOT_SEED = 0xedcaa89a82293940;

    // Mock token minting function for tests
    function mint(address account, uint256 id, uint256 amount) external {
        assembly {
            // Compute the sender's balance slot using the master slot seed.
            mstore(0x20, _ERC6909_MASTER_SLOT_SEED)
            mstore(0x14, account)
            mstore(0x00, id)
            let fromBalanceSlot := keccak256(0x00, 0x40)
            // NOTE: no overflow protection here
            sstore(fromBalanceSlot, add(sload(fromBalanceSlot), amount))
        }
    }

    // Mock balance query function for tests
    function balanceOf(address account, uint256 id) external view returns (uint256 balanceValue) {
        assembly {
            // Compute the sender's balance slot using the master slot seed.
            mstore(0x20, _ERC6909_MASTER_SLOT_SEED)
            mstore(0x14, account)
            mstore(0x00, id)
            let fromBalanceSlot := keccak256(0x00, 0x40)
            balanceValue := sload(fromBalanceSlot)
        }
    }

    // Expose internal functions for testing
    function enableForcedWithdrawal(uint256 id) external returns (uint256) {
        return _enableForcedWithdrawal(id);
    }

    function disableForcedWithdrawal(uint256 id) external {
        _disableForcedWithdrawal(id);
    }

    function processForcedWithdrawal(uint256 id, address recipient, uint256 amount) external {
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
