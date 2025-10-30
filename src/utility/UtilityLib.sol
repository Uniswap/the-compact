// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Extsload } from "../lib/Extsload.sol";
import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { Tstorish } from "../lib/Tstorish.sol";

library UtilityLib {
    address public constant THE_COMPACT = address(0x00000000000000171ede64904551eeDF3C6C9788);
    uint256 public constant REENTRANCY_GUARD_SLOT = 0x929eee149b4bd21268;

    error TheCompactNotDeployed();
    error UntrustedBalance();

    function isTstoreAvailable() public returns (bool tstoreAvailable, uint256 tStoreAvailableAt) {
        try Tstorish(THE_COMPACT).__activateTstore() {
            // Transient storage was not previously activated, but will become available at the next block.
            return (false, block.number + 1);
        } catch (bytes memory errorData) {
            bytes4 selector;
            if (errorData.length == 4) {
                assembly ("memory-safe") {
                    // skip the length word and load the first 32-byte chunk;
                    // the bytes4 variable is right-aligned automatically
                    selector := mload(add(errorData, 0x20))
                }
            } else {
                // returned with unknown error length, which could never happen with the correct compact deployment.
                revert TheCompactNotDeployed();
            }
            if (selector == bytes4(0xf45b98b0)) {
                // returned with error: TStoreAlreadyActivated(), so tstore is available.
                return (true, 0);
            } else if (selector == bytes4(0x70a4078f)) {
                // returned with error: TStoreNotSupported(), so tstore is not available.
                return (false, type(uint256).max);
            } else {
                // returned with unknown error, which could never happen with the correct compact deployment.
                revert TheCompactNotDeployed();
            }
        }
    }

    /// @notice Returns the users balance only if no reentrancy is active on the Compact. This eliminates in flight balances and ensures a valid value.
    /// @dev Only if eip-1153 (transient storage) available.
    function safeBalanceOf(address owner, uint256 id) public view returns (uint256 amount) {
        // If transient storage available
        bytes32 reentrancySlotContent = Extsload(THE_COMPACT).exttload(bytes32(REENTRANCY_GUARD_SLOT));
        if (uint256(reentrancySlotContent) > 1) {
            revert UntrustedBalance();
        }

        return ERC6909(THE_COMPACT).balanceOf(owner, id);
    }

    /// @notice Returns the users balance only if no reentrancy is active on the Compact. This eliminates in flight balances and ensures a valid value.
    /// @dev Only if eip-1153 (transient storage) is not available.
    function safeBalanceOf_nonTransient(address owner, uint256 id) public view returns (uint256 amount) {
        // If  storage available
        bytes32 reentrancySlotContent = Extsload(THE_COMPACT).extsload(bytes32(REENTRANCY_GUARD_SLOT));
        if (uint256(reentrancySlotContent) > 1) {
            revert UntrustedBalance();
        }

        return ERC6909(THE_COMPACT).balanceOf(owner, id);
    }
}
