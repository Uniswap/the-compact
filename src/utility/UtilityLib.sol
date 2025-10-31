// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Extsload } from "../lib/Extsload.sol";
import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { Tstorish } from "../lib/Tstorish.sol";

library UtilityLib {
    address internal constant THE_COMPACT = address(0x00000000000000171ede64904551eeDF3C6C9788);
    address internal constant TSTORE_TEST_CONTRACT = address(0x627c1071d6A691688938Bb856659768398262690);

    uint256 internal constant REENTRANCY_GUARD_SLOT = 0x929eee149b4bd21268;

    error TheCompactNotDeployed();
    error UntrustedBalance();

    function checkTstoreAvailable() internal view returns (bool ok) {
        if (TSTORE_TEST_CONTRACT.code.length == 0) {
            revert TheCompactNotDeployed();
        }

        // Call the test contract, which will perform a TLOAD test. If the call
        // does not revert, then TLOAD/TSTORE is supported. Do not forward all
        // available gas, as all forwarded gas will be consumed on revert.
        // Note that this assumes that the contract was successfully deployed.
        address tloadTestContract = TSTORE_TEST_CONTRACT;
        assembly ("memory-safe") {
            ok := staticcall(div(gas(), 10), tloadTestContract, 0, 0, 0, 0)
        }
    }

    /// @notice Returns the users balance only if no reentrancy is active on the Compact. This eliminates in flight balances and ensures a valid value.
    /// @dev Only if eip-1153 (transient storage) available.
    function settledBalanceOf(address owner, uint256 id) internal view returns (uint256 amount) {
        // If transient storage available
        bytes32 reentrancySlotContent = Extsload(THE_COMPACT).exttload(bytes32(REENTRANCY_GUARD_SLOT));
        if (uint256(reentrancySlotContent) > 1) {
            revert UntrustedBalance();
        }

        return ERC6909(THE_COMPACT).balanceOf(owner, id);
    }

    /// @notice Returns the users balance only if no reentrancy is active on the Compact. This eliminates in flight balances and ensures a valid value.
    /// @dev Only if eip-1153 (transient storage) is not available.
    function settledBalanceOf_nonTransient(address owner, uint256 id) internal view returns (uint256 amount) {
        // If  storage available
        bytes32 reentrancySlotContent = Extsload(THE_COMPACT).extsload(bytes32(REENTRANCY_GUARD_SLOT));
        if (uint256(reentrancySlotContent) > 1) {
            revert UntrustedBalance();
        }

        return ERC6909(THE_COMPACT).balanceOf(owner, id);
    }
}
