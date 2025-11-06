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
    error BalanceNotSettled();

    /// @notice Checks if the Compact is deployed and if transient storage is available on the chain.
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

    /// @notice Returns the users balance only if reentrancy protection is not active on the Compact. This eliminates in flight balances before the ERC6909 tokens were burned.
    /// @dev The function favors chains supporting eip-1153 (transient storage)
    function settledBalanceOf(address owner, uint256 id) internal view returns (uint256 amount) {
        // Favoring transient storage
        try Extsload(THE_COMPACT).exttload(bytes32(REENTRANCY_GUARD_SLOT)) returns (bytes32 reentrancySlotContent) {
            if (uint256(reentrancySlotContent) > 1) {
                revert BalanceNotSettled();
            }
        } catch {
            // If the call fails, assume transient storage is not available, so falling back to persistent storage
            try Extsload(THE_COMPACT).extsload(bytes32(REENTRANCY_GUARD_SLOT)) returns (bytes32 reentrancySlotContent) {
                if (uint256(reentrancySlotContent) > 1) {
                    revert BalanceNotSettled();
                }
            } catch {
                // If the call fails as well, assume the compact is not deployed
                revert TheCompactNotDeployed();
            }
        }

        // If we get here, the balance is settled, so returning the balance
        return ERC6909(THE_COMPACT).balanceOf(owner, id);
    }
}
