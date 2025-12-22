// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Extsload } from "../lib/Extsload.sol";
import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { Tstorish } from "../lib/Tstorish.sol";

contract Utility {
    address internal constant THE_COMPACT = address(0x00000000000000171ede64904551eeDF3C6C9788);
    address internal constant TSTORE_TEST_CONTRACT = address(0x627c1071d6A691688938Bb856659768398262690);

    uint256 internal constant REENTRANCY_GUARD_SLOT = 0x929eee149b4bd21268;
    // ╭------------------------+---------+------+--------+-------+-------------------------------╮
    // | Name                   | Type    | Slot | Offset | Bytes | Contract                      |
    // +==========================================================================================+
    // | _tstoreSupportActiveAt | uint256 | 0    | 0      | 32    | src/TheCompact.sol:TheCompact |
    // ╰------------------------+---------+------+--------+-------+-------------------------------╯
    bytes32 internal constant TSTORE_SUPPORT_ACTIVE_AT_SLOT = 0x00;

    bool internal immutable TSTORE_INITIAL_SUPPORT;

    error TheCompactNotDeployed();
    error BalanceNotSettled();

    constructor() {
        TSTORE_INITIAL_SUPPORT = checkTstoreAvailable();
        if (TSTORE_INITIAL_SUPPORT) {
            try Tstorish(THE_COMPACT).__activateTstore() {
                // Successfully activated TSTORE
                /// @dev This leads to tstore only being active after the current block.
                ///      As a precaution, we deactivate TSTORE_INITIAL_SUPPORT.
                TSTORE_INITIAL_SUPPORT = false;
            } catch (bytes memory) {
                // Failed to activate TSTORE
                /// @dev Since we know the chain supports tstore, this call can only revert with:
                ///      TStoreAlreadyActivated(). We have to read _tstoreSupportActiveAt to confirm it is already active.
                bytes32 tstoreSupportActiveAt = Extsload(THE_COMPACT).extsload(TSTORE_SUPPORT_ACTIVE_AT_SLOT);
                if (uint256(tstoreSupportActiveAt) > block.number) {
                    TSTORE_INITIAL_SUPPORT = false;
                }
            }
        }
    }

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
        bytes32 reentrancySlotContent;

        if (TSTORE_INITIAL_SUPPORT) {
            // Only check the tstore reentrancy guard slot
            reentrancySlotContent = Extsload(THE_COMPACT).exttload(bytes32(REENTRANCY_GUARD_SLOT));
        } else {
            // Check both slots to cover the potential transition period
            try Extsload(THE_COMPACT).exttload(bytes32(REENTRANCY_GUARD_SLOT)) returns (bytes32 content) {
                reentrancySlotContent = content;
            } catch { }

            // Independent of the result, check the persistent storage slot
            reentrancySlotContent |= Extsload(THE_COMPACT).extsload(bytes32(REENTRANCY_GUARD_SLOT));
        }

        if (uint256(reentrancySlotContent) > 1) {
            revert BalanceNotSettled();
        }

        // If we get here, the balance is settled, so returning the balance
        return ERC6909(THE_COMPACT).balanceOf(owner, id);
    }
}
