// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ConstructorLogic } from "./ConstructorLogic.sol";
import { IdLib } from "./IdLib.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/**
 * @title SharedLogic
 * @notice Inherited contract implementing logic for internal functions with
 * low-level shared logic for processing transfers and withdrawals.
 */
contract SharedLogic is ConstructorLogic {
    using IdLib for uint256;
    using SafeTransferLib for address;

    // Storage slot seed for ERC6909 state, used in computing balance slots.
    uint256 private constant _ERC6909_MASTER_SLOT_SEED = 0xedcaa89a82293940;

    // keccak256(bytes("Transfer(address,address,address,uint256,uint256)")).
    uint256 private constant _TRANSFER_EVENT_SIGNATURE = 0x1b3d7edb2e9c0b0e7c525b20aaaef0f5940d2ed71663c7d39266ecafac728859;

    /**
     * @notice Internal function for transferring ERC6909 tokens between accounts. Updates
     * both balances, checking for overflow and insufficient balance. This function bypasses
     * transfer hooks and allowance checks as it is only called in trusted contexts. Emits
     * a Transfer event.
     * @param from   The account to transfer tokens from.
     * @param to     The account to transfer tokens to.
     * @param id     The ERC6909 token identifier to transfer.
     * @param amount The amount of tokens to transfer.
     * @return       Whether the transfer was successful.
     */
    function _release(address from, address to, uint256 id, uint256 amount) internal virtual returns (bool) {
        assembly ("memory-safe") {
            // Compute the sender's balance slot using the master slot seed.
            mstore(0x20, _ERC6909_MASTER_SLOT_SEED)
            mstore(0x14, from)
            mstore(0x00, id)
            let fromBalanceSlot := keccak256(0x00, 0x40)

            // Load from sender's current balance.
            let fromBalance := sload(fromBalanceSlot)

            // Revert if amount is zero or exceeds balance.
            if or(iszero(amount), gt(amount, fromBalance)) {
                mstore(0x00, 0xf4d678b8) // `InsufficientBalance()`.
                revert(0x1c, 0x04)
            }

            // Subtract from current balance and store the updated balance.
            sstore(fromBalanceSlot, sub(fromBalance, amount))

            // Compute the recipient's balance slot and update balance.
            mstore(0x14, to)
            mstore(0x00, id)
            let toBalanceSlot := keccak256(0x00, 0x40)
            let toBalanceBefore := sload(toBalanceSlot)
            let toBalanceAfter := add(toBalanceBefore, amount)

            // Revert if the balance overflows.
            if lt(toBalanceAfter, toBalanceBefore) {
                mstore(0x00, 0x89560ca1) // `BalanceOverflow()`.
                revert(0x1c, 0x04)
            }

            // Store the recipient's updated balance.
            sstore(toBalanceSlot, toBalanceAfter)

            // Emit the Transfer event:
            //  - topic1: Transfer event signature
            //  - topic2: sender address (sanitized)
            //  - topic3: recipient address (sanitized)
            //  - topic4: token id
            //  - data: [caller, amount]
            mstore(0x00, caller())
            mstore(0x20, amount)
            log4(0x00, 0x40, _TRANSFER_EVENT_SIGNATURE, shr(0x60, shl(0x60, from)), shr(0x60, shl(0x60, to)), id)
        }

        return true;
    }

    /**
     * @notice Internal function for burning ERC6909 tokens and withdrawing the underlying
     * tokens. Updates the sender's balance and transfers either native tokens or ERC20
     * tokens to the recipient. For ERC20 withdrawals, the actual amount burned is derived
     * from the balance change. Uses a reentrancy guard due to external calls. Emits a
     * Transfer event.
     * @param from   The account to burn tokens from.
     * @param to     The account to send underlying tokens to.
     * @param id     The ERC6909 token identifier to burn.
     * @param amount The amount of tokens to burn and withdraw.
     * @return       Whether the withdrawal was successful.
     */
    function _withdraw(address from, address to, uint256 id, uint256 amount) internal virtual returns (bool) {
        // Set reentrancy guard due to external token transfers.
        _setReentrancyGuard();

        // Derive the underlying token from the id of the resource lock.
        address token = id.toToken();

        // Handle native token withdrawals directly.
        if (token == address(0)) {
            to.trySafeTransferETH(amount, SafeTransferLib.GAS_STIPEND_NO_GRIEF);
        } else {
            // For ERC20s, track balance change to determine actual withdrawal amount.
            uint256 initialBalance = token.balanceOf(address(this));

            // Perform the token withdrawal.
            token.safeTransfer(to, amount);

            // Derive actual amount from balance change. A balance increase would cause
            // a massive underflow, resulting in a failure during the subsequent burn.
            unchecked {
                amount = initialBalance - token.balanceOf(address(this));
            }
        }

        assembly ("memory-safe") {
            // Compute the sender's balance slot using the master slot seed.
            mstore(0x20, _ERC6909_MASTER_SLOT_SEED)
            mstore(0x14, from)
            mstore(0x00, id)
            let fromBalanceSlot := keccak256(0x00, 0x40)

            // Load from sender's current balance.
            let fromBalance := sload(fromBalanceSlot)

            // Revert if insufficient balance.
            if gt(amount, fromBalance) {
                mstore(0x00, 0xf4d678b8) // `InsufficientBalance()`.
                revert(0x1c, 0x04)
            }

            // Subtract from current balance and store the updated balance.
            sstore(fromBalanceSlot, sub(fromBalance, amount))

            // Emit the Transfer event:
            //  - topic1: Transfer event signature
            //  - topic2: sender address (sanitized)
            //  - topic3: address(0) signifying a burn
            //  - topic4: token id
            //  - data: [caller, amount]
            mstore(0x00, caller())
            mstore(0x20, amount)
            log4(0x00, 0x40, _TRANSFER_EVENT_SIGNATURE, shr(0x60, shl(0x60, from)), 0, id)
        }

        // Clear the reentrancy guard.
        _clearReentrancyGuard();

        return true;
    }
}
