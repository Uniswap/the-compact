// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ConstructorLogic } from "./ConstructorLogic.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/**
 * @title DepositLogic
 * @notice Inherited contract implementing internal functions with low-level shared logic for
 * processing token deposits.
 */
contract DepositLogic is ConstructorLogic {
    using SafeTransferLib for address;

    // Storage slot seed for ERC6909 state, used in computing balance slots.
    uint256 private constant _ERC6909_MASTER_SLOT_SEED = 0xedcaa89a82293940;

    // keccak256(bytes("Transfer(address,address,address,uint256,uint256)")).
    uint256 private constant _TRANSFER_EVENT_SIGNATURE = 0x1b3d7edb2e9c0b0e7c525b20aaaef0f5940d2ed71663c7d39266ecafac728859;

    /**
     * @notice Internal function that verifies a token balance increase and mints the
     * corresponding amount of ERC6909 tokens. Checks that the token balance has increased
     * from the provided initial balance, and mints the difference to the specified recipient.
     * Reverts if the balance has not increased. Finally, emits a Transfer event.
     * @param token          The address of the token to check the balance of.
     * @param to             The account to mint ERC6909 tokens to.
     * @param id             The ERC6909 token identifier to mint.
     * @param initialBalance The token balance before the deposit operation.
     */
    function _checkBalanceAndDeposit(address token, address to, uint256 id, uint256 initialBalance) internal {
        // Get the current token balance to compare against initial balance.
        uint256 tokenBalance = token.balanceOf(address(this));

        // Revert if the balance hasn't increased.
        assembly ("memory-safe") {
            if iszero(lt(initialBalance, tokenBalance)) {
                // revert InvalidDepositBalanceChange()
                mstore(0, 0x426d8dcf)
                revert(0x1c, 0x04)
            }
        }

        // Skip underflow check as balance increase has been confirmed.
        unchecked {
            // Mint the balance difference as ERC6909 tokens.
            _deposit(to, id, tokenBalance - initialBalance);
        }
    }

    /**
     * @notice Internal function for minting ERC6909 tokens. Updates the recipient's balance,
     * checking for overflow, and emits a Transfer event. This function bypasses transfer
     * hooks and allowance checks as it is only called in trusted deposit contexts.
     * @param to     The address to mint tokens to.
     * @param id     The ERC6909 token identifier to mint.
     * @param amount The amount of tokens to mint.
     */
    function _deposit(address to, uint256 id, uint256 amount) internal {
        assembly ("memory-safe") {
            // Compute the recipient's balance slot using the master slot seed.
            mstore(0x20, _ERC6909_MASTER_SLOT_SEED)
            mstore(0x14, to)
            mstore(0x00, id)
            let toBalanceSlot := keccak256(0x00, 0x40)

            // Load current balance and compute new balance.
            let toBalanceBefore := sload(toBalanceSlot)
            let toBalanceAfter := add(toBalanceBefore, amount)

            // Revert on balance overflow.
            if lt(toBalanceAfter, toBalanceBefore) {
                mstore(0x00, 0x89560ca1) // `BalanceOverflow()`.
                revert(0x1c, 0x04)
            }

            // Store the updated balance.
            sstore(toBalanceSlot, toBalanceAfter)

            // Emit the Transfer event:
            // - topic1: Transfer event signature
            // - topic2: address(0) signifying a mint
            // - topic3: recipient address (sanitized)
            // - topic4: token id
            // - data: [caller, amount]
            mstore(0x00, caller())
            mstore(0x20, amount)
            log4(0, 0x40, _TRANSFER_EVENT_SIGNATURE, 0, shr(0x60, shl(0x60, to)), id)
        }
    }
}
