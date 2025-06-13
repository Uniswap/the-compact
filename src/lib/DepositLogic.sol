// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ConstructorLogic } from "./ConstructorLogic.sol";

import { TransferLib } from "./TransferLib.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/**
 * @title DepositLogic
 * @notice Inherited contract implementing internal functions with low-level shared logic for
 * processing token deposits.
 */
contract DepositLogic is ConstructorLogic {
    using TransferLib for address;
    using SafeTransferLib for address;

    /**
     * @notice Internal function that verifies a token balance increase and mints the
     * corresponding amount of ERC6909 tokens. Checks that the token balance has increased
     * from the provided initial balance, and mints the difference to the specified recipient.
     * Reverts if the balance has not increased. Finally, emits a Transfer event.
     * @param token          The address of the token to check the balance of.
     * @param to             The account to mint ERC6909 tokens to.
     * @param id             The ERC6909 token identifier to mint.
     * @param initialBalance The token balance before the deposit operation.
     * @return mintedAmount The minted ERC6909 token amount based on the balance change.
     */
    function _checkBalanceAndDeposit(address token, address to, uint256 id, uint256 initialBalance)
        internal
        returns (uint256 mintedAmount)
    {
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
            mintedAmount = tokenBalance - initialBalance;
        }

        // Mint the balance difference as ERC6909 tokens.
        to.deposit(id, mintedAmount);
    }
}
