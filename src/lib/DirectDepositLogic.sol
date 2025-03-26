// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";

import { EfficiencyLib } from "./EfficiencyLib.sol";
import { IdLib } from "./IdLib.sol";
import { DepositLogic } from "./DepositLogic.sol";
import { ValidityLib } from "./ValidityLib.sol";
import { SharedLib } from "./SharedLogic.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

/**
 * @title DirectDepositLogic
 * @notice Inherited contract implementing internal functions with logic for processing
 * direct token deposits (or deposits that do not involve Permit2). This includes both
 * single-token deposits and batch token deposits.
 */
contract DirectDepositLogic is DepositLogic {
    using SharedLib for address;
    using IdLib for uint96;
    using IdLib for uint256;
    using IdLib for address;
    using EfficiencyLib for bool;
    using ValidityLib for address;
    using SafeTransferLib for address;

    /**
     * @notice Internal function for depositing native tokens into a resource lock and
     * receiving back ERC6909 tokens representing the underlying locked balance controlled
     * by the depositor. The allocator mediating the lock is provided as an argument, and the
     * default reset period (ten minutes) and scope (multichain) will be used for the resource
     * lock. The ERC6909 token amount received by the caller will match the amount of native
     * tokens sent with the transaction.
     * @param allocator The address of the allocator.
     * @return id The ERC6909 token identifier of the associated resource lock.
     */
    function _performBasicNativeTokenDeposit(address allocator) internal returns (uint256 id) {
        // Derive the resource lock ID using the null address and default parameters.
        id = address(0).toIdIfRegistered(Scope.Multichain, ResetPeriod.TenMinutes, allocator);

        // Mint ERC6909 tokens to caller using derived ID and supplied native tokens.
        msg.sender.deposit(id, msg.value);
    }

    /**
     * @notice Internal function for depositing multiple tokens in a single transaction. The
     * first entry in idsAndAmounts can optionally represent native tokens by providing the null
     * address and an amount matching msg.value. For ERC20 tokens, the caller must directly
     * approve The Compact to transfer sufficient amounts on its behalf. The ERC6909 token amounts
     * received by the recipient are derived from the differences between starting and ending
     * balances held in the resource locks, which may differ from the amounts transferred depending
     * on the implementation details of the respective tokens.
     * @param idsAndAmounts Array of [id, amount] pairs with each pair indicating the resource lock and amount to deposit.
     * @param recipient     The address that will receive the corresponding ERC6909 tokens.
     */
    function _processBatchDeposit(uint256[2][] calldata idsAndAmounts, address recipient) internal {
        // Set reentrancy guard.
        _setReentrancyGuard();

        // Retrieve the total number of IDs and amounts in the batch.
        uint256 totalIds = idsAndAmounts.length;

        // Declare variables for ID, amount, and whether first token is native.
        uint256 id;
        uint256 amount;
        bool firstUnderlyingTokenIsNative;

        assembly ("memory-safe") {
            // Determine the offset of idsAndAmounts in calldata.
            let idsAndAmountsOffset := idsAndAmounts.offset

            // Load the first ID from idsAndAmounts.
            id := calldataload(idsAndAmountsOffset)

            // Determine if token encoded in first ID is the null address.
            firstUnderlyingTokenIsNative := iszero(shr(96, shl(96, id)))

            // Revert if:
            //  * the array is empty
            //  * the callvalue is zero but the first token is native
            //  * the callvalue is nonzero but the first token is non-native
            //  * the first token is non-native and the callvalue doesn't equal the first amount
            if or(iszero(totalIds), or(eq(firstUnderlyingTokenIsNative, iszero(callvalue())), and(firstUnderlyingTokenIsNative, iszero(eq(callvalue(), calldataload(add(idsAndAmountsOffset, 0x20))))))) {
                // revert InvalidBatchDepositStructure()
                mstore(0, 0xca0fc08e)
                revert(0x1c, 0x04)
            }
        }

        // Derive current allocator ID from first resource lock ID.
        uint96 currentAllocatorId = id.toRegisteredAllocatorId();

        // Declare variable for subsequent allocator IDs.
        uint96 newAllocatorId;

        // Deposit native tokens directly if first underlying token is native.
        if (firstUnderlyingTokenIsNative) {
            recipient.deposit(id, msg.value);
        }

        // Iterate over remaining IDs and amounts.
        unchecked {
            for (uint256 i = firstUnderlyingTokenIsNative.asUint256(); i < totalIds; ++i) {
                // Navigate to the current ID and amount pair in calldata.
                uint256[2] calldata idAndAmount = idsAndAmounts[i];

                // Retrieve the current ID and amount.
                id = idAndAmount[0];
                amount = idAndAmount[1];

                // Derive new allocator ID from current resource lock ID.
                newAllocatorId = id.toAllocatorId();

                // Determine if new allocator ID differs from current allocator ID.
                if (newAllocatorId != currentAllocatorId) {
                    // Ensure new allocator ID is registered.
                    newAllocatorId.mustHaveARegisteredAllocator();

                    // Update current allocator ID.
                    currentAllocatorId = newAllocatorId;
                }

                // Transfer underlying tokens in and mint ERC6909 tokens to recipient.
                _transferAndDeposit(id.toToken(), recipient, id, amount);
            }
        }

        // Clear reentrancy guard.
        _clearReentrancyGuard();
    }

    /**
     * @notice Internal function for depositing native tokens into a resource lock and
     * receiving back ERC6909 tokens representing the underlying locked balance controlled
     * by the depositor. The allocator mediating the lock is provided as an argument, and the
     * default reset period (ten minutes) and scope (multichain) will be used for the resource
     * lock. The ERC6909 token amount received by the caller will match the amount of native
     * tokens sent with the transaction.
     * @param allocator The address of the allocator.
     * @return id The ERC6909 token identifier of the associated resource lock.
     */
    function _performBasicERC20Deposit(address token, address allocator, uint256 amount) internal returns (uint256 id) {
        // Derive resource lock ID using provided token, default parameters, and allocator.
        id = token.excludingNative().toIdIfRegistered(Scope.Multichain, ResetPeriod.TenMinutes, allocator);

        // Transfer underlying tokens in and mint ERC6909 tokens to caller.
        _transferAndDepositWithReentrancyGuard(token, msg.sender, id, amount);
    }

    /**
     * @notice Internal function for depositing native tokens into a resource lock with custom
     * reset period and scope parameters. The ERC6909 token amount received by the recipient
     * will match the amount of native tokens sent with the transaction.
     * @param allocator   The address of the allocator mediating the resource lock.
     * @param resetPeriod The duration after which the resource lock can be reset once a forced withdrawal is initiated.
     * @param scope       The scope of the resource lock (multichain or single chain).
     * @param recipient   The address that will receive the corresponding ERC6909 tokens.
     * @return id         The ERC6909 token identifier of the associated resource lock.
     */
    function _performCustomNativeTokenDeposit(address allocator, ResetPeriod resetPeriod, Scope scope, address recipient) internal returns (uint256 id) {
        // Derive resource lock ID using null address, provided parameters, and allocator.
        id = address(0).toIdIfRegistered(scope, resetPeriod, allocator);

        // Deposit native tokens and mint ERC6909 tokens to recipient.
        recipient.deposit(id, msg.value);
    }

    /**
     * @notice Internal function for depositing ERC20 tokens into a resource lock with custom reset
     * period and scope parameters. The caller must directly approve The Compact to transfer a
     * sufficient amount of the ERC20 token on its behalf. The ERC6909 token amount received by
     * the recipient is derived from the difference between the starting and ending balance held
     * in the resource lock, which may differ from the amount transferred depending on the
     * implementation details of the respective token.
     * @param token       The address of the ERC20 token to deposit.
     * @param allocator   The address of the allocator mediating the resource lock.
     * @param resetPeriod The duration after which the resource lock can be reset once a forced withdrawal is initiated.
     * @param scope       The scope of the resource lock (multichain or single chain).
     * @param amount      The amount of tokens to deposit.
     * @param recipient   The address that will receive the corresponding ERC6909 tokens.
     * @return id         The ERC6909 token identifier of the associated resource lock.
     */
    function _performCustomERC20Deposit(address token, address allocator, ResetPeriod resetPeriod, Scope scope, uint256 amount, address recipient) internal returns (uint256 id) {
        // Derive resource lock ID using provided token, parameters, and allocator.
        id = token.excludingNative().toIdIfRegistered(scope, resetPeriod, allocator);

        // Transfer ERC20 tokens in and mint ERC6909 tokens to recipient.
        _transferAndDepositWithReentrancyGuard(token, recipient, id, amount);
    }

    /**
     * @notice Private function for transferring ERC20 tokens in and minting the resulting balance
     * change of `id` to `to`. Emits a Transfer event.
     * @param token The address of the ERC20 token to transfer.
     * @param to    The address that will receive the corresponding ERC6909 tokens.
     * @param id    The ERC6909 token identifier of the associated resource lock.
     * @param amount The amount of tokens to transfer.
     */
    function _transferAndDeposit(address token, address to, uint256 id, uint256 amount) private {
        // Retrieve initial token balance of this contract.
        uint256 initialBalance = token.balanceOf(address(this));

        // Transfer tokens from caller to this contract.
        token.safeTransferFrom(msg.sender, address(this), amount);

        // Compare new balance to initial balance and deposit ERC6909 tokens to recipient.
        _checkBalanceAndDeposit(token, to, id, initialBalance);
    }

    /**
     * @notice Private function for transferring ERC20 tokens in and minting the resulting balance
     * change of `id` to `to`. Emits a Transfer event.
     * @param token The address of the ERC20 token to transfer.
     * @param to    The address that will receive the corresponding ERC6909 tokens.
     * @param id    The ERC6909 token identifier of the associated resource lock.
     * @param amount The amount of tokens to transfer.
     */
    function _transferAndDepositWithReentrancyGuard(address token, address to, uint256 id, uint256 amount) private {
        // Set reentrancy guard.
        _setReentrancyGuard();

        // Transfer tokens in and mint ERC6909 tokens to recipient.
        _transferAndDeposit(token, to, id, amount);

        // Clear reentrancy guard.
        _clearReentrancyGuard();
    }
}
