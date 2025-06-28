// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BenchmarkERC20 } from "./BenchmarkERC20.sol";

/**
 * @title TransferBenchmarker
 * @notice External contract for measuring the cost of native and generic ERC20 token
 * transfers. Designed to account for the idiosyncrasies of gas pricing across various
 * chains, as well as to have functionality for updating the benchmarks should gas
 * prices change on a given chain.
 */
contract TransferBenchmarker {
    // Declare an immutable argument for the account of the benchmark ERC20 token.
    address private immutable _BENCHMARK_ERC20;

    // Storage scope for erc20 token benchmark transaction uniqueness.
    // slot: _ERC20_TOKEN_BENCHMARK_SENTINEL => block.number
    uint32 private constant _ERC20_TOKEN_BENCHMARK_SENTINEL = 0x83ceba49;

    error InvalidBenchmark();

    error InsufficientStipendForWithdrawalFallback();

    constructor() {
        // Deploy reference ERC20 for benchmarking generic ERC20 token withdrawals. Note
        // that benchmark cannot be evaluated as part of contract creation as it requires
        // that the token account is not already warm as part of deriving the benchmark.
        _BENCHMARK_ERC20 = address(new BenchmarkERC20());
    }

    /**
     * @notice External function to benchmark the gas costs of token transfers.
     * Measures both native token and ERC20 token transfer costs and stores them.
     * @param salt A bytes32 value used to derive a cold account for benchmarking.
     */
    function __benchmark(bytes32 salt)
        external
        payable
        returns (uint256 nativeTransferBenchmark, uint256 erc20TransferBenchmark)
    {
        nativeTransferBenchmark = _getNativeTokenBenchmark(salt);
        erc20TransferBenchmark = _getERC20TokenBenchmark();
    }

    /**
     * @notice Internal function for benchmarking the cost of native token transfers.
     * Uses a deterministic address derived from the contract address and provided salt
     * to measure the gas cost to transfer native tokens to a cold address with no balance.
     * @param salt A bytes32 value used to derive a cold account for benchmarking.
     * @return benchmark The measured gas cost of the native token transfer.
     */
    function _getNativeTokenBenchmark(bytes32 salt) internal returns (uint256 benchmark) {
        assembly ("memory-safe") {
            // Derive the target for native token transfer using address.this & salt.
            mstore(0, address())
            mstore(0x20, salt)
            let target := shr(0x60, keccak256(0x0c, 0x34))

            // First: measure transfer cost to an uncreated account — note that the
            // balance check prior to making the transfer will warm the account.
            // Ensure callvalue is exactly 2 wei and the target balance is zero.
            if or(xor(callvalue(), 2), balance(target)) {
                // revert InvalidBenchmark()
                mstore(0, 0x9f608b8a)
                revert(0x1c, 4)
            }

            // Get gas before first call.
            let gasCheckpointOne := gas()

            // Perform the first call, sending 1 wei.
            let success1 := call(gas(), target, 1, codesize(), 0, codesize(), 0)

            // Get gas before second call.
            let gasCheckpointTwo := gas()

            // Perform the second call, sending 1 wei.
            let success2 := call(gas(), target, 1, codesize(), 0, codesize(), 0)

            // Get gas after second call.
            let gasCheckpointThree := gas()

            // Derive a second address directly from the salt where a simple balance
            // check can be performed to assess the cost of warming an account.
            let balanceOne := balance(salt)

            // Get gas after the first balance check.
            let gasCheckpointFour := gas()

            // Check balance again now that the account is warm.
            let balanceTwo := balance(salt)

            // Get gas after second balance check.
            let gasCheckpointFive := gas()

            // Determine the cost of the first transfer to the uncreated account.
            let transferToWarmUncreatedAccountCost := sub(gasCheckpointOne, gasCheckpointTwo)

            // Determine the difference between the cost of the first balance check
            // and the cost of the second balance check.
            let coldAccountAccessCost :=
                sub(sub(gasCheckpointThree, gasCheckpointFour), sub(gasCheckpointFour, gasCheckpointFive))

            // Ensure that both calls succeeded and that the cost of the first call
            // exceeded that of the second, indicating that the account was created.
            // Also ensure the first balance check cost exceeded the second, and use
            // the balances to ensure the checks are not removed during optimization.
            if or(
                iszero(and(success1, success2)),
                or(
                    iszero(gt(transferToWarmUncreatedAccountCost, sub(gasCheckpointTwo, gasCheckpointThree))),
                    or(iszero(coldAccountAccessCost), xor(balanceOne, balanceTwo))
                )
            ) {
                // revert InvalidBenchmark()
                mstore(0, 0x9f608b8a)
                revert(0x1c, 4)
            }

            // Derive benchmark cost using first transfer cost and warm access cost.
            benchmark := add(transferToWarmUncreatedAccountCost, coldAccountAccessCost)
        }
    }

    /**
     * @notice Internal function for benchmarking the cost of ERC20 token transfers.
     * Measures the gas cost of transferring tokens to a zero-balance account and
     * includes the overhead of interacting with a cold token contract.
     * @return benchmark The measured gas cost of the ERC20 token transfer.
     */
    function _getERC20TokenBenchmark() internal returns (uint256 benchmark) {
        // Set the reference ERC20 as the token.
        address token = _BENCHMARK_ERC20;

        // Set the caller as the target (TheCompact in case of benchmarking).
        address target = msg.sender;

        assembly ("memory-safe") {
            {
                // Retrieve sentinel value.
                let sentinel := sload(_ERC20_TOKEN_BENCHMARK_SENTINEL)

                // Ensure it is not set to the current block number.
                if eq(sentinel, number()) {
                    // revert InvalidBenchmark()
                    mstore(0, 0x9f608b8a)
                    revert(0x1c, 4)
                }

                // Store the current block number for the sentinel value.
                sstore(_ERC20_TOKEN_BENCHMARK_SENTINEL, number())
            }

            let firstCallCost
            let secondCallCost

            {
                // Get gas before first account access.
                let firstStart := gas()

                // First account access.
                let balanceOne := balance(token)

                // Get gas before second access.
                let secondStart := gas()

                // Perform the second access.
                let balanceTwo := balance(token)

                // Get gas after second access.
                let secondEnd := gas()

                // Derive the benchmark cost of account access.
                firstCallCost := sub(firstStart, secondStart)
                secondCallCost := sub(secondStart, secondEnd)

                // Ensure that the cost of the first call exceeded that of the second, indicating that the account was not warm.
                // Use the balances to ensure the checks are not removed during optimization
                if or(iszero(gt(firstCallCost, secondCallCost)), xor(balanceOne, balanceTwo)) {
                    // revert InvalidBenchmark()
                    mstore(0, 0x9f608b8a)
                    revert(0x1c, 4)
                }
            }

            // Place `transfer(address,uint256)` calldata into memory before `thirdStart` to ensure accurate gas measurement
            mstore(0x14, target) // Store target `to` argument in memory.
            mstore(0x34, 1) // Store an `amount` argument of 1 in memory.
            mstore(0x00, shl(96, 0xa9059cbb)) // `transfer(address,uint256)`.

            // Get gas before third call.
            let thirdStart := gas()

            // Perform the third call, only the first word of the return data is loaded into memory at word 0.
            let transferCallStatus := call(gas(), token, 0, 0x10, 0x44, 0, 0x20)

            // Get gas after third call.
            let thirdEnd := gas()

            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten by amount.

            // Revert if call failed, or return data exists and is not equal to 1 (success)
            if iszero(
                and(
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    transferCallStatus
                )
            ) {
                // As the token is deployed by the contract itself, this should never happen except if this benchmark is called uint256.max times and has drained the balance.
                // revert InvalidBenchmark()
                mstore(0, 0x9f608b8a)
                revert(0x1c, 4)
            }

            // Derive the execution benchmark cost using the difference.
            let thirdCallCost := sub(thirdStart, thirdEnd)

            // Combine cost of first and third calls, and remove the second call due
            // to the fact that a single call is performed, to derive the benchmark.
            benchmark := sub(add(firstCallCost, thirdCallCost), secondCallCost)

            // Burn the transferred tokens from the target.
            mstore(0, 0x89afcb44)
            mstore(0x20, target)
            if iszero(call(gas(), token, 0, 0x1c, 0x24, codesize(), 0)) {
                // As the token is deployed by the contract itself, this should never happen.
                // revert InvalidBenchmark()
                mstore(0, 0x9f608b8a)
                revert(0x1c, 4)
            }
        }
    }
}
