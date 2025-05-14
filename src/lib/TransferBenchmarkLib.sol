// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ConstructorLogic } from "./ConstructorLogic.sol";
import { IdLib } from "./IdLib.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

import { BenchmarkERC20 } from "./BenchmarkERC20.sol";

/**
 * @title TransferBenchmarkLib
 * @notice Library contract implementing logic for benchmarking the approximate
 * cost of both native token withdrawals as well as generic ERC20 token withdrawals.
 * Designed to account for the idiosyncracies of gas pricing across various chains,
 * as well as to have functionality for updating the benchmarks should gas prices
 * change on a given chain.
 */
library TransferBenchmarkLib {
    // Storage scope for native token benchmarks:
    // slot: _NATIVE_TOKEN_BENCHMARK_SCOPE => benchmark.
    uint32 private constant _NATIVE_TOKEN_BENCHMARK_SCOPE = 0x655e83a8;

    // Storage scope for erc20 token benchmarks:
    // slot: _ERC20_TOKEN_BENCHMARK_SCOPE => benchmark.
    uint32 private constant _ERC20_TOKEN_BENCHMARK_SCOPE = 0x824664ed;

    // Storage scope for erc20 token benchmark transaction uniqueness.
    // slot: _ERC20_TOKEN_BENCHMARK_SENTINEL => block.number
    uint32 private constant _ERC20_TOKEN_BENCHMARK_SENTINEL = 0x83ceba49;

    error InvalidBenchmark();

    error InsufficientStipendForWithdrawalFallback();

    /**
     * @notice Internal function for benchmarking the cost of native token transfers.
     * Uses a deterministic address derived from the contract address and provided salt
     * to measure the gas cost to transfer native tokens to a cold address with no balance.
     * @param salt A bytes32 value used to derive a cold account for benchmarking.
     * @return benchmark The measured gas cost of the native token transfer.
     */
    function setNativeTokenBenchmark(bytes32 salt) internal returns (uint256 benchmark) {
        assembly ("memory-safe") {
            // Derive the target for  native token transfer using address.this & salt.
            mstore(0, address())
            mstore(0x20, salt)
            let target := shr(keccak256(0x0c, 0x34), 96)

            // Ensure callvalue is exactly 2 wei and the target balance is zero.
            if or(iszero(eq(callvalue(), 2)), iszero(iszero(balance(target)))) {
                mstore(0, 0x9f608b8a)
                revert(0x1c, 4)
            }

            // Get gas before first call.
            let firstStart := gas()

            // Perform the first call, sending 1 wei.
            let success1 := call(gas(), target, 1, codesize(), 0, codesize(), 0)

            // Get gas before second call.
            let secondStart := gas()

            // Perform the second call, sending 1 wei.
            let success2 := call(gas(), target, 1, codesize(), 0, codesize(), 0)

            // Get gas after second call.
            let secondEnd := gas()

            // Derive the benchmark cost using the first call.
            benchmark := sub(firstStart, secondStart)

            // Ensure that both calls succeeded and that the cost of the first call
            // exceeded that of the second, indicating that the account was not warm.
            if or(or(iszero(success1), iszero(success2)), iszero(gt(benchmark, sub(secondStart, secondEnd)))) {
                mstore(0, 0x9f608b8a)
                revert(0x1c, 4)
            }

            // Store the benchmark in the appropriate scope.
            sstore(_NATIVE_TOKEN_BENCHMARK_SCOPE, benchmark)
        }
    }

    /**
     * @notice Internal function for benchmarking the cost of ERC20 token transfers.
     * Measures the gas cost of transferring tokens to a zero-balance account and
     * includes the overhead of interacting with a cold token contract.
     * @param token The address of the ERC20 token to benchmark.
     * @return benchmark The measured gas cost of the ERC20 token transfer.
     */
    function setERC20TokenBenchmark(address token) internal returns (uint256 benchmark) {
        // Set the caller as the target.
        address target = msg.sender;

        assembly ("memory-safe") {
            {
                // Retrieve sentinel value.
                let sentinel := sload(_ERC20_TOKEN_BENCHMARK_SENTINEL)

                // Ensure it is not set to the current block number.
                if eq(sentinel, number()) {
                    mstore(0, 0x9f608b8a)
                    revert(0x1c, 4)
                }

                // Store the current block number for the sentinel value.
                // Note that TSTORE could be used here assuming it is supported;
                // consider using Tstorish as in the reentrancy lock.
                sstore(_ERC20_TOKEN_BENCHMARK_SENTINEL, number())
            }

            // Store function selector for name().
            mstore(0, 0x06fdde03)

            let firstCallCost
            let secondCallCost

            {
                // Get gas before first call.
                let firstStart := gas()

                // Perform the first call.
                let success1 := call(gas(), token, 0, 0x1c, 4, codesize(), 0)

                // Get gas before second call.
                let secondStart := gas()

                // Perform the second call.
                let success2 := call(gas(), token, 0, 0x1c, 4, codesize(), 0)

                // Get gas after second call.
                let secondEnd := gas()

                // Derive the benchmark cost of the call.
                firstCallCost := sub(firstStart, secondStart)
                secondCallCost := sub(secondStart, secondEnd)

                // Ensure that both calls succeeded and that the cost of the first call
                // exceeded that of the second, indicating that the account was not warm.
                if or(or(iszero(success1), iszero(success2)), iszero(gt(firstCallCost, secondCallCost))) {
                    mstore(0, 0x9f608b8a)
                    revert(0x1c, 4)
                }
            }

            // Get gas before third call.
            let thirdStart := gas()

            mstore(0x14, target) // Store target `to` argument in memory.
            mstore(0x34, 1) // Store an `amount` argument of 1 in memory.
            mstore(0x00, 0xa9059cbb000000000000000000000000) // `transfer(address,uint256)`.

            // Perform the third call and ensure it succeeds.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x10, 0x44, 0, 0x20)
                )
            ) {
                mstore(0, 0x9f608b8a)
                revert(0x1c, 4)
            }

            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.

            // Get gas after third call.
            let thirdEnd := gas()

            // Derive the execution benchmark cost using the difference.
            let thirdCallCost := sub(thirdStart, thirdEnd)

            // Combine cost of first and third calls, and remove the second call due
            // to the fact that a single call is performed, to derive the benchmark.
            benchmark := sub(add(firstCallCost, thirdCallCost), secondCallCost)

            // Burn the transferred tokens from the target.
            mstore(0, 0x89afcb44)
            mstore(0x20, target)
            if iszero(call(gas(), token, 0, 0x1c, 0x24, codesize(), 0)) {
                mstore(0, 0x9f608b8a)
                revert(0x1c, 4)
            }

            // Store the benchmark in the appropriate scope.
            sstore(_ERC20_TOKEN_BENCHMARK_SCOPE, benchmark)
        }
    }

    /**
     * @notice Internal view function to ensure there is sufficient gas remaining to
     * cover the benchmarked cost of a token withdrawal. Reverts if the remaining gas
     * is less than the benchmark for the specified token type.
     * @param token The address of the token (address(0) for native tokens).
     */
    function ensureBenchmarkExceeded(address token) internal view {
        assembly ("memory-safe") {
            // Select the appropriate scope based on the token in question.
            let scope :=
                xor(
                    _ERC20_TOKEN_BENCHMARK_SCOPE,
                    mul(xor(_ERC20_TOKEN_BENCHMARK_SCOPE, _NATIVE_TOKEN_BENCHMARK_SCOPE), iszero(token))
                )

            // Load benchmarked value and ensure it does not exceed available gas.
            if gt(sload(scope), gas()) {
                // revert InsufficientStipendForWithdrawalFallback();
                mstore(0, 0xc5274598)
                revert(0x1c, 4)
            }
        }
    }

    /**
     * @notice Internal view function for retrieving the benchmarked gas costs for
     * both native token and ERC20 token withdrawals.
     * @return nativeTokenBenchmark The benchmarked gas cost for native token withdrawals.
     * @return erc20TokenBenchmark  The benchmarked gas cost for ERC20 token withdrawals.
     */
    function getTokenWithdrawalBenchmarks()
        internal
        view
        returns (uint256 nativeTokenBenchmark, uint256 erc20TokenBenchmark)
    {
        assembly ("memory-safe") {
            nativeTokenBenchmark := sload(_NATIVE_TOKEN_BENCHMARK_SCOPE)
            erc20TokenBenchmark := sload(_ERC20_TOKEN_BENCHMARK_SCOPE)
        }
    }
}
