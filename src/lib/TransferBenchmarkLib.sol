// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Storage scope for native token benchmarks:
// slot: _NATIVE_TOKEN_BENCHMARK_SCOPE => benchmark.
uint32 constant _NATIVE_TOKEN_BENCHMARK_SCOPE = 0x655e83a8;

// Storage scope for erc20 token benchmarks:
// slot: _ERC20_TOKEN_BENCHMARK_SCOPE => benchmark.
uint32 constant _ERC20_TOKEN_BENCHMARK_SCOPE = 0x824664ed;

/**
 * @title TransferBenchmarkLib
 * @notice Library contract implementing setters and getters for the approximate
 * cost of both native token withdrawals as well as generic ERC20 token withdrawals.
 */
library TransferBenchmarkLib {
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
}
