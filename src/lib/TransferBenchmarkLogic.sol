// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { TransferBenchmarkLib } from "./TransferBenchmarkLib.sol";

import { BenchmarkERC20 } from "./BenchmarkERC20.sol";

/**
 * @title TransferBenchmarkLogic
 * @notice Inherited contract implementing logic for benchmarking the approximate
 * cost of both native token withdrawals as well as generic ERC20 token withdrawals.
 * Deploys a benchmark ERC20 token during contract creation for use in benchmarking.
 */
contract TransferBenchmarkLogic {
    using TransferBenchmarkLib for address;
    using TransferBenchmarkLib for bytes32;

    // Declare an immutable argument for the account of the benchmark ERC20 token.
    address private immutable _BENCHMARK_ERC20;

    constructor() {
        // Deploy reference ERC20 for benchmarking generic ERC20 token withdrawals. Note
        // that benchmark cannot be evaluated as part of contract creation as it requires
        // that the token account is not already warm as part of deriving the benchmark.
        _BENCHMARK_ERC20 = address(new BenchmarkERC20());
    }

    /**
     * @notice Internal function to benchmark the gas costs of token transfers.
     * Measures both native token and ERC20 token transfer costs and stores them.
     * @param salt A bytes32 value used to derive a cold account for benchmarking.
     */
    function _benchmark(bytes32 salt) internal {
        salt.setNativeTokenBenchmark();
        _BENCHMARK_ERC20.setERC20TokenBenchmark();
    }

    /**
     * @notice Internal view function for retrieving the benchmarked gas costs for
     * both native token and ERC20 token withdrawals.
     * @return nativeTokenStipend The benchmarked gas cost for native token withdrawals.
     * @return erc20TokenStipend  The benchmarked gas cost for ERC20 token withdrawals.
     */
    function _getRequiredWithdrawalFallbackStipends()
        internal
        view
        returns (uint256 nativeTokenStipend, uint256 erc20TokenStipend)
    {
        return TransferBenchmarkLib.getTokenWithdrawalBenchmarks();
    }
}
