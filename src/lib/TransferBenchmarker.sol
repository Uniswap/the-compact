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

    // Declare an immutable argument for the account of the native transfer benchmarker.
    address private immutable _NATIVE_TRANSFER_BENCHMARKER;

    // Declare an immutable argument for the account of the warm vs cold benchmarker.
    address private immutable _WARM_VS_COLD_BENCHMARKER;

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

        address nativeTokenBenchmarker;
        address warmVsColdBenchmarker;

        /**
         * 1) nativeTokenBenchmarker —> eth transfers
         *   takes one word (target address) and 2 wei
         *   returns five words:
         *    - gasCheckpointOne
         *    - success1
         *    - gasCheckpointTwo
         *    - successTwo
         *    - gasCheckpointThree
         *
         * 0x5a3d383d3860013d355af15a3d383d3860013d355af15a6080526060526040526020523d52593df3
         *
         * [00]	GAS
         * [01]	RETURNDATASIZE
         * [02]	CODESIZE
         * [03]	RETURNDATASIZE
         * [04]	CODESIZE
         * [05]	PUSH1	01
         * [07]	RETURNDATASIZE
         * [08]	CALLDATALOAD
         * [09]	GAS
         * [0a]	CALL
         * [0b]	GAS
         * [0c]	RETURNDATASIZE
         * [0d]	CODESIZE
         * [0e]	RETURNDATASIZE
         * [0f]	CODESIZE
         * [10]	PUSH1	01
         * [12]	RETURNDATASIZE
         * [13]	CALLDATALOAD
         * [14]	GAS
         * [15]	CALL
         * [16]	GAS
         * [17]	PUSH1	80
         * [19]	MSTORE
         * [1a]	PUSH1	60
         * [1c]	MSTORE
         * [1d]	PUSH1	40
         * [1f]	MSTORE
         * [20]	PUSH1	20
         * [22]	MSTORE
         * [23]	RETURNDATASIZE
         * [24]	MSTORE
         * [25]	MSIZE
         * [26]	RETURNDATASIZE
         * [27]	RETURN
         *
         * 2) warmVsColdBenchmarker —> cold vs warm access cost
         *  Takes one word (salt "address" or token address)
         *  Returns three words:
         *   - gasCheckpointOne
         *   - gasCheckpointTwo
         *   - gasCheckpointThree
         *
         * 0x5a3d35315a3d35315a60405250602052503d52593df3
         *
         * [00]	GAS
         * [01]	RETURNDATASIZE
         * [02]	CALLDATALOAD
         * [03]	BALANCE
         * [04]	GAS
         * [05]	RETURNDATASIZE
         * [06]	CALLDATALOAD
         * [07]	BALANCE
         * [08]	GAS
         * [09]	PUSH1	40
         * [0b]	MSTORE
         * [0c]	POP
         * [0d]	PUSH1	20
         * [0f]	MSTORE
         * [10]	POP
         * [11]	RETURNDATASIZE
         * [12]	MSTORE
         * [13]	MSIZE
         * [14]	RETURNDATASIZE
         * [15]	RETURN
         *
         * Both helpers use the "universal minimal constructor":
         *
         * 0x600b5981380380925939f3
         *
         * [00]	PUSH1	0b
         * [02]	MSIZE
         * [03]	DUP2
         * [04]	CODESIZE
         * [05]	SUB
         * [06]	DUP1
         * [07]	SWAP3
         * [08]	MSIZE
         * [09]	CODECOPY
         * [0a]	RETURN
         * ... runtime code
         */
        ///
        assembly ("memory-safe") {
            // Deploy the native token benchmarker.
            mstore(0x13, 0xf15a6080526060526040526020523d52593df3)
            mstore(0, 0x600b5981380380925939f35a3d383d3860013d355af15a3d383d3860013d355a)
            nativeTokenBenchmarker := create(0, 0, 0x33)

            // Deploy the warm vs. cold access benchmarker.
            mstore(0, 0x600b5981380380925939f35a3d35315a3d35315a60405250602052503d52593d)
            mstore8(0x20, 0xf3)
            warmVsColdBenchmarker := create(0, 0, 0x21)

            // Ensure that both helper contracts were successfully deployed.
            if or(iszero(nativeTokenBenchmarker), iszero(warmVsColdBenchmarker)) {
                // revert InvalidBenchmark()
                mstore(0, 0x9f608b8a)
                revert(0x1c, 4)
            }
        }

        _NATIVE_TRANSFER_BENCHMARKER = nativeTokenBenchmarker;
        _WARM_VS_COLD_BENCHMARKER = warmVsColdBenchmarker;
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
        // Place helper contract account immutable values onto the stack.
        address nativeTransferBenchmarker = _NATIVE_TRANSFER_BENCHMARKER;
        address warmVsColdBenchmarker = _WARM_VS_COLD_BENCHMARKER;

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

            let transferToWarmUncreatedAccountCost
            let transferToWarmCreatedAccountCost
            let eitherTransferFailed
            let transferBenchmarkCallSuccess

            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            {
                // Prepare the target as the sole argument to the transfer benchmark call.
                mstore(0, target)

                // Measure transfer benchmarks, providing 2 wei.
                transferBenchmarkCallSuccess := call(gas(), nativeTransferBenchmarker, 2, 0, 0x20, m, 0xa0)

                // Get gas before first call.
                let gasCheckpointOne := mload(m)

                // Get success status of the first call.
                let success1 := mload(add(m, 0x20))

                // Get gas before second call.
                let gasCheckpointTwo := mload(add(m, 0x40))

                // Get success status of the second call.
                let success2 := mload(add(m, 0x60))

                // Get gas after second call.
                let gasCheckpointThree := mload(add(m, 0x80))

                // Determine cost of transfer to uncreated and created accounts.
                transferToWarmUncreatedAccountCost := sub(gasCheckpointOne, gasCheckpointTwo)
                transferToWarmCreatedAccountCost := sub(gasCheckpointTwo, gasCheckpointThree)

                // Determine if either transfer failed.
                eitherTransferFailed := iszero(and(success1, success2))
            }

            // Prepare the salt as the sole argument to the transfer benchmark call.
            mstore(0, salt)

            // Measure warm vs cold account access benchmarks.
            let warmVsColdBenchmarkCallSuccess := staticcall(gas(), warmVsColdBenchmarker, 0, 0x20, m, 0x60)

            let coldAccountAccessCost

            {
                // Get gas before the first balance check.
                let gasCheckpointFour := mload(m)

                // Get gas after the first balance check.
                let gasCheckpointFive := mload(add(m, 0x20))

                // Get gas after second balance check.
                let gasCheckpointSix := mload(add(m, 0x40))

                // Determine the difference between the cost of the first balance check
                // and the cost of the second balance check.
                coldAccountAccessCost :=
                    sub(sub(gasCheckpointFour, gasCheckpointFive), sub(gasCheckpointFive, gasCheckpointSix))
            }

            // Ensure that both calls succeeded and that the cost of the first call
            // exceeded that of the second, indicating that the account was created.
            // Also ensure the first balance check cost exceeded the second and that
            // both benchmark attempts were successfully executed.
            if or(
                eitherTransferFailed,
                or(
                    iszero(gt(transferToWarmUncreatedAccountCost, transferToWarmCreatedAccountCost)),
                    or(
                        iszero(coldAccountAccessCost),
                        or(iszero(transferBenchmarkCallSuccess), iszero(warmVsColdBenchmarkCallSuccess))
                    )
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

        // Place warm vs cold helper contract account immutable value onto the stack.
        address warmVsColdBenchmarker = _WARM_VS_COLD_BENCHMARKER;

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
                // Retrieve the free memory pointer; memory will be left dirtied.
                let m := mload(0x40)

                // Prepare the token as the sole argument to the transfer benchmark call.
                mstore(0, token)

                // Measure warm vs cold account access benchmarks.
                let warmVsColdBenchmarkCallSuccess := staticcall(gas(), warmVsColdBenchmarker, 0, 0x20, m, 0x60)

                // Get gas before first account access.
                let firstStart := mload(m)

                // Get gas before second access.
                let secondStart := mload(add(m, 0x20))

                // Get gas after second access.
                let secondEnd := mload(add(m, 0x40))

                // Derive the benchmark cost of account access.
                firstCallCost := sub(firstStart, secondStart)
                secondCallCost := sub(secondStart, secondEnd)

                // Ensure that the cost of the first call exceeded that of the second, indicating that the
                // account was not warm. Also ensure that the benchmark attempt was successfully executed.
                if or(iszero(gt(firstCallCost, secondCallCost)), iszero(warmVsColdBenchmarkCallSuccess)) {
                    // revert InvalidBenchmark()
                    mstore(0, 0x9f608b8a)
                    revert(0x1c, 4)
                }
            }

            // Place `transfer(address,uint256)` calldata into memory before measuring `thirdStart`.
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
