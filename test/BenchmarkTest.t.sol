// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test, console } from "forge-std/Test.sol";
import { TheCompact } from "../src/TheCompact.sol";
import { ITheCompact } from "../src/interfaces/ITheCompact.sol";

/**
 * @title BenchmarkTest
 * @notice Tests for the __benchmark and getRequiredWithdrawalFallbackStipends functions
 */
contract BenchmarkTest is Test {
    TheCompact private theCompact;
    address private benchmarker;
    bytes32 private salt;

    function setUp() public {
        // Deploy TheCompact contract
        theCompact = new TheCompact();
        // Fund the test contract with some ETH
        vm.deal(address(this), 1 ether);

        // TheCompact stores benchmarker in private immutable, so we need to calculate address here
        benchmarker = vm.computeCreateAddress(address(theCompact), 3);
        // Some random salt
        salt = keccak256(bytes("test salt"));
    }

    /**
     * @notice Test that getRequiredWithdrawalFallbackStipends values are initially zero
     * and are set after calling __benchmark
     */
    function test_benchmark() external {
        // Check that the stipends are initially zero
        (uint256 nativeTokenStipend, uint256 erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertEq(nativeTokenStipend, 0, "Native token stipend should initially be zero");
        assertEq(erc20TokenStipend, 0, "ERC20 token stipend should initially be zero");

        // Create a new transaction by advancing the block number
        vm.roll(block.number + 1);

        // Call the __benchmark function with a random salt
        // We need to supply exactly 2 wei to the __benchmark call
        (bool success,) =
            address(theCompact).call{ value: 2 wei }(abi.encodeWithSelector(theCompact.__benchmark.selector, salt));
        require(success, "Benchmark call failed");

        // Check that the stipends are now set to non-zero values
        (nativeTokenStipend, erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertGt(nativeTokenStipend, 0, "Native token stipend should be set after benchmarking");
        assertGt(erc20TokenStipend, 0, "ERC20 token stipend should be set after benchmarking");

        // Log the values for informational purposes
        console.log("Native token stipend:", nativeTokenStipend);
        console.log("ERC20 token stipend:", erc20TokenStipend);
    }

    // Only 2 wei can be provided to the `__benchmark` call
    function test_benchmarkSucceedWithValueTwo() external {
        (bool success,) =
            address(theCompact).call{ value: 2 wei }(abi.encodeWithSelector(theCompact.__benchmark.selector, salt));
        require(success, "Benchmark call failed");

        // Check that the stipends are now set to non-zero values
        (uint256 nativeTokenStipend, uint256 erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertGt(nativeTokenStipend, 0, "Native token stipend should be set after benchmarking");
        assertGt(erc20TokenStipend, 0, "ERC20 token stipend should be set after benchmarking");
    }

    function test_benchmarkFailsWithNonZeroTargetBalance() external {
        // Recalculate the target address to which the benchmarker will attempt to send the native token.
        address target = getBenchmarkerTarget();

        // Increase balance to non-zero
        deal(target, 1 ether);

        // Should fail
        (bool success,) =
            address(theCompact).call{ value: 2 wei }(abi.encodeWithSelector(theCompact.__benchmark.selector, salt));
        assertFalse(success, "Target has non-zero balance but benchmark succeeded");
    }

    // Fails with other values
    function testFuzz_benchmarkRevertWithValueDifferentFromTwo(uint256 val) external {
        vm.assume(val != 2);

        deal(address(this), val);

        (bool success,) =
            address(theCompact).call{ value: val }(abi.encodeWithSelector(theCompact.__benchmark.selector, salt));

        // Check that the stipends are now set to non-zero values
        (uint256 nativeTokenStipend, uint256 erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertFalse(success, "Benchmark call succeeded with incorrect value");
        assertEq(nativeTokenStipend, 0, "Native token stipend shouldn't change with failed call");
        assertEq(erc20TokenStipend, 0, "ERC20 token stipend shouldn't change with failed call");
    }

    function test_ifNativeTokenTransferFailsRevert() external {
        address target = getBenchmarkerTarget();
        vm.etch(target, hex"5f5ffd"); // push0 push0 revert

        (bool success,) =
            address(theCompact).call{ value: 2 wei }(abi.encodeWithSelector(theCompact.__benchmark.selector, salt));
        assertFalse(success, "Benchmark succeeded while target reverted");
    }

    function test_ifTokenTransferFailsRevert() external {
        address token = vm.computeCreateAddress(benchmarker, 1);
        vm.etch(token, hex"5f5ffd"); // push0 push0 revert

        (bool success,) =
            address(theCompact).call{ value: 2 wei }(abi.encodeWithSelector(theCompact.__benchmark.selector, salt));
        assertFalse(success, "Benchmark succeeded while target reverted");
    }

    // Helpers
    function getBenchmarkerTarget() private view returns (address target) {
        assembly {
            mstore(0, sload(benchmarker.slot))
            mstore(0x20, sload(salt.slot))
            target := shr(0x60, keccak256(0x0c, 0x34))
        }
    }
}
