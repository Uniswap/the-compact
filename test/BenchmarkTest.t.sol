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
    TheCompact public theCompact;

    function setUp() public {
        // Deploy TheCompact contract
        theCompact = new TheCompact();

        // Fund the test contract with some ETH
        vm.deal(address(this), 1 ether);
    }

    /**
     * @notice Test that getRequiredWithdrawalFallbackStipends values are initially zero
     * and are set after calling __benchmark
     */
    function test_benchmark() public {
        // Check that the stipends are initially zero
        (uint256 nativeTokenStipend, uint256 erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertEq(nativeTokenStipend, 0, "Native token stipend should initially be zero");
        assertEq(erc20TokenStipend, 0, "ERC20 token stipend should initially be zero");

        // Create a new transaction by advancing the block number
        vm.roll(block.number + 1);

        // Call the __benchmark function with a random salt
        // We need to supply exactly 2 wei to the __benchmark call
        bytes32 salt = keccak256(abi.encodePacked("test salt"));
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
}
