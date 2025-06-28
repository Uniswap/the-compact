// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test, console } from "forge-std/Test.sol";
import { TheCompact } from "../src/TheCompact.sol";
import { ITheCompact } from "../src/interfaces/ITheCompact.sol";
import { TransferBenchmarker } from "../src/lib/TransferBenchmarker.sol";
import { BenchmarkERC20 } from "../src/lib/BenchmarkERC20.sol";
import { MaliciousBenchmarkTarget } from "../src/test/MaliciousBenchmarkTarget.sol";
import { AlwaysDenyingToken } from "../src/test/AlwaysDenyingToken.sol";

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

    function test_revert_wrongValue(uint8 wrongValue) public {
        vm.assume(wrongValue != 2);
        // Check that the stipends are initially zero
        (uint256 nativeTokenStipend, uint256 erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertEq(nativeTokenStipend, 0, "Native token stipend should initially be zero");
        assertEq(erc20TokenStipend, 0, "ERC20 token stipend should initially be zero");

        // Create a new transaction by advancing the block number
        vm.roll(block.number + 1);

        // Call the __benchmark function with a random salt
        // We do not supply exactly 2 wei to the __benchmark call
        salt = keccak256(abi.encodePacked("test salt"));

        vm.expectRevert(abi.encodeWithSelector(TransferBenchmarker.InvalidBenchmark.selector));
        theCompact.__benchmark{ value: wrongValue }(salt);

        // Check that the stipends are still set to zero values
        (nativeTokenStipend, erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertEq(nativeTokenStipend, 0, "Native token stipend should not be set after reverted benchmarking");
        assertEq(erc20TokenStipend, 0, "ERC20 token stipend should not be set after reverted benchmarking");
    }

    function test_revert_alreadyBenchmarkedWithSalt() public {
        // Check that the stipends are initially zero
        (uint256 nativeTokenStipend, uint256 erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertEq(nativeTokenStipend, 0, "Native token stipend should initially be zero");
        assertEq(erc20TokenStipend, 0, "ERC20 token stipend should initially be zero");

        // Create a new transaction by advancing the block number
        vm.roll(block.number + 1);

        // Call the __benchmark function with a random salt
        // We need to supply exactly 2 wei to the __benchmark call
        salt = keccak256(abi.encodePacked("test salt"));
        (bool success,) =
            address(theCompact).call{ value: 2 wei }(abi.encodeWithSelector(theCompact.__benchmark.selector, salt));
        require(success, "Benchmark call failed");

        // Check that the stipends are now set to non-zero values
        (nativeTokenStipend, erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertGt(nativeTokenStipend, 0, "Native token stipend should be set after benchmarking");
        assertGt(erc20TokenStipend, 0, "ERC20 token stipend should be set after benchmarking");

        // Try to benchmark again, should revert for the same salt, as the benchmark target already has balance
        vm.expectRevert(abi.encodeWithSelector(TransferBenchmarker.InvalidBenchmark.selector));
        theCompact.__benchmark{ value: 2 wei }(salt);
    }

    function test_BenchmarkERC20_name() public {
        BenchmarkERC20 benchmarkERC20 = new BenchmarkERC20();
        assertEq(benchmarkERC20.name(), "Benchmark ERC20");
    }

    function test_BenchmarkERC20_symbol() public {
        BenchmarkERC20 benchmarkERC20 = new BenchmarkERC20();
        assertEq(benchmarkERC20.symbol(), "BENCHMARK_ERC20");
    }

    function test_BenchmarkERC20_revert_burn_notDeployer() public {
        BenchmarkERC20 benchmarkERC20 = new BenchmarkERC20();
        address notDeployer = makeAddr("notDeployer");
        vm.prank(address(notDeployer));
        vm.expectRevert(abi.encodeWithSelector(BenchmarkERC20.InvalidBurn.selector), address(benchmarkERC20));
        benchmarkERC20.burn(address(this));
    }

    function test_BenchmarkERC20_revert_burn_fromDeployer() public {
        BenchmarkERC20 benchmarkERC20 = new BenchmarkERC20();
        vm.prank(address(benchmarkERC20));
        vm.expectRevert(abi.encodeWithSelector(BenchmarkERC20.InvalidBurn.selector), address(benchmarkERC20));
        benchmarkERC20.burn(address(this));
    }

    function test_revert_maliciousBenchmarkTarget() public {
        // Generate benchmark address
        address benchmark = address(
            uint160(
                uint256(
                    bytes32(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(theCompact), bytes1(0x03))))
                )
            )
        );

        salt = keccak256(abi.encodePacked("test salt"));
        address maliciousBenchmarkTarget = address(bytes20(keccak256(abi.encodePacked(benchmark, salt)))); // recreate the benchmark target address
        deployCodeTo("MaliciousBenchmarkTarget", maliciousBenchmarkTarget);

        vm.expectRevert(abi.encodeWithSelector(TransferBenchmarker.InvalidBenchmark.selector), maliciousBenchmarkTarget);
        theCompact.__benchmark{ value: 2 wei }(salt);
    }

    function test_revert_manipulationOfBenchmarkTarget() public {
        // Generate benchmark address
        address benchmark = address(
            uint160(
                uint256(
                    bytes32(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(theCompact), bytes1(0x03))))
                )
            )
        );

        salt = keccak256(abi.encodePacked("test salt"));
        address benchmarkTarget = address(bytes20(keccak256(abi.encodePacked(benchmark, salt)))); // recreate the benchmark target address

        // Send ETH to manipulate the benchmark target
        (bool success,) = benchmarkTarget.call{ value: 1 }(bytes(""));
        require(success, "Failed to send ETH to malicious benchmark target");

        vm.expectRevert(abi.encodeWithSelector(TransferBenchmarker.InvalidBenchmark.selector), benchmark);
        theCompact.__benchmark{ value: 2 wei }(salt);
    }

    function test_revert_sameBlockBenchmark() public {
        salt = keccak256(abi.encodePacked("test salt"));
        bytes32 differentSalt = keccak256(abi.encodePacked("different salt"));

        address benchmark = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(theCompact), bytes1(0x03)))))
        );

        uint256 blockNumber = block.number;
        // Make the first benchmark call
        theCompact.__benchmark{ value: 2 wei }(salt);

        (uint256 nativeTokenStipend, uint256 erc20TokenStipend) = theCompact.getRequiredWithdrawalFallbackStipends();

        assertGt(nativeTokenStipend, 0, "Native token stipend should be set after benchmarking");
        assertGt(erc20TokenStipend, 0, "ERC20 token stipend should be set after benchmarking");

        assertEq(blockNumber, block.number, "Block number should be the same");

        // A second call reverts within the same block
        vm.expectRevert(abi.encodeWithSelector(TransferBenchmarker.InvalidBenchmark.selector), benchmark);
        theCompact.__benchmark{ value: 2 wei }(differentSalt);
    }

    function test_revert_warmTokenAccount() public {
        salt = keccak256(abi.encodePacked("test salt"));
        address benchmark = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(theCompact), bytes1(0x03)))))
        );
        address benchmarkToken = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(benchmark), bytes1(0x01)))))
        );

        // Warm up the token account
        BenchmarkERC20(benchmarkToken).name();

        // Call the __benchmark function
        vm.expectRevert(abi.encodeWithSelector(TransferBenchmarker.InvalidBenchmark.selector), benchmark);
        theCompact.__benchmark{ value: 2 wei }(salt);
    }
}

contract BenchmarkCoverageTest is Test {
    TheCompact public theCompact1;
    address public benchmark1;
    address public benchmarkToken1;
    TheCompact public theCompact2;
    address public benchmark2;
    address public benchmarkToken2;
    TheCompact public theCompact;
    address public benchmark;
    address public benchmarkToken;

    function setUp() public {
        // Doing all of this in the setup, because this means the contracts will be `cold` again during the test function.
        // The benchmarkERC20 contract MUST be cold for the benchmark to succeed.

        // Deploy TheCompact contract
        theCompact1 = new TheCompact();
        address benchmark_ = address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(theCompact1), bytes1(0x03))))
            )
        );
        benchmark1 = benchmark_;
        benchmarkToken1 = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(benchmark_), bytes1(0x01)))))
        );

        // Manipulate the benchmarkERC20
        {
            {
                // Clear the BenchmarkERC20 storage slots
                uint256 _TOTAL_SUPPLY_SLOT = 0x05345cdf77eb68f44c;
                uint256 _BALANCE_SLOT_SEED = 0x87a211a2;
                bytes32 benchmarkBalanceSlot;
                /// @solidity memory-safe-assembly
                assembly {
                    mstore(0x0c, _BALANCE_SLOT_SEED)
                    mstore(0x00, benchmark_)
                    benchmarkBalanceSlot := keccak256(0x0c, 0x20)
                }

                vm.etch(benchmarkToken1, ""); // Remove contract code
                vm.store(benchmarkToken1, bytes32(_TOTAL_SUPPLY_SLOT), bytes32("")); // Clear total supply
                vm.store(benchmarkToken1, benchmarkBalanceSlot, bytes32("")); // Clear balance
            }
            // Deploy the AlwaysDenyingToken contract to replace the benchmarkToken1
            deployCodeTo("AlwaysDenyingToken", abi.encode(address(0xdead), benchmark1), benchmarkToken1);

            // manipulate the blocked `from` address to be the benchmarker
            vm.store(benchmarkToken1, bytes32(uint256(0)), bytes32(uint256(uint160(benchmark1))));
        }

        // Deploy TheCompact contract
        theCompact2 = new TheCompact();
        benchmark_ = address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(theCompact2), bytes1(0x03))))
            )
        );
        benchmark2 = benchmark_;
        benchmarkToken2 = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(benchmark_), bytes1(0x01)))))
        );

        // Manipulate the benchmarkERC20
        {
            {
                // Clear the BenchmarkERC20 storage slots (not needed, as we etch the runtime bytecode, not the creation code)
                uint256 _BALANCE_SLOT_SEED = 0x87a211a2;
                bytes32 benchmarkBalanceSlot;
                /// @solidity memory-safe-assembly
                assembly {
                    mstore(0x0c, _BALANCE_SLOT_SEED)
                    mstore(0x00, benchmark_)
                    benchmarkBalanceSlot := keccak256(0x0c, 0x20)
                }
                vm.store(benchmarkToken2, benchmarkBalanceSlot, bytes32(uint256(0))); // Clear balance
            }
        }

        // Deploy an unmanipulated TheCompact contract
        theCompact = new TheCompact();
        benchmark_ = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(theCompact), bytes1(0x03)))))
        );
        benchmark = benchmark_;
        benchmarkToken = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(benchmark_), bytes1(0x01)))))
        );

        // Fund the test contract with some ETH
        vm.deal(address(this), 1 ether);
    }

    function test_revert_onFailingERC20BenchmarkTransfer() public {
        bytes32 salt = keccak256(abi.encodePacked("test salt"));

        // Call the __benchmark function with a manipulated benchmarkERC20 token that will deny the transfer
        vm.expectRevert(abi.encodeWithSelector(TransferBenchmarker.InvalidBenchmark.selector), benchmarkToken1);
        theCompact1.__benchmark{ value: 2 wei }(salt);
    }

    function test_revert_onBalanceDrained() public {
        bytes32 salt = keccak256(abi.encodePacked("test salt"));

        // Call the __benchmark function with an empty benchmarkERC20 token balance that will cancel the transfer
        vm.expectRevert(abi.encodeWithSelector(TransferBenchmarker.InvalidBenchmark.selector), benchmarkToken2);
        theCompact2.__benchmark{ value: 2 wei }(salt);
    }

    function test_revert_onBurnFailure() public {
        bytes32 salt = keccak256(abi.encodePacked("test salt"));

        vm.deal(benchmark, 1 ether);
        vm.prank(benchmark); // Call the contract with itself, so the burn target will be the benchmarker, which will fail

        // Call the __benchmark function with an failing burn
        vm.expectRevert(abi.encodeWithSelector(TransferBenchmarker.InvalidBenchmark.selector), benchmarkToken);
        TransferBenchmarker(benchmark).__benchmark{ value: 2 wei }(salt);
    }
}
