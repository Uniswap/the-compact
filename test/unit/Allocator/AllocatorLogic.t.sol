// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { Scope } from "src/types/Scope.sol";
import { AllocatorLogic } from "src/lib/AllocatorLogic.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import "src/test/AlwaysOKAllocator.sol";
import "src/lib/IdLib.sol";
import "src/lib/EfficiencyLib.sol";
import "src/lib/ConsumerLib.sol";
import "./MockAllocatorLogic.sol";
import { console2 } from "forge-std/console2.sol";

contract AllocatorLogicTest is Test {
    using IdLib for address;
    using IdLib for uint96;
    using EfficiencyLib for uint256;
    using EfficiencyLib for address;

    MockAllocatorLogic logic;

    address allocatorAddr;
    address userAddr;
    AlwaysOKAllocator allocatorContract;

    uint96 allocatorId;

    function setUp() public {
        logic = new MockAllocatorLogic();

        allocatorAddr = makeAddr("allocator");
        userAddr = makeAddr("user");
        allocatorContract = new AlwaysOKAllocator();

        vm.prank(allocatorAddr);
        allocatorId = logic.registerAllocator(allocatorAddr, "");

        vm.warp(1743479729);
    }

    function test_registerAllocator() public {
        // EOA allocator already registered in setup
        assertTrue(allocatorId > 0, "Allocator ID should be non-zero");

        // Test registering a contract allocator
        uint96 contractAllocatorId = logic.registerAllocator(address(allocatorContract), "");
        assertTrue(contractAllocatorId > 0, "Contract allocator ID should be non-zero");
        assertTrue(contractAllocatorId != allocatorId, "IDs should be different");
    }

    function test_registerAllocator_invalidProof() public {
        // Test with invalid proof
        vm.expectRevert();
        address randomAddr = makeAddr("random");
        logic.registerAllocator(randomAddr, "invalid");
    }

    function test_consume() public {
        uint256[] memory nonces = new uint256[](3);
        nonces[0] = 1;
        nonces[1] = 2;
        nonces[2] = 3;

        // Consume nonces as the allocator
        vm.prank(allocatorAddr);
        bool success = logic.consume(nonces);
        assertTrue(success, "Consume should return true");

        // Verify nonces are consumed
        for (uint256 i = 0; i < nonces.length; i++) {
            bool consumed = logic.hasConsumedAllocatorNonce(nonces[i], allocatorAddr);
            assertTrue(consumed, "Nonce should be consumed");
        }
    }

    function test_hasConsumedAllocatorNonce() public {
        uint256 nonce = 42;
        bool consumed = logic.hasConsumedAllocatorNonce(nonce, allocatorAddr);
        assertFalse(consumed, "Nonce should not be consumed initially");

        // Consume the nonce
        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce;

        vm.prank(allocatorAddr);
        logic.consume(nonces);

        // Verify nonce is now consumed
        consumed = logic.hasConsumedAllocatorNonce(nonce, allocatorAddr);
        assertTrue(consumed, "Nonce should be consumed after consumption");
    }

    function test_getLockDetails() public {
        // Create a mock token ID that encodes lock details
        address token = makeAddr("token");
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;

        // Generate lock ID using IdLib functions
        bytes12 lockTag = allocatorId.toLockTag(scope, resetPeriod);
        uint256 id = token.asUint256() | (uint256(bytes32(lockTag)));

        // Get lock details
        (
            address retrievedToken,
            address retrievedAllocator,
            ResetPeriod retrievedResetPeriod,
            Scope retrievedScope,
            bytes12 retrievedLockTag
        ) = logic.getLockDetails(id);

        // Assert lock details match
        assertEq(retrievedToken, token, "Token address should match");
        assertEq(retrievedAllocator, allocatorAddr, "Allocator address should match");
        assertEq(retrievedLockTag, lockTag, "Lock tags should match");
        assertEq(uint8(retrievedResetPeriod), uint8(resetPeriod), "Reset periods should match");
        assertEq(uint8(retrievedScope), uint8(scope), "Scopes should match");
    }

    function test_registerAllocator_zeroAddress() public {
        // Try to register the zero address as allocator
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidRegistrationProof.selector, address(0)));
        logic.registerAllocator(address(0), "");
    }

    function test_revert_registerAllocator_duplicateRegistration() public {
        vm.expectRevert(abi.encodeWithSelector(IdLib.AllocatorAlreadyRegistered.selector, allocatorId, allocatorAddr));
        vm.prank(allocatorAddr);
        logic.registerAllocator(allocatorAddr, "");
    }

    function test_registerAllocator_differentCallers() public {
        // Register an allocator when caller is not the allocator (should revert)
        address differentCaller = makeAddr("differentCaller");
        address targetAllocator = makeAddr("targetAllocator");

        vm.prank(differentCaller);
        vm.expectRevert();
        logic.registerAllocator(targetAllocator, "");
    }

    function test_consume_emptyArray() public {
        uint256[] memory emptyNonces = new uint256[](0);

        vm.prank(allocatorAddr);
        bool success = logic.consume(emptyNonces);
        assertTrue(success, "Consuming empty array should succeed");
    }

    function test_consume_duplicateNonces() public {
        uint256[] memory duplicateNonces = new uint256[](3);
        duplicateNonces[0] = 1;
        duplicateNonces[1] = 1;
        duplicateNonces[2] = 2;

        // Consume nonces with duplicates
        vm.prank(allocatorAddr);
        vm.expectRevert(abi.encodeWithSelector(ConsumerLib.InvalidNonce.selector, allocatorAddr, 1));
        logic.consume(duplicateNonces);
    }

    function test_consume_extremeValues() public {
        uint256[] memory extremeNonces = new uint256[](3);
        extremeNonces[0] = 0;
        extremeNonces[1] = type(uint128).max;
        extremeNonces[2] = type(uint256).max;

        vm.prank(allocatorAddr);
        bool success = logic.consume(extremeNonces);
        assertTrue(success, "Consuming extreme values should succeed");

        bool nonce0Consumed = logic.hasConsumedAllocatorNonce(0, allocatorAddr);
        bool nonce128Consumed = logic.hasConsumedAllocatorNonce(type(uint128).max, allocatorAddr);
        bool nonce256Consumed = logic.hasConsumedAllocatorNonce(type(uint256).max, allocatorAddr);

        assertTrue(nonce0Consumed, "Nonce 0 should be consumed");
        assertTrue(nonce128Consumed, "Nonce 2^128-1 should be consumed");
        assertTrue(nonce256Consumed, "Nonce 2^256-1 should be consumed");
    }

    function test_consume_unregisteredAllocator() public {
        // Try to consume nonces as unregistered allocator (should revert)
        address unregisteredAddr = makeAddr("unregistered");

        uint256[] memory nonces = new uint256[](1);
        nonces[0] = 1;

        vm.prank(unregisteredAddr);
        vm.expectRevert();
        logic.consume(nonces);
    }

    function test_consume_largeNonceArray() public {
        // Create large nonce array (100 nonces)
        uint256[] memory largeNonceArray = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            largeNonceArray[i] = i + 1;
        }

        // Consume large nonce array
        vm.prank(allocatorAddr);
        bool success = logic.consume(largeNonceArray);
        assertTrue(success, "Consuming large array should succeed");

        // Verify some nonces in the range were consumed
        bool nonce10Consumed = logic.hasConsumedAllocatorNonce(10, allocatorAddr);
        bool nonce50Consumed = logic.hasConsumedAllocatorNonce(50, allocatorAddr);
        bool nonce100Consumed = logic.hasConsumedAllocatorNonce(100, allocatorAddr);

        assertTrue(nonce10Consumed, "Nonce 10 should be consumed");
        assertTrue(nonce50Consumed, "Nonce 50 should be consumed");
        assertTrue(nonce100Consumed, "Nonce 100 should be consumed");
    }

    function test_hasConsumedAllocatorNonce_unregisteredAllocator() public {
        address unregisteredAddr = makeAddr("unregistered");

        uint256[] memory nonces = new uint256[](1);
        nonces[0] = 1;
        vm.prank(allocatorAddr);
        logic.consume(nonces);

        bool consumed = logic.hasConsumedAllocatorNonce(nonces[0], unregisteredAddr);
        assertFalse(consumed, "Unregistered allocator should not have consumed nonces");
    }
}
