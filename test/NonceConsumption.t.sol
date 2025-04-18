// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console } from "forge-std/Test.sol";
import { TheCompact } from "../src/TheCompact.sol";
import { AlwaysOKAllocator } from "../src/test/AlwaysOKAllocator.sol";
import { ITheCompact } from "../src/interfaces/ITheCompact.sol";

contract NonceConsumptionTest is Test {
    TheCompact public theCompact;
    address allocator;
    uint96 allocatorId;

    function setUp() public {
        // Deploy TheCompact contract
        theCompact = new TheCompact();

        // Deploy and register an allocator
        allocator = address(new AlwaysOKAllocator());
        vm.prank(allocator);
        allocatorId = theCompact.__registerAllocator(allocator, "");
    }

    function test_consumeNonces() public {
        // Set up nonces to consume
        uint256[] memory noncesToConsume = new uint256[](3);
        noncesToConsume[0] = 1;
        noncesToConsume[1] = 42;
        noncesToConsume[2] = 255;

        // Consume nonces as the allocator
        vm.prank(allocator);
        bool success = theCompact.consume(noncesToConsume);

        // Verify the operation was successful
        assertTrue(success, "Nonce consumption should succeed");

        // Check that each nonce was consumed
        for (uint256 i = 0; i < noncesToConsume.length; i++) {
            bool consumed = theCompact.hasConsumedAllocatorNonce(noncesToConsume[i], allocator);
            assertTrue(
                consumed, string(abi.encodePacked("Nonce ", vm.toString(noncesToConsume[i]), " should be consumed"))
            );
        }

        // Verify that a nonce we didn't consume is still valid
        uint256 unusedNonce = 100;
        bool isUnusedNonceConsumed = theCompact.hasConsumedAllocatorNonce(unusedNonce, allocator);
        assertFalse(isUnusedNonceConsumed, "Unused nonce should not be consumed");
    }

    function test_consumeNonceEvents() public {
        // Set up a single nonce to consume
        uint256[] memory noncesToConsume = new uint256[](1);
        noncesToConsume[0] = 123;

        // Expect the NonceConsumedDirectly event to be emitted
        vm.expectEmit(true, false, false, true);
        emit ITheCompact.NonceConsumedDirectly(allocator, 123);

        // Consume the nonce
        vm.prank(allocator);
        theCompact.consume(noncesToConsume);
    }

    function test_cannotConsumeNonceTwice() public {
        // Set up a nonce to consume
        uint256[] memory noncesToConsume = new uint256[](1);
        noncesToConsume[0] = 5;

        // Consume the nonce first time
        vm.prank(allocator);
        theCompact.consume(noncesToConsume);

        // Try to consume the same nonce again, should revert
        vm.prank(allocator);
        vm.expectRevert(abi.encodeWithSignature("InvalidNonce(address,uint256)", allocator, 5));
        theCompact.consume(noncesToConsume);
    }

    function test_onlyAllocatorCanConsumeNonces() public {
        // Set up a nonce to consume
        uint256[] memory noncesToConsume = new uint256[](1);
        noncesToConsume[0] = 7;

        // Try to consume as a non-allocator address
        address nonAllocator = address(0x123);
        vm.prank(nonAllocator);
        vm.expectRevert(); // Should revert as the caller is not a registered allocator
        theCompact.consume(noncesToConsume);
    }

    function test_consumeMultipleNoncesAtOnce() public {
        // Set up many nonces to consume
        uint256[] memory noncesToConsume = new uint256[](10);
        for (uint256 i = 0; i < noncesToConsume.length; i++) {
            noncesToConsume[i] = i + 1000;
        }

        // Consume all nonces at once
        vm.prank(allocator);
        bool success = theCompact.consume(noncesToConsume);

        // Verify the operation was successful
        assertTrue(success, "Batch nonce consumption should succeed");

        // Check that each nonce was consumed
        for (uint256 i = 0; i < noncesToConsume.length; i++) {
            bool consumed = theCompact.hasConsumedAllocatorNonce(noncesToConsume[i], allocator);
            assertTrue(
                consumed, string(abi.encodePacked("Nonce ", vm.toString(noncesToConsume[i]), " should be consumed"))
            );
        }
    }
}
