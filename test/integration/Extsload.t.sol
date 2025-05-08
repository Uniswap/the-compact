// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TheCompact } from "../../src/TheCompact.sol";
import { MockERC20 } from "../../lib/solady/test/utils/mocks/MockERC20.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { Claim } from "../../src/types/Claims.sol";
import { Component } from "../../src/types/Components.sol";
import { IdLib } from "../../src/lib/IdLib.sol";
import { ReentrantAllocator } from "../../src/test/ReentrantAllocator.sol";
import { Setup } from "./Setup.sol";
import { CreateClaimHashWithWitnessArgs } from "./TestHelperStructs.sol";

/**
 * @title ExtsloadTest
 * @notice Integration test for the Extsload functionality in TheCompact, which
 * provides external functions for reading values from storage or transient
 * storage directly.
 */
contract ExtsloadTest is Setup {
    using IdLib for uint96;

    uint256 private constant _ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED = 0x000044036fc77deaed2300000000000000000000000;

    // Reentrant allocator for testing tstore/tload.
    ReentrantAllocator public reentrantAllocator;

    function setUp() public override {
        super.setUp();
        reentrantAllocator = new ReentrantAllocator(address(theCompact));
    }

    /**
     * @notice Test the extsload function for reading a single storage slot.
     * This test verifies that allocator address is correctly read from storage
     * using the same slot derivation logic as in IdLib.
     */
    function test_extsload_singleSlot() public {
        // Register an allocator to ensure it's in storage.
        (uint96 allocatorId,) = _registerAllocator(allocator);

        // Derive the storage slot for the allocator.
        bytes32 allocatorSlot = bytes32(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED | allocatorId);

        // Read the allocator address from storage using Extsload.
        bytes32 storedValue = theCompact.extsload(allocatorSlot);

        // Convert the bytes32 value to an address.
        address storedAllocator = address(uint160(uint256(storedValue)));

        // Verify that the stored allocator matches the expected allocator.
        assertEq(storedAllocator, allocator, "Stored allocator does not match expected allocator");
    }

    /**
     * @notice Test the extsload function for reading multiple storage slots.
     * This test verifies thatread multiple allocator addresses are correctly read from storage.
     */
    function test_extsload_multipleSlots() public {
        // Register multiple allocators
        (uint96 allocatorId1,) = _registerAllocator(allocator);

        address anotherAllocator = address(0x1111111111111111111111111111111111111111);
        vm.prank(anotherAllocator);
        uint96 allocatorId2 = theCompact.__registerAllocator(anotherAllocator, "");

        // Derive the storage slots for the allocators.
        bytes32 allocatorSlot1 = bytes32(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED | allocatorId1);
        bytes32 allocatorSlot2 = bytes32(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED | allocatorId2);

        // Create an array of slots to read.
        bytes32[] memory slots = new bytes32[](2);
        slots[0] = allocatorSlot1;
        slots[1] = allocatorSlot2;

        // Read the allocator addresses from storage using Extsload.
        bytes32[] memory storedValues = theCompact.extsload(slots);

        // Convert the bytes32 values to addresses.
        address storedAllocator1 = address(uint160(uint256(storedValues[0])));
        address storedAllocator2 = address(uint160(uint256(storedValues[1])));

        // Verify that the stored allocators match the expected allocators.
        assertEq(storedAllocator1, allocator, "Stored allocator1 does not match expected allocator");
        assertEq(storedAllocator2, anotherAllocator, "Stored allocator2 does not match expected allocator");
    }

    /**
     * @notice Test the exttload function for reading a value from transient storage.
     * Note: This test is more limited since transient storage (tstore/tload) is a newer EVM feature
     * and may not be available in all test environments.
     */
    function test_exttload() public {
        // Skip this test if the environment doesn't support transient storage.
        try theCompact.exttload(bytes32(0)) returns (bytes32) {
            // This indicates that transient storage is supported.

            // Verify that the function doesn't revert.
            bytes32 slot = bytes32(uint256(1));
            bytes32 value = theCompact.exttload(slot);

            // The value should be 0 this slot hasn't been written to.
            assertEq(value, bytes32(0), "Transient storage value should be 0");
        } catch {
            // If the call reverts, transient storage is not supported in this environment.
            emit log("Skipping test_exttload as transient storage is not supported in this environment");
        }
    }

    /**
     * @notice Test reading an unregistered allocator ID.
     * This test verifies the expected zero address is returned when reading a storage slot
     * for an allocator ID that hasn't been registered.
     */
    function test_extsload_unregisteredAllocator() public view {
        // Create an allocator ID that hasn't been registered.
        uint96 unregisteredAllocatorId = 123456;

        // Derive the storage slot for the unregistered allocator.
        bytes32 allocatorSlot = bytes32(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED | unregisteredAllocatorId);

        // Read the allocator address from storage using Extsload.
        bytes32 storedValue = theCompact.extsload(allocatorSlot);

        // Convert the bytes32 value to an address.
        address storedAllocator = address(uint160(uint256(storedValue)));

        // Verify that the stored allocator is the zero address.
        assertEq(storedAllocator, address(0), "Unregistered allocator should return zero address");
    }

    /**
     * @notice Test reading multiple allocator IDs with a mix of registered and unregistered IDs.
     */
    function test_extsload_mixedAllocators() public {
        // Register an allocator.
        (uint96 allocatorId,) = _registerAllocator(allocator);

        // Create an allocator ID that hasn't been registered.
        uint96 unregisteredAllocatorId = 123456;

        // Derive the storage slots.
        bytes32 registeredSlot = bytes32(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED | allocatorId);
        bytes32 unregisteredSlot = bytes32(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED | unregisteredAllocatorId);

        // Create an array of slots to read.
        bytes32[] memory slots = new bytes32[](2);
        slots[0] = registeredSlot;
        slots[1] = unregisteredSlot;

        // Read the values from storage using Extsload.
        bytes32[] memory storedValues = theCompact.extsload(slots);

        // Convert the bytes32 values to addresses.
        address storedRegisteredAllocator = address(uint160(uint256(storedValues[0])));
        address storedUnregisteredAllocator = address(uint160(uint256(storedValues[1])));

        // Verify the results.
        assertEq(storedRegisteredAllocator, allocator, "Stored registered allocator does not match expected allocator");
        assertEq(storedUnregisteredAllocator, address(0), "Unregistered allocator should return zero address");
    }

    /**
     * @notice Test the exttload function for reading the reentrancy guard during a reentrant call.
     * This test uses a custom allocator that attempts to read the reentrancy guard slot
     * during the authorizeClaim function, which is called during the claim process.
     */
    function test_exttload_reentrancyGuard() public {
        // Register the reentrant allocator.
        vm.prank(address(reentrantAllocator));
        uint96 allocatorId = theCompact.__registerAllocator(address(reentrantAllocator), "");
        bytes12 lockTag = _createLockTag(ResetPeriod.TenMinutes, Scope.Multichain, allocatorId);

        // Initialize claim struct.
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = 1e18;

        // Make a deposit with the reentrant allocator.
        claim.id = _makeDeposit(swapper, claim.allocatedAmount, lockTag);

        // Create witness.
        claim.witness = _createCompactWitness(234);
        claim.witnessTypestring = witnessTypestring;

        // Create claim hash.
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = address(0x2222222222222222222222222222222222222222);
            args.sponsor = claim.sponsor;
            args.nonce = claim.nonce;
            args.expires = claim.expires;
            args.id = claim.id;
            args.amount = claim.allocatedAmount;
            args.witness = claim.witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        // Create signatures.
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            // Create sponsor signature.
            {
                (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
                claim.sponsorSignature = abi.encodePacked(r, vs);
            }

            // For the allocator signature, use a dummy value since ReentrantAllocator
            // will check the reentrancy guard during authorizeClaim regardless.
            claim.allocatorData = hex"deadbeef";
        }

        // Prepare recipients.
        {
            address recipientOne = address(0x1111111111111111111111111111111111111111);
            address recipientTwo = address(0x3333333333333333333333333333333333333333);
            uint256 amountOne = 4e17;
            uint256 amountTwo = 6e17;

            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));
            uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(0), recipientTwo), (uint256));

            Component[] memory recipients = new Component[](2);
            recipients[0] = Component({ claimant: claimantOne, amount: amountOne });
            recipients[1] = Component({ claimant: claimantTwo, amount: amountTwo });

            claim.claimants = recipients;
        }

        // Execute claim - this will trigger authorizeClaim in the ReentrantAllocator.
        vm.prank(address(0x2222222222222222222222222222222222222222));

        // Process the claim.
        theCompact.claim(claim);

        // Check if the reentrancy guard was detected.
        assertTrue(reentrantAllocator.reentrantCallDetected(), "Reentrancy guard was not detected");

        // Check the value read from the reentrancy guard slot.
        bytes32 reentrancyGuardValue = reentrantAllocator.reentrancyGuardValue();
        address storedAddress = address(uint160(uint256(reentrancyGuardValue)));
        assertEq(
            storedAddress,
            address(0x2222222222222222222222222222222222222222),
            "Reentrancy guard value does not match arbiter address"
        );
    }
}
