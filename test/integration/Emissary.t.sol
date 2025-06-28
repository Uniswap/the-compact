// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";
import { EmissaryStatus } from "../../src/types/EmissaryStatus.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { EmissaryLib } from "../../src/lib/EmissaryLib.sol";
import { EmissaryLogic } from "../../src/lib/EmissaryLogic.sol";
import { IdLib } from "../../src/lib/IdLib.sol";
import { Setup } from "./Setup.sol";
import { AlwaysOKEmissary } from "../../src/test/AlwaysOKEmissary.sol";
import { AlwaysDenyingEmissary } from "../../src/test/AlwaysDenyingEmissary.sol";
import { AlwaysRevertingEmissary } from "../../src/test/AlwaysRevertingEmissary.sol";
import { CreateClaimHashWithWitnessArgs } from "./TestHelperStructs.sol";
import { Claim } from "../../src/types/Claims.sol";
import { BatchClaim } from "../../src/types/BatchClaims.sol";
import { Component, BatchClaimComponent } from "../../src/types/Components.sol";
import { TestParams, CreateBatchClaimHashWithWitnessArgs } from "./TestHelperStructs.sol";

contract EmissaryTest is Setup {
    function setUp() public override {
        super.setUp();
    }

    function test_assignEmissary() public {
        // Setup: register allocator
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Create a new emissary
        address emissary = address(new AlwaysOKEmissary());

        // Test: assign emissary (no scheduling needed for first assignment)
        vm.prank(swapper);
        bool success = theCompact.assignEmissary(lockTag, emissary);
        vm.snapshotGasLastCall("assignEmissary");

        // Verify: operation was successful
        assertTrue(success, "Assigning initial emissary should succeed without scheduling");

        // Verify: emissary status is enabled
        vm.prank(swapper);
        (EmissaryStatus status, uint256 emissaryAssignableAt, address currentEmissary) =
            theCompact.getEmissaryStatus(swapper, lockTag);
        assertEq(uint256(status), uint256(EmissaryStatus.Enabled), "Status should be enabled");
        assertEq(emissaryAssignableAt, type(uint96).max, "AssignableAt should be max uint96");
        assertEq(currentEmissary, emissary, "Current emissary should match assigned emissary");
    }

    function test_assignEmissary_withoutSchedule() public {
        // Setup: register allocator
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Create a new emissary
        address emissary = address(new AlwaysOKEmissary());

        // Test: assign emissary without scheduling first
        vm.prank(swapper);
        bool success = theCompact.assignEmissary(lockTag, emissary);

        // Verify: operation was successful
        assertTrue(success, "Assigning initial emissary should succeed without requiring scheduling");

        // Verify: emissary status is enabled
        vm.prank(swapper);
        (EmissaryStatus status, uint256 emissaryAssignableAt, address currentEmissary) =
            theCompact.getEmissaryStatus(swapper, lockTag);
        assertEq(uint256(status), uint256(EmissaryStatus.Enabled), "Status should be enabled");
        assertEq(emissaryAssignableAt, type(uint96).max, "AssignableAt should be max uint96");
        assertEq(currentEmissary, emissary, "Current emissary should match assigned emissary");
    }

    function test_revert_assignSecondEmissary_EmissaryAssignmentUnavailable() public {
        // Setup: register allocator
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Create two emissaries
        address emissary1 = address(new AlwaysOKEmissary());
        address emissary2 = address(new AlwaysOKEmissary());

        // Assign first emissary (should work without scheduling)
        vm.prank(swapper);
        bool success = theCompact.assignEmissary(lockTag, emissary1);
        assertTrue(success, "Assigning initial emissary should succeed without scheduling");

        // Verify first emissary is assigned
        vm.prank(swapper);
        (, uint256 assignableAt, address currentEmissary) = theCompact.getEmissaryStatus(swapper, lockTag);
        assertEq(currentEmissary, emissary1, "Current emissary should be emissary1");

        // Try to assign second emissary without scheduling (should fail)
        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.EmissaryAssignmentUnavailable.selector, assignableAt));
        theCompact.assignEmissary(lockTag, emissary2);
    }

    function test_scheduleEmissaryAssignment() public {
        // Setup: register allocator and assign an emissary first
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Create a new emissary
        address emissary = address(new AlwaysOKEmissary());

        // First assign an emissary
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, emissary);

        // Test: schedule emissary assignment again
        vm.prank(swapper);
        uint256 assignableAt = theCompact.scheduleEmissaryAssignment(lockTag);
        vm.snapshotGasLastCall("scheduleEmissaryAssignment");

        // Verify: assignable timestamp is correct (current time + reset period)
        assertEq(assignableAt, block.timestamp + 10 minutes, "Assignable timestamp should be 10 minutes from now");

        // Verify: emissary status is scheduled
        vm.prank(swapper);
        (EmissaryStatus status, uint256 emissaryAssignableAt, address currentEmissary) =
            theCompact.getEmissaryStatus(swapper, lockTag);
        assertEq(uint256(status), uint256(EmissaryStatus.Scheduled), "Status should be scheduled");
        assertEq(emissaryAssignableAt, assignableAt, "AssignableAt should match returned value");
        assertEq(currentEmissary, emissary, "Current emissary should be the assigned emissary");
    }

    function test_assignEmissary_afterSchedule() public {
        // Setup: register allocator and assign first emissary
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Create two emissaries
        address emissary1 = address(new AlwaysOKEmissary());
        address emissary2 = address(new AlwaysOKEmissary());

        // Assign first emissary (no scheduling needed)
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, emissary1);

        // Schedule reassignment
        vm.prank(swapper);
        uint256 assignableAt = theCompact.scheduleEmissaryAssignment(lockTag);

        // Verify the assignableAt time is at least the reset period from now
        assertEq(
            assignableAt,
            block.timestamp + 10 minutes,
            "Assignable timestamp should be 10 minutes from now (reset period)"
        );

        // Warp to after the waiting period
        vm.warp(assignableAt);

        // Test: assign second emissary after waiting period
        vm.prank(swapper);
        bool success = theCompact.assignEmissary(lockTag, emissary2);

        // Verify: operation was successful
        assertTrue(success, "Assigning second emissary after waiting period should succeed");

        // Verify: emissary status is enabled
        vm.prank(swapper);
        (EmissaryStatus status, uint256 emissaryAssignableAt, address currentEmissary) =
            theCompact.getEmissaryStatus(swapper, lockTag);
        assertEq(uint256(status), uint256(EmissaryStatus.Enabled), "Status should be enabled");
        assertEq(emissaryAssignableAt, type(uint96).max, "AssignableAt should be max uint96");
        assertEq(currentEmissary, emissary2, "Current emissary should be the second emissary");
    }

    function test_disableEmissary() public {
        // Setup: register allocator and assign emissary
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Create a new emissary
        address emissary = address(new AlwaysOKEmissary());

        // Assign emissary (no scheduling needed for first assignment)
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, emissary);

        // Schedule emissary reassignment to disable it
        vm.prank(swapper);
        uint256 assignableAt = theCompact.scheduleEmissaryAssignment(lockTag);

        // Warp to after the waiting period
        vm.warp(assignableAt);

        // Test: disable emissary by assigning address(0)
        vm.prank(swapper);
        bool success = theCompact.assignEmissary(lockTag, address(0));
        vm.snapshotGasLastCall("disableEmissary");

        // Verify: operation was successful
        assertTrue(success, "Disabling emissary should succeed");

        // Verify: emissary status is disabled
        vm.prank(swapper);
        (EmissaryStatus status, uint256 emissaryAssignableAt, address currentEmissary) =
            theCompact.getEmissaryStatus(swapper, lockTag);
        assertEq(uint256(status), uint256(EmissaryStatus.Disabled), "Status should be disabled");
        assertEq(emissaryAssignableAt, 0, "AssignableAt should be 0");
        assertEq(currentEmissary, address(0), "Current emissary should be zero address");
    }

    function test_getEmissaryStatus_disabled() public {
        // Setup: register allocator
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Test: get emissary status when disabled
        vm.prank(swapper);
        (EmissaryStatus status, uint256 assignableAt, address currentEmissary) =
            theCompact.getEmissaryStatus(swapper, lockTag);
        vm.snapshotGasLastCall("getEmissaryStatus_disabled");

        // Verify: status is disabled
        assertEq(uint256(status), uint256(EmissaryStatus.Disabled), "Status should be disabled");
        assertEq(assignableAt, 0, "AssignableAt should be 0");
        assertEq(currentEmissary, address(0), "Current emissary should be zero address");
    }

    function test_getEmissaryStatus_scheduled() public {
        // Setup: register allocator, assign emissary, and schedule reassignment
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Create a new emissary
        address emissary = address(new AlwaysOKEmissary());

        // First schedule and assign an emissary
        vm.prank(swapper);
        uint256 firstAssignableAt = theCompact.scheduleEmissaryAssignment(lockTag);
        vm.warp(firstAssignableAt + 1);
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, emissary);

        // Now schedule a reassignment
        vm.prank(swapper);
        uint256 secondAssignableAt = theCompact.scheduleEmissaryAssignment(lockTag);

        // Test: get emissary status when scheduled for reassignment
        vm.prank(swapper);
        (EmissaryStatus status, uint256 emissaryAssignableAt, address currentEmissary) =
            theCompact.getEmissaryStatus(swapper, lockTag);
        vm.snapshotGasLastCall("getEmissaryStatus_scheduled");

        // Verify: status is scheduled
        assertEq(uint256(status), uint256(EmissaryStatus.Scheduled), "Status should be scheduled");
        assertEq(emissaryAssignableAt, secondAssignableAt, "AssignableAt should match scheduled time");
        assertEq(currentEmissary, emissary, "Current emissary should be the assigned emissary");
    }

    function test_getEmissaryStatus_enabled() public {
        // Setup: register allocator and assign emissary (no scheduling needed for first assignment)
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Create a new emissary
        address emissary = address(new AlwaysOKEmissary());

        // Assign emissary (no scheduling needed for first assignment)
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, emissary);

        // Test: get emissary status when enabled
        vm.prank(swapper);
        (EmissaryStatus status, uint256 emissaryAssignableAt, address currentEmissary) =
            theCompact.getEmissaryStatus(swapper, lockTag);
        vm.snapshotGasLastCall("getEmissaryStatus_enabled");

        // Verify: status is enabled
        assertEq(uint256(status), uint256(EmissaryStatus.Enabled), "Status should be enabled");
        assertEq(emissaryAssignableAt, type(uint96).max, "AssignableAt should be max uint96");
        assertEq(currentEmissary, emissary, "Current emissary should match assigned emissary");
    }

    function test_scheduleEmissaryAssignment_differentResetPeriods() public {
        // Setup: register allocator
        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        // Create lock tags with different reset periods
        ResetPeriod[] memory resetPeriods = new ResetPeriod[](4);
        resetPeriods[0] = ResetPeriod.OneHourAndFiveMinutes;
        resetPeriods[1] = ResetPeriod.OneDay;
        resetPeriods[2] = ResetPeriod.SevenDaysAndOneHour;
        resetPeriods[3] = ResetPeriod.ThirtyDays;

        uint256[] memory expectedDurations = new uint256[](4);
        expectedDurations[0] = 1 hours + 5 minutes;
        expectedDurations[1] = 1 days;
        expectedDurations[2] = 7 days + 1 hours;
        expectedDurations[3] = 30 days;

        Scope scope = Scope.Multichain;

        // Schedule emissary assignments for each reset period
        for (uint256 i = 0; i < resetPeriods.length; i++) {
            bytes12 lockTag = bytes12(
                bytes32((uint256(scope) << 255) | (uint256(resetPeriods[i]) << 252) | (uint256(allocatorId) << 160))
            );

            vm.prank(swapper);
            uint256 assignableAt = theCompact.scheduleEmissaryAssignment(lockTag);

            // Verify: assignable timestamp is correct
            assertEq(
                assignableAt,
                block.timestamp + expectedDurations[i],
                "Assignable timestamp should match expected duration"
            );
        }
    }

    function test_revert_assignEmissary_NoAllocatorRegistered() public {
        // Setup: create a lock tag with an unregistered allocator
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint96 invalidAllocatorId = 12345; // Some random ID that's not registered

        bytes12 lockTag = bytes12(
            bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(invalidAllocatorId) << 160))
        );

        // Test: try to schedule emissary assignment with invalid allocator
        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(IdLib.NoAllocatorRegistered.selector, invalidAllocatorId));
        theCompact.scheduleEmissaryAssignment(lockTag);
    }

    function test_revert_assignEmissary_allocatorAsEmissary() public {
        // Setup: register allocator
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Schedule emissary assignment
        vm.prank(swapper);
        uint256 assignableAt = theCompact.scheduleEmissaryAssignment(lockTag);

        // Warp to after the waiting period
        vm.warp(assignableAt + 1);

        // Test: try to assign allocator as emissary
        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidEmissaryAssignment.selector));
        theCompact.assignEmissary(lockTag, allocator);
    }

    function test_reassignEmissary() public {
        // Setup: register allocator, schedule and assign first emissary
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        // Create two emissaries
        address emissary1 = address(new AlwaysOKEmissary());
        address emissary2 = address(new AlwaysOKEmissary());

        // Schedule and assign first emissary
        vm.prank(swapper);
        uint256 assignableAt = theCompact.scheduleEmissaryAssignment(lockTag);
        vm.warp(assignableAt + 1);
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, emissary1);

        // Verify first emissary is assigned
        vm.prank(swapper);
        (EmissaryStatus status, uint256 emissaryAssignableAt, address currentEmissary) =
            theCompact.getEmissaryStatus(swapper, lockTag);
        assertEq(currentEmissary, emissary1, "Current emissary should be emissary1");

        // Schedule reassignment
        vm.prank(swapper);
        assignableAt = theCompact.scheduleEmissaryAssignment(lockTag);
        vm.warp(assignableAt + 1);

        // Test: reassign to second emissary
        vm.prank(swapper);
        bool success = theCompact.assignEmissary(lockTag, emissary2);
        vm.snapshotGasLastCall("reassignEmissary");

        // Verify: operation was successful
        assertTrue(success, "Reassigning emissary should succeed");

        // Verify: emissary is updated
        vm.prank(swapper);
        (status, emissaryAssignableAt, currentEmissary) = theCompact.getEmissaryStatus(swapper, lockTag);
        assertEq(uint256(status), uint256(EmissaryStatus.Enabled), "Status should be enabled");
        assertEq(emissaryAssignableAt, type(uint96).max, "AssignableAt should be max uint96");
        assertEq(currentEmissary, emissary2, "Current emissary should be emissary2");
    }

    function test_claimAndWithdraw_withEmissary() public {
        uint256 amount = 1e18;
        uint256 nonce = 0;
        uint256 expires = block.timestamp + 1000;
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x3333333333333333333333333333333333333333;
        uint256 amountOne = 4e17;
        uint256 amountTwo = 6e17;
        address arbiter = 0x2222222222222222222222222222222222222222;

        (, bytes12 lockTag) = _registerAllocator(allocator);

        address emissary = address(new AlwaysOKEmissary());
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, emissary);

        uint256 id = _makeDeposit(swapper, amount, lockTag);

        bytes32 claimHash;
        bytes32 witness = _createCompactWitness(234);
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = nonce;
            args.expires = expires;
            args.id = id;
            args.amount = amount;
            args.witness = witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        Claim memory claim;
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
            claim.sponsorSignature = hex"41414141414141414141";

            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            claim.allocatorData = abi.encodePacked(r, vs);
        }

        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));
            uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(0), recipientTwo), (uint256));

            Component memory splitOne = Component({ claimant: claimantOne, amount: amountOne });

            Component memory splitTwo = Component({ claimant: claimantTwo, amount: amountTwo });

            Component[] memory recipients = new Component[](2);
            recipients[0] = splitOne;
            recipients[1] = splitTwo;

            claim.claimants = recipients;
        }

        claim.sponsor = swapper;
        claim.nonce = nonce;
        claim.expires = expires;
        claim.witness = witness;
        claim.witnessTypestring = witnessTypestring;
        claim.id = id;
        claim.allocatedAmount = amount;

        vm.prank(arbiter);
        (bytes32 returnedClaimHash) = theCompact.claim(claim);
        vm.snapshotGasLastCall("claimAndWithdraw");
        assertEq(returnedClaimHash, claimHash);

        assertEq(address(theCompact).balance, 0);
        assertEq(recipientOne.balance, amountOne);
        assertEq(recipientTwo.balance, amountTwo);
        assertEq(theCompact.balanceOf(swapper, id), 0);
        assertEq(theCompact.balanceOf(recipientOne, id), 0);
        assertEq(theCompact.balanceOf(recipientTwo, id), 0);
    }

    function test_claimAndWithdraw_Batch_withEmissary() public {
        // Setup test parameters
        TestParams memory params;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize batch claim
        BatchClaim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = block.timestamp + 1000;
        claim.witnessTypestring = witnessTypestring;

        // Register allocator and make deposits
        uint256 id;
        uint256 anotherId;
        uint256 aThirdId;
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            id = _makeDeposit(swapper, 1e18, lockTag);
            anotherId = _makeDeposit(swapper, address(token), 1e18, lockTag);
            aThirdId = _makeDeposit(swapper, address(anotherToken), 1e18, lockTag);

            assertEq(theCompact.balanceOf(swapper, id), 1e18);
            assertEq(theCompact.balanceOf(swapper, anotherId), 1e18);
            assertEq(theCompact.balanceOf(swapper, aThirdId), 1e18);

            // Assign emissary
            address emissary = address(new AlwaysOKEmissary());
            vm.prank(swapper);
            theCompact.assignEmissary(lockTag, emissary);
        }

        // Create idsAndAmounts and witness
        uint256[2][] memory idsAndAmounts;
        {
            idsAndAmounts = new uint256[2][](3);
            idsAndAmounts[0] = [id, 1e18];
            idsAndAmounts[1] = [anotherId, 1e18];
            idsAndAmounts[2] = [aThirdId, 1e18];

            uint256 witnessArgument = 234;
            claim.witness = _createCompactWitness(witnessArgument);
        }

        // Create claim hash
        bytes32 claimHash;
        {
            CreateBatchClaimHashWithWitnessArgs memory args;
            {
                args.typehash = batchCompactWithWitnessTypehash;
                args.arbiter = 0x2222222222222222222222222222222222222222;
                args.sponsor = claim.sponsor;
                args.nonce = claim.nonce;
                args.expires = claim.expires;
                args.idsAndAmountsHash = _hashOfHashes(idsAndAmounts);
                args.witness = claim.witness;
            }

            claimHash = _createBatchClaimHashWithWitness(args);
        }

        // Create signatures
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            {
                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Create batch claim components
        {
            BatchClaimComponent[] memory claims = new BatchClaimComponent[](3);

            // First claim component
            {
                uint256 claimantOne = abi.decode(
                    abi.encodePacked(bytes12(bytes32(id)), 0x1111111111111111111111111111111111111111), (uint256)
                );
                uint256 claimantTwo = abi.decode(
                    abi.encodePacked(bytes12(bytes32(id)), 0x3333333333333333333333333333333333333333), (uint256)
                );

                Component[] memory portions = new Component[](2);
                portions[0] = Component({ claimant: claimantOne, amount: 4e17 });
                portions[1] = Component({ claimant: claimantTwo, amount: 6e17 });

                claims[0] = BatchClaimComponent({ id: id, allocatedAmount: 1e18, portions: portions });
            }

            // Second claim component
            {
                uint256 claimantThree = abi.decode(
                    abi.encodePacked(bytes12(bytes32(anotherId)), 0x1111111111111111111111111111111111111111), (uint256)
                );

                Component[] memory anotherPortion = new Component[](1);
                anotherPortion[0] = Component({ claimant: claimantThree, amount: 1e18 });

                claims[1] = BatchClaimComponent({ id: anotherId, allocatedAmount: 1e18, portions: anotherPortion });
            }

            // Third claim component
            {
                uint256 claimantFour = abi.decode(
                    abi.encodePacked(bytes12(bytes32(aThirdId)), 0x3333333333333333333333333333333333333333), (uint256)
                );

                Component[] memory aThirdPortion = new Component[](1);
                aThirdPortion[0] = Component({ claimant: claimantFour, amount: 1e18 });

                claims[2] = BatchClaimComponent({ id: aThirdId, allocatedAmount: 1e18, portions: aThirdPortion });
            }

            claim.claims = claims;
        }

        // Execute claim
        bytes32 returnedClaimHash;
        {
            vm.prank(0x2222222222222222222222222222222222222222);
            returnedClaimHash = theCompact.batchClaim(claim);
            vm.snapshotGasLastCall("splitBatchClaimWithWitness");
            assertEq(returnedClaimHash, claimHash);
        }

        // Verify balances
        {
            assertEq(address(theCompact).balance, 1e18);
            assertEq(token.balanceOf(address(theCompact)), 1e18);
            assertEq(anotherToken.balanceOf(address(theCompact)), 1e18);

            assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, id), 4e17);
            assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, id), 6e17);
            assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, anotherId), 1e18);
            assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, aThirdId), 1e18);
        }
    }

    function test_revert_invalidLockTag() public {
        // Setup test parameters
        TestParams memory params;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize batch claim
        BatchClaim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = block.timestamp + 1000;
        claim.witnessTypestring = witnessTypestring;

        // Register allocator and make deposits
        uint256 id;
        uint256 anotherId;
        uint256 aThirdId;
        {
            bytes12 lockTag;
            bytes12 anotherLockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
                // Create a lock tag with a different reset period
                anotherLockTag = bytes12(
                    bytes32(
                        (uint256(Scope.Multichain) << 255) | (uint256(ResetPeriod.OneHourAndFiveMinutes) << 252)
                            | (uint256(allocatorId) << 160)
                    )
                );
            }

            id = _makeDeposit(swapper, 1e18, lockTag);
            anotherId = _makeDeposit(swapper, address(token), 1e18, lockTag);
            aThirdId = _makeDeposit(swapper, address(anotherToken), 1e18, anotherLockTag);

            assertEq(theCompact.balanceOf(swapper, id), 1e18);
            assertEq(theCompact.balanceOf(swapper, anotherId), 1e18);
            assertEq(theCompact.balanceOf(swapper, aThirdId), 1e18);

            // Assign emissary
            address emissary = address(new AlwaysOKEmissary());
            vm.prank(swapper);
            theCompact.assignEmissary(lockTag, emissary);
        }

        // Create idsAndAmounts and witness
        uint256[2][] memory idsAndAmounts;
        {
            idsAndAmounts = new uint256[2][](3);
            idsAndAmounts[0] = [id, 1e18];
            idsAndAmounts[1] = [anotherId, 1e18];
            idsAndAmounts[2] = [aThirdId, 1e18];

            uint256 witnessArgument = 234;
            claim.witness = _createCompactWitness(witnessArgument);
        }

        // Create claim hash
        bytes32 claimHash;
        {
            CreateBatchClaimHashWithWitnessArgs memory args;
            {
                args.typehash = keccak256(
                    "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)"
                );
                args.arbiter = 0x2222222222222222222222222222222222222222;
                args.sponsor = claim.sponsor;
                args.nonce = claim.nonce;
                args.expires = claim.expires;
                args.idsAndAmountsHash = _hashOfHashes(idsAndAmounts);
                args.witness = claim.witness;
            }

            claimHash = _createBatchClaimHashWithWitness(args);
        }

        // Create signatures
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            {
                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Create batch claim components
        {
            BatchClaimComponent[] memory claims = new BatchClaimComponent[](3);

            // First claim component
            {
                uint256 claimantOne = abi.decode(
                    abi.encodePacked(bytes12(bytes32(id)), 0x1111111111111111111111111111111111111111), (uint256)
                );
                uint256 claimantTwo = abi.decode(
                    abi.encodePacked(bytes12(bytes32(id)), 0x3333333333333333333333333333333333333333), (uint256)
                );

                Component[] memory portions = new Component[](2);
                portions[0] = Component({ claimant: claimantOne, amount: 4e17 });
                portions[1] = Component({ claimant: claimantTwo, amount: 6e17 });

                claims[0] = BatchClaimComponent({ id: id, allocatedAmount: 1e18, portions: portions });
            }

            // Second claim component
            {
                uint256 claimantThree = abi.decode(
                    abi.encodePacked(bytes12(bytes32(anotherId)), 0x1111111111111111111111111111111111111111), (uint256)
                );

                Component[] memory anotherPortion = new Component[](1);
                anotherPortion[0] = Component({ claimant: claimantThree, amount: 1e18 });

                claims[1] = BatchClaimComponent({ id: anotherId, allocatedAmount: 1e18, portions: anotherPortion });
            }

            // Third claim component
            {
                uint256 claimantFour = abi.decode(
                    abi.encodePacked(bytes12(bytes32(aThirdId)), 0x3333333333333333333333333333333333333333), (uint256)
                );

                Component[] memory aThirdPortion = new Component[](1);
                aThirdPortion[0] = Component({ claimant: claimantFour, amount: 1e18 });

                claims[2] = BatchClaimComponent({ id: aThirdId, allocatedAmount: 1e18, portions: aThirdPortion });
            }

            claim.claims = claims;
        }

        // Execute claim
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidLockTag.selector));
        vm.prank(0x2222222222222222222222222222222222222222);
        theCompact.batchClaim(claim);
    }

    function test_revert_invalidSignature() public {
        uint256 amount = 1e18;
        uint256 nonce = 0;
        uint256 expires = block.timestamp + 1000;
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x3333333333333333333333333333333333333333;
        uint256 amountOne = 4e17;
        uint256 amountTwo = 6e17;
        address arbiter = 0x2222222222222222222222222222222222222222;

        (, bytes12 lockTag) = _registerAllocator(allocator);

        address emissary = address(new AlwaysDenyingEmissary());
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, emissary);

        uint256 id = _makeDeposit(swapper, amount, lockTag);

        bytes32 claimHash;
        bytes32 witness = _createCompactWitness(234);
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = nonce;
            args.expires = expires;
            args.id = id;
            args.amount = amount;
            args.witness = witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        Claim memory claim;
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
            claim.sponsorSignature = hex"41414141414141414141";

            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            claim.allocatorData = abi.encodePacked(r, vs);
        }

        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));
            uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(0), recipientTwo), (uint256));

            Component memory splitOne = Component({ claimant: claimantOne, amount: amountOne });

            Component memory splitTwo = Component({ claimant: claimantTwo, amount: amountTwo });

            Component[] memory recipients = new Component[](2);
            recipients[0] = splitOne;
            recipients[1] = splitTwo;

            claim.claimants = recipients;
        }

        claim.sponsor = swapper;
        claim.nonce = nonce;
        claim.expires = expires;
        claim.witness = witness;
        claim.witnessTypestring = witnessTypestring;
        claim.id = id;
        claim.allocatedAmount = amount;

        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidSignature.selector));
        theCompact.claim(claim);
    }

    function test_revert_allocatorReverts() public {
        uint256 amount = 1e18;
        uint256 nonce = 0;
        uint256 expires = block.timestamp + 1000;
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x3333333333333333333333333333333333333333;
        uint256 amountOne = 4e17;
        uint256 amountTwo = 6e17;
        address arbiter = 0x2222222222222222222222222222222222222222;

        (, bytes12 lockTag) = _registerAllocator(allocator);

        address emissary = address(new AlwaysRevertingEmissary());
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, emissary);

        uint256 id = _makeDeposit(swapper, amount, lockTag);

        bytes32 claimHash;
        bytes32 witness = _createCompactWitness(234);
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = nonce;
            args.expires = expires;
            args.id = id;
            args.amount = amount;
            args.witness = witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        Claim memory claim;
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
            claim.sponsorSignature = hex"41414141414141414141";

            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            claim.allocatorData = abi.encodePacked(r, vs);
        }

        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));
            uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(0), recipientTwo), (uint256));

            Component memory splitOne = Component({ claimant: claimantOne, amount: amountOne });

            Component memory splitTwo = Component({ claimant: claimantTwo, amount: amountTwo });

            Component[] memory recipients = new Component[](2);
            recipients[0] = splitOne;
            recipients[1] = splitTwo;

            claim.claimants = recipients;
        }

        claim.sponsor = swapper;
        claim.nonce = nonce;
        claim.expires = expires;
        claim.witness = witness;
        claim.witnessTypestring = witnessTypestring;
        claim.id = id;
        claim.allocatedAmount = amount;

        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(AlwaysRevertingEmissary.AlwaysReverting.selector));
        theCompact.claim(claim);
    }
}
