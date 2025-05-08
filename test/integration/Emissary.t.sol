// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";
import { EmissaryStatus } from "../../src/types/EmissaryStatus.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";

import { Setup } from "./Setup.sol";
import { AlwaysOKEmissary } from "../../src/test/AlwaysOKEmissary.sol";

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

    function test_assignSecondEmissary_withoutSchedule() public {
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
        (,, address currentEmissary) = theCompact.getEmissaryStatus(swapper, lockTag);
        assertEq(currentEmissary, emissary1, "Current emissary should be emissary1");

        // Try to assign second emissary without scheduling (should fail)
        vm.prank(swapper);
        vm.expectRevert();
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

    function test_assignEmissary_invalidAllocator() public {
        // Setup: create a lock tag with an unregistered allocator
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint96 invalidAllocatorId = 12345; // Some random ID that's not registered

        bytes12 lockTag = bytes12(
            bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(invalidAllocatorId) << 160))
        );

        // Test: try to schedule emissary assignment with invalid allocator
        vm.prank(swapper);
        vm.expectRevert();
        theCompact.scheduleEmissaryAssignment(lockTag);
    }

    function test_assignEmissary_allocatorAsEmissary() public {
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
        vm.expectRevert();
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
}
