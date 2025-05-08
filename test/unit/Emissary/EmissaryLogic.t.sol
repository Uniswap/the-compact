// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { EmissaryStatus } from "src/types/EmissaryStatus.sol";
import "./MockEmissaryLogic.sol";
import "src/test/AlwaysOKEmissary.sol";
import "src/test/AlwaysOKAllocator.sol";
import "src/lib/EfficiencyLib.sol";

contract EmissaryLogicTest is Test {
    using IdLib for *;
    using EfficiencyLib for *;

    MockEmissaryLogic logic;

    AlwaysOKEmissary emissary1;
    AlwaysOKEmissary emissary2;

    address sponsor;
    AlwaysOKAllocator allocator;
    ResetPeriod resetPeriod;
    Scope scope;
    uint96 allocatorId;
    bytes12 lockTag;

    function setUp() public {
        logic = new MockEmissaryLogic();

        sponsor = makeAddr("sponsor");
        emissary1 = new AlwaysOKEmissary();
        emissary2 = new AlwaysOKEmissary();
        allocator = new AlwaysOKAllocator();
        resetPeriod = ResetPeriod.TenMinutes;
        scope = Scope.Multichain;

        allocatorId = logic.registerAllocator(address(allocator), "");
        lockTag = allocatorId.toLockTag(scope, resetPeriod);

        vm.warp(1743479729);
    }

    function test_new_emissary() public {
        vm.prank(sponsor);
        bool success = logic.assignEmissary(lockTag, address(emissary1));
        assertTrue(success);

        (EmissaryStatus status, uint256 assignableAt, address currentEmissary) =
            logic.getEmissaryStatus(sponsor, lockTag);

        assertTrue(status == EmissaryStatus.Enabled, "Status");
        assertTrue(assignableAt == type(uint96).max, "timestamp");
        assertTrue(currentEmissary == address(emissary1), "addr");
    }

    function test_new_emissary_withoutSchedule() public {
        test_new_emissary();
        vm.expectRevert();
        vm.prank(sponsor);
        logic.assignEmissary(lockTag, address(emissary1));
    }

    function test_reset_emissary() public {
        (EmissaryStatus status, uint256 assignableAt, address currentEmissary) =
            logic.getEmissaryStatus(sponsor, lockTag);

        assertTrue(status == EmissaryStatus.Disabled, "Status");
        assertTrue(assignableAt == 0, "timestamp");
        assertTrue(currentEmissary == address(0), "addr");

        test_new_emissary();
        vm.prank(sponsor);
        logic.scheduleEmissaryAssignment(lockTag);
        (status, assignableAt, currentEmissary) = logic.getEmissaryStatus(sponsor, lockTag);

        assertTrue(status == EmissaryStatus.Scheduled, "Status");
        assertTrue(assignableAt == block.timestamp + 10 minutes, "timestamp");
        assertTrue(currentEmissary == address(emissary1), "addr");

        vm.warp(block.timestamp + 1 minutes);

        vm.expectRevert();
        vm.prank(sponsor);
        bool success = logic.assignEmissary(lockTag, address(emissary1));
        vm.warp(block.timestamp + 10 minutes);
        vm.prank(sponsor);
        success = logic.assignEmissary(lockTag, address(emissary2));

        (status, assignableAt, currentEmissary) = logic.getEmissaryStatus(sponsor, lockTag);

        assertTrue(status == EmissaryStatus.Enabled, "Status");
        assertTrue(assignableAt == type(uint96).max, "timestamp");
        assertTrue(currentEmissary == address(emissary2), "addr");
    }

    function test_disable_emissary() public {
        (EmissaryStatus status, uint256 assignableAt, address currentEmissary) =
            logic.getEmissaryStatus(sponsor, lockTag);

        assertTrue(status == EmissaryStatus.Disabled, "Status should be disabled");
        assertTrue(assignableAt == 0, "timestamp");
        assertTrue(currentEmissary == address(0), "addr");

        // Set the emissary.
        test_new_emissary();

        vm.prank(sponsor);
        logic.scheduleEmissaryAssignment(lockTag);
        (status, assignableAt, currentEmissary) = logic.getEmissaryStatus(sponsor, lockTag);

        assertTrue(status == EmissaryStatus.Scheduled, "Status should be scheduled");
        assertTrue(assignableAt == block.timestamp + 10 minutes, "timestamp");
        assertTrue(currentEmissary == address(emissary1), "addr");

        vm.warp(block.timestamp + 10 minutes);
        vm.prank(sponsor);
        logic.assignEmissary(lockTag, address(0));

        (status, assignableAt, currentEmissary) = logic.getEmissaryStatus(sponsor, lockTag);

        assertTrue(status == EmissaryStatus.Disabled, "Status");
        assertTrue(assignableAt == 0, "timestamp should be 0");
        assertTrue(currentEmissary == address(0), "addr");
    }

    function test_lockTag() public view {
        address allocatorOne = 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF;
        uint96 allocatorOneId = allocatorOne.usingAllocatorId();
        bytes12 tag = toLockTag(allocatorOneId, Scope.Multichain, ResetPeriod.OneHourAndFiveMinutes);
        (uint96 _allocatorId, Scope _scope, ResetPeriod _resetPeriod) = fromLockTag(tag);
        assertEq(allocatorOneId, _allocatorId);
        assertTrue(scope == _scope, "scope");
        assertTrue(ResetPeriod.OneHourAndFiveMinutes == _resetPeriod, "ResetPeriod");
    }

    function toLockTag(uint96 _allocatorId, Scope _scope, ResetPeriod _resetPeriod) internal pure returns (bytes12) {
        // Derive lock tag (pack scope, reset period, & allocator ID).
        return ((_scope.asUint256() << 255) | (_resetPeriod.asUint256() << 252) | (_allocatorId.asUint256() << 160))
            .asBytes12();
    }

    function fromLockTag(bytes12 tag)
        internal
        pure
        returns (uint96 _allocatorId, Scope _scope, ResetPeriod _resetPeriod)
    {
        uint256 value = tag.asUint256();

        // Extract scope (bits 255 to 253)
        _scope = Scope(uint8((value >> 255) & 0x1)); // 0x7 = 0b111 (3 bits)

        _resetPeriod = ResetPeriod(uint8((value >> 252) & 0xF)); // FIXED: mask with 0xF for 4 bits

        // Extract allocatorId (bits 160 to 250, which is 91 bits)
        _allocatorId = uint96((value >> 160) & ((1 << 91) - 1));
    }
}
