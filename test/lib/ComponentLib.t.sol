// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import { ComponentLib } from "src/lib/ComponentLib.sol";
import { Component, BatchClaimComponent } from "src/types/Components.sol";
import { Scope } from "src/types/Scope.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { IdLib } from "src/lib/IdLib.sol";
import { EfficiencyLib } from "src/lib/EfficiencyLib.sol";

error InsufficientBalance();

contract ComponentLibTester {
    using ComponentLib for Component[];
    using ComponentLib for BatchClaimComponent[];
    using IdLib for *;
    using EfficiencyLib for *;

    function aggregateComponents(Component[] calldata recipients) external pure returns (uint256) {
        return ComponentLib.aggregate(recipients);
    }

    function buildIdsAndAmounts(BatchClaimComponent[] calldata claims, bytes32 sponsorDomainSeparator)
        external
        pure
        returns (uint256[2][] memory idsAndAmounts, uint96 firstAllocatorId, uint256 shortestResetPeriod)
    {
        return ComponentLib._buildIdsAndAmounts(claims, sponsorDomainSeparator);
    }

    function verifyAndProcessComponents(
        Component[] calldata claimants,
        address sponsor,
        uint256 id,
        uint256 allocatedAmount
    ) external {
        claimants.verifyAndProcessComponents(sponsor, id, allocatedAmount);
    }
}

contract ComponentLibTest is Test {
    using ComponentLib for *;
    using IdLib for *;
    using EfficiencyLib for *;

    ComponentLibTester internal tester;

    address constant ALLOCATOR = address(0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa);
    address constant TOKEN = address(0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB);
    address constant CLAIMANT_1 = address(0x1111);
    address constant CLAIMANT_2 = address(0x2222);
    uint96 allocatorId;
    bytes12 lockTag;

    function setUp() public {
        tester = new ComponentLibTester();
        (allocatorId, lockTag) = _registerAllocator(ALLOCATOR);
    }

    function testAggregate_Empty() public view {
        Component[] memory recipients = new Component[](0);
        assertEq(tester.aggregateComponents(recipients), 0, "Aggregate empty failed");
    }

    function testAggregate_Single() public view {
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({ claimant: _makeClaimant(CLAIMANT_1), amount: 100 });
        assertEq(tester.aggregateComponents(recipients), 100, "Aggregate single failed");
    }

    function testAggregate_Multiple() public view {
        Component[] memory recipients = new Component[](3);
        recipients[0] = Component({ claimant: _makeClaimant(CLAIMANT_1), amount: 100 });
        recipients[1] = Component({ claimant: _makeClaimant(CLAIMANT_2), amount: 250 });
        recipients[2] = Component({ claimant: _makeClaimant(CLAIMANT_1), amount: 50 });
        assertEq(tester.aggregateComponents(recipients), 400, "Aggregate multiple failed");
    }

    function testAggregate_Overflow() public {
        Component[] memory recipients = new Component[](2);
        recipients[0] = Component({ claimant: _makeClaimant(CLAIMANT_1), amount: type(uint256).max });
        recipients[1] = Component({ claimant: _makeClaimant(CLAIMANT_2), amount: 1 });
        vm.expectRevert(ComponentLib.Overflow.selector);
        tester.aggregateComponents(recipients);
    }

    function testFuzzAggregate(Component[] memory recipients) public {
        uint256 len = recipients.length > 20 ? 20 : recipients.length;
        Component[] memory limitedRecipients = new Component[](len);
        uint256 expectedSum = 0;
        bool expectOverflow = false;
        for (uint256 i = 0; i < len; ++i) {
            limitedRecipients[i] = recipients[i];
            uint256 currentSum = expectedSum;

            unchecked {
                expectedSum += recipients[i].amount;
                expectOverflow = expectedSum < currentSum;
                if (expectOverflow) break;
            }
        }

        // if we did overflow, aggregate function should revert
        if (expectOverflow) {
            vm.expectRevert(ComponentLib.Overflow.selector);
            tester.aggregateComponents(limitedRecipients);
        } else {
            assertEq(tester.aggregateComponents(limitedRecipients), expectedSum, "Fuzz Aggregate failed");
        }
    }

    function _buildTestClaim(uint256 id, uint256 amount, Component[] memory portions)
        internal
        pure
        returns (BatchClaimComponent memory)
    {
        return BatchClaimComponent({ id: id, allocatedAmount: amount, portions: portions });
    }

    function _buildTestId(address allocator, address token, Scope scope, ResetPeriod period)
        internal
        pure
        returns (uint256)
    {
        return IdLib.toId(token, allocator, period, scope);
    }

    function testBuildIdsAndAmounts_Single() public view {
        uint256 id = _buildTestId(ALLOCATOR, TOKEN, Scope.Multichain, ResetPeriod.OneDay);
        uint256 amount = 1000;
        Component[] memory portions = new Component[](1);
        portions[0] = Component({ claimant: _makeClaimant(CLAIMANT_1), amount: amount });

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        claims[0] = _buildTestClaim(id, amount, portions);

        (uint256[2][] memory idsAndAmounts, uint96 firstAllocatorId, uint256 shortestResetPeriod) =
            tester.buildIdsAndAmounts(claims, bytes32(0)); // No sponsor domain sep => multichain allowed

        assertEq(idsAndAmounts.length, 1, "idsAndAmounts length mismatch");
        assertEq(idsAndAmounts[0][0], id, "ID mismatch");
        assertEq(idsAndAmounts[0][1], amount, "Amount mismatch");
        assertEq(firstAllocatorId, ALLOCATOR.usingAllocatorId(), "Allocator ID mismatch");
        assertEq(shortestResetPeriod, uint256(ResetPeriod.OneDay), "Shortest period mismatch");
    }

    function testBuildIdsAndAmounts_Multiple_Valid() public view {
        uint256 id1 = _buildTestId(ALLOCATOR, TOKEN, Scope.Multichain, ResetPeriod.OneDay);
        uint256 id2 = _buildTestId(ALLOCATOR, address(0xcccc), Scope.Multichain, ResetPeriod.OneHourAndFiveMinutes);
        uint256 amount1 = 1000;
        uint256 amount2 = 500;
        Component[] memory portions1 = new Component[](1);
        portions1[0] = Component({ claimant: _makeClaimant(CLAIMANT_1), amount: amount1 });
        Component[] memory portions2 = new Component[](1);
        portions2[0] = Component({ claimant: _makeClaimant(CLAIMANT_2), amount: amount2 });

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        claims[0] = _buildTestClaim(id1, amount1, portions1);
        claims[1] = _buildTestClaim(id2, amount2, portions2);

        (uint256[2][] memory idsAndAmounts, uint96 firstAllocatorId, uint256 shortestResetPeriod) =
            tester.buildIdsAndAmounts(claims, bytes32(0));

        assertEq(idsAndAmounts.length, 2, "idsAndAmounts length mismatch");
        assertEq(idsAndAmounts[0][0], id1);
        assertEq(idsAndAmounts[0][1], amount1);
        assertEq(idsAndAmounts[1][0], id2);
        assertEq(idsAndAmounts[1][1], amount2);
        assertEq(firstAllocatorId, ALLOCATOR.usingAllocatorId(), "Allocator ID mismatch");
        assertEq(shortestResetPeriod, uint256(ResetPeriod.OneHourAndFiveMinutes), "Shortest period mismatch"); // OneHour < OneDay
    }

    function testBuildIdsAndAmounts_RevertEmpty() public {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](0);
        vm.expectRevert(ComponentLib.NoIdsAndAmountsProvided.selector);
        tester.buildIdsAndAmounts(claims, bytes32(0));
    }

    function testBuildIdsAndAmounts_RevertAllocatorMismatch() public {
        address otherAllocator = address(0xdeadbeef);
        IdLib.register(otherAllocator); // Register the other allocator

        uint256 id1 = _buildTestId(ALLOCATOR, TOKEN, Scope.Multichain, ResetPeriod.OneDay);
        uint256 id2 = _buildTestId(otherAllocator, TOKEN, Scope.Multichain, ResetPeriod.OneDay);
        Component[] memory portions = new Component[](0); // Portions don't matter for this test

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        claims[0] = _buildTestClaim(id1, 100, portions);
        claims[1] = _buildTestClaim(id2, 200, portions);

        vm.expectRevert(ITheCompact.InvalidBatchAllocation.selector);
        tester.buildIdsAndAmounts(claims, bytes32(0));
    }

    function testBuildIdsAndAmounts_RevertScopeMismatch() public {
        uint256 id1 = _buildTestId(ALLOCATOR, TOKEN, Scope.Multichain, ResetPeriod.OneDay);
        uint256 id2 = _buildTestId(ALLOCATOR, TOKEN, Scope.ChainSpecific, ResetPeriod.OneDay);
        Component[] memory portions = new Component[](0);

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        claims[0] = _buildTestClaim(id1, 100, portions);
        claims[1] = _buildTestClaim(id2, 200, portions);

        // Non-zero implies multichain checks apply
        bytes32 sponsorDomainSeparator = bytes32(uint256(1));

        vm.expectRevert(ITheCompact.InvalidBatchAllocation.selector);
        tester.buildIdsAndAmounts(claims, sponsorDomainSeparator);
    }

    function testVerifyAndProcessComponents_AmountExceedsAllocation() public {
        uint256 id = _buildTestId(ALLOCATOR, TOKEN, Scope.Multichain, ResetPeriod.OneDay);
        uint256 allocatedAmount = 300;

        Component[] memory recipients = new Component[](2);
        recipients[0] = Component({ claimant: _makeClaimant(CLAIMANT_1), amount: 100 });
        recipients[1] = Component({ claimant: _makeClaimant(CLAIMANT_2), amount: 250 });

        vm.expectRevert(InsufficientBalance.selector);
        tester.verifyAndProcessComponents(recipients, address(this), id, allocatedAmount);
    }

    function testVerifyAndProcessComponents_EmptyClaimants() public {
        uint256 id = _buildTestId(ALLOCATOR, TOKEN, Scope.Multichain, ResetPeriod.OneDay);
        uint256 allocatedAmount = 100;
        Component[] memory recipients = new Component[](0);

        // Empty array sets the error buffer to 0, which causes a revert with AllocatedAmountExceeded
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.AllocatedAmountExceeded.selector, allocatedAmount, 0));
        tester.verifyAndProcessComponents(recipients, address(this), id, allocatedAmount);
    }

    function testVerifyAndProcessComponents_Overflow() public {
        uint256 id = _buildTestId(ALLOCATOR, TOKEN, Scope.Multichain, ResetPeriod.OneDay);
        uint256 allocatedAmount = type(uint256).max;

        Component[] memory recipients = new Component[](2);
        recipients[0] = Component({ claimant: _makeClaimant(CLAIMANT_1), amount: type(uint256).max });
        recipients[1] = Component({ claimant: _makeClaimant(CLAIMANT_2), amount: 1 });

        vm.expectRevert(InsufficientBalance.selector);
        tester.verifyAndProcessComponents(recipients, address(this), id, allocatedAmount);
    }

    function _makeClaimant(address _recipient) internal view returns (uint256) {
        return abi.decode(abi.encodePacked(lockTag, _recipient), (uint256));
    }

    function _registerAllocator(address allocator) internal returns (uint96 id, bytes12 tag) {
        id = allocator.register();
        tag = id.toLockTag(Scope.Multichain, ResetPeriod.OneDay);
        return (id, tag);
    }
}
