// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import { ForcedWithdrawalStatus } from "src/types/ForcedWithdrawalStatus.sol";
import "src/lib/IdLib.sol";
import "./MockWithdrawalLogic.sol";

contract WithdrawalLogicTest is Test {
    using IdLib for uint256;

    MockWithdrawalLogic logic;

    address user;
    address recipient;
    uint256 testTokenId;

    function setUp() public {
        logic = new MockWithdrawalLogic();

        user = makeAddr("user");
        recipient = makeAddr("recipient");

        // Create a token ID that encodes a reset period
        testTokenId = 0x000001 | (uint256(ResetPeriod.OneDay) << 252);
        logic.mint(user, testTokenId, 1000);

        vm.warp(1743479729);
    }

    function test_enableForcedWithdrawal() public {
        vm.prank(user);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        // Reset period is OneDay, so withdrawable time should be 1 day from now
        assertEq(withdrawableAt, block.timestamp + 1 days, "Withdrawable timestamp should be 1 day from now");

        // Check the withdrawal status
        vm.prank(user);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = logic.getForcedWithdrawalStatus(user, testTokenId);

        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Pending), "Status should be pending");
        assertEq(enabledAt, block.timestamp + 1 days, "EnabledAt should match withdrawableAt");
    }

    function test_disableForcedWithdrawal() public {
        vm.startPrank(user);
        // First enable forced withdrawal
        logic.enableForcedWithdrawal(testTokenId);

        // Now disable it
        logic.disableForcedWithdrawal(testTokenId);

        // Check the withdrawal status
        (ForcedWithdrawalStatus status, uint256 enabledAt) = logic.getForcedWithdrawalStatus(user, testTokenId);
        vm.stopPrank();

        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Disabled), "Status should be disabled");
        assertEq(enabledAt, 0, "EnabledAt should be 0");
    }

    function test_disableForcedWithdrawal_alreadyDisabled() public {
        // Trying to disable a withdrawal that's already disabled should revert
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.ForcedWithdrawalAlreadyDisabled.selector, user, testTokenId));
        logic.disableForcedWithdrawal(testTokenId);
    }

    function test_processForcedWithdrawal() public {
        // First enable forced withdrawal
        vm.prank(user);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        // Try to withdraw before time has elapsed
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.PrematureWithdrawal.selector, testTokenId));
        logic.processForcedWithdrawal(testTokenId, recipient, 500);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        // Now withdrawal should work
        vm.prank(user);
        logic.processForcedWithdrawal(testTokenId, recipient, 500);

        // Check balances
        assertEq(logic.balanceOf(user, testTokenId), 500, "User should have 500 tokens left");
    }

    function test_getForcedWithdrawalStatus_disabled() public {
        vm.prank(user);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = logic.getForcedWithdrawalStatus(user, testTokenId);

        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Disabled), "Status should be disabled");
        assertEq(enabledAt, 0, "EnabledAt should be 0");
    }

    function test_getForcedWithdrawalStatus_pending() public {
        // Enable forced withdrawal
        vm.prank(user);
        logic.enableForcedWithdrawal(testTokenId);

        vm.prank(user);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = logic.getForcedWithdrawalStatus(user, testTokenId);

        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Pending), "Status should be pending");
        assertEq(enabledAt, block.timestamp + 1 days, "EnabledAt should be 1 day from now");
    }

    function test_getForcedWithdrawalStatus_enabled() public {
        // Enable forced withdrawal
        vm.prank(user);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        vm.prank(user);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = logic.getForcedWithdrawalStatus(user, testTokenId);

        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Enabled), "Status should be enabled");
        assertEq(enabledAt, withdrawableAt, "EnabledAt should match withdrawableAt");
    }

    function test_enableForcedWithdrawal_differentResetPeriods() public {
        // Create token IDs with different reset periods
        uint256[] memory tokenIds = new uint256[](4);
        tokenIds[0] = 0x000001 | (uint256(ResetPeriod.OneHourAndFiveMinutes) << 252);
        tokenIds[1] = 0x000002 | (uint256(ResetPeriod.OneDay) << 252);
        tokenIds[2] = 0x000003 | (uint256(ResetPeriod.SevenDaysAndOneHour) << 252);
        tokenIds[3] = 0x000004 | (uint256(ResetPeriod.ThirtyDays) << 252);

        uint256[] memory expectedDurations = new uint256[](4);
        expectedDurations[0] = 1 hours + 5 minutes;
        expectedDurations[1] = 1 days;
        expectedDurations[2] = 7 days + 1 hours;
        expectedDurations[3] = 30 days;

        // Mint tokens for all IDs
        for (uint256 i = 0; i < tokenIds.length; i++) {
            logic.mint(user, tokenIds[i], 100);
        }

        // Enable forced withdrawal for each token and verify correct reset period
        for (uint256 i = 0; i < tokenIds.length; i++) {
            vm.prank(user);
            uint256 withdrawableAt = logic.enableForcedWithdrawal(tokenIds[i]);

            assertEq(
                withdrawableAt,
                block.timestamp + expectedDurations[i],
                "Withdrawable timestamp should match expected duration"
            );
        }
    }

    function test_enableForcedWithdrawal_whenAlreadyEnabled() public {
        // First enable forced withdrawal
        vm.prank(user);
        uint256 firstWithdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        // Warp time forward a bit
        vm.warp(block.timestamp + 12 hours);

        // Re-enable the forced withdrawal
        vm.prank(user);
        uint256 secondWithdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        // Should update to a new timestamp
        assertNotEq(firstWithdrawableAt, secondWithdrawableAt, "New withdrawable timestamp should be different");
        assertEq(secondWithdrawableAt, block.timestamp + 1 days, "New timestamp should be 1 day from current time");
    }

    function test_processForcedWithdrawal_exactTimestamp() public {
        // First enable forced withdrawal
        vm.prank(user);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        // Warp to exactly when it becomes withdrawable
        vm.warp(withdrawableAt);

        // Now withdrawal should work
        vm.prank(user);
        logic.processForcedWithdrawal(testTokenId, recipient, 500);

        // Check balances
        assertEq(logic.balanceOf(user, testTokenId), 500, "User should have 500 tokens left");
    }

    function test_processForcedWithdrawal_zeroAmount() public {
        // First enable forced withdrawal
        vm.prank(user);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        // Try to withdraw zero tokens
        vm.prank(user);
        logic.processForcedWithdrawal(testTokenId, recipient, 0);

        // Check balances - should be unchanged
        assertEq(logic.balanceOf(user, testTokenId), 1000, "User should still have 1000 tokens");
    }

    function test_processForcedWithdrawal_fullBalance() public {
        // First enable forced withdrawal
        vm.prank(user);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        // Withdraw entire balance
        vm.prank(user);
        logic.processForcedWithdrawal(testTokenId, recipient, 1000);

        // Check balances
        assertEq(logic.balanceOf(user, testTokenId), 0, "User should have 0 tokens left");
    }

    function test_processForcedWithdrawal_zeroAddress() public {
        // First enable forced withdrawal
        vm.prank(user);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        // Withdraw to zero address
        vm.prank(user);
        logic.processForcedWithdrawal(testTokenId, address(0), 100);

        // Check balances
        assertEq(logic.balanceOf(user, testTokenId), 900, "User should have 900 tokens left");
    }

    function test_processForcedWithdrawal_requestExceedingBalance() public {
        vm.prank(user);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);
        vm.warp(withdrawableAt + 1);

        uint256 amount = logic.balanceOf(user, testTokenId) + 1;
        vm.prank(user);

        // TODO: add a custom error to avoid panic here?
        // currently reverts with 0x11 (panic: arithmetic under/overflow)
        vm.expectRevert();
        logic.processForcedWithdrawal(testTokenId, recipient, amount);
    }

    function test_disableForcedWithdrawal_justBeforeEnabling() public {
        vm.startPrank(user);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        vm.warp(withdrawableAt - 1);

        logic.disableForcedWithdrawal(testTokenId);

        // Warp to after when it would have been enabled
        vm.warp(withdrawableAt + 1);

        // Try to withdraw - should revert
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.PrematureWithdrawal.selector, testTokenId));
        logic.processForcedWithdrawal(testTokenId, recipient, 100);
        vm.stopPrank();
    }

    function test_enableForcedWithdrawal_noTokenBalance() public {
        // Create a new address with no tokens
        address noTokenUser = makeAddr("noTokenUser");

        // Should be able to enable forced withdrawal even with no tokens
        vm.prank(noTokenUser);
        uint256 withdrawableAt = logic.enableForcedWithdrawal(testTokenId);

        assertEq(withdrawableAt, block.timestamp + 1 days, "Withdrawable timestamp should be set correctly");

        // Check status
        vm.prank(noTokenUser);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = logic.getForcedWithdrawalStatus(noTokenUser, testTokenId);

        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Pending), "Status should be pending");
        assertEq(enabledAt, withdrawableAt, "EnabledAt should match withdrawableAt");
    }
}
