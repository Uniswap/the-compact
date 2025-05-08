// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";
import { ForcedWithdrawalStatus } from "../../src/types/ForcedWithdrawalStatus.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";

import { Setup } from "./Setup.sol";

contract ForcedWithdrawalTest is Setup {
    function setUp() public override {
        super.setUp();
    }

    function test_enableForcedWithdrawal() public {
        // Setup: register allocator and make a deposit
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        // Test: enable forced withdrawal
        vm.prank(swapper);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);
        vm.snapshotGasLastCall("enableForcedWithdrawal");

        // Verify: withdrawable timestamp is correct (current time + reset period)
        assertEq(withdrawableAt, block.timestamp + 1 days, "Withdrawable timestamp should be 1 day from now");

        // Verify: withdrawal status is pending
        vm.prank(swapper);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = theCompact.getForcedWithdrawalStatus(swapper, id);
        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Pending), "Status should be pending");
        assertEq(enabledAt, withdrawableAt, "EnabledAt should match withdrawableAt");
    }

    function test_disableForcedWithdrawal() public {
        // Setup: register allocator, make a deposit, and enable forced withdrawal
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        vm.prank(swapper);
        theCompact.enableForcedWithdrawal(id);

        // Test: disable forced withdrawal
        vm.prank(swapper);
        bool success = theCompact.disableForcedWithdrawal(id);
        vm.snapshotGasLastCall("disableForcedWithdrawal");

        // Verify: operation was successful
        assertTrue(success, "Disabling forced withdrawal should succeed");

        // Verify: withdrawal status is disabled
        vm.prank(swapper);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = theCompact.getForcedWithdrawalStatus(swapper, id);
        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Disabled), "Status should be disabled");
        assertEq(enabledAt, 0, "EnabledAt should be 0");
    }

    function test_disableForcedWithdrawal_alreadyDisabled() public {
        // Setup: register allocator and make a deposit
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        // Test: try to disable a withdrawal that's already disabled
        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.ForcedWithdrawalAlreadyDisabled.selector, swapper, id));
        theCompact.disableForcedWithdrawal(id);
    }

    function test_processForcedWithdrawal() public {
        // Setup: register allocator, make a deposit, and enable forced withdrawal
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;
        address recipient = address(0x1111111111111111111111111111111111111111);

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        vm.prank(swapper);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Try to withdraw before time has elapsed
        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.PrematureWithdrawal.selector, id));
        theCompact.forcedWithdrawal(id, recipient, amount / 2);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        // Test: process forced withdrawal
        uint256 withdrawAmount = amount / 2;
        vm.prank(swapper);
        bool success = theCompact.forcedWithdrawal(id, recipient, withdrawAmount);
        vm.snapshotGasLastCall("processForcedWithdrawal");

        // Verify: operation was successful
        assertTrue(success, "Processing forced withdrawal should succeed");

        // Verify: balances are updated correctly
        assertEq(theCompact.balanceOf(swapper, id), amount - withdrawAmount, "Swapper should have remaining tokens");
        assertEq(recipient.balance, withdrawAmount, "Recipient should have received tokens");
    }

    function test_processForcedWithdrawal_fullBalance() public {
        // Setup: register allocator, make a deposit, and enable forced withdrawal
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;
        address recipient = address(0x1111111111111111111111111111111111111111);

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        vm.prank(swapper);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        // Test: process forced withdrawal for full balance
        vm.prank(swapper);
        bool success = theCompact.forcedWithdrawal(id, recipient, amount);
        vm.snapshotGasLastCall("processForcedWithdrawal_fullBalance");

        // Verify: operation was successful
        assertTrue(success, "Processing forced withdrawal should succeed");

        // Verify: balances are updated correctly
        assertEq(theCompact.balanceOf(swapper, id), 0, "Swapper should have no tokens left");
        assertEq(recipient.balance, amount, "Recipient should have received all tokens");
    }

    function test_getForcedWithdrawalStatus_disabled() public {
        // Setup: register allocator and make a deposit
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        // Test: get forced withdrawal status when disabled
        vm.prank(swapper);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = theCompact.getForcedWithdrawalStatus(swapper, id);
        vm.snapshotGasLastCall("getForcedWithdrawalStatus_disabled");

        // Verify: status is disabled
        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Disabled), "Status should be disabled");
        assertEq(enabledAt, 0, "EnabledAt should be 0");
    }

    function test_getForcedWithdrawalStatus_pending() public {
        // Setup: register allocator, make a deposit, and enable forced withdrawal
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        vm.prank(swapper);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Test: get forced withdrawal status when pending
        vm.prank(swapper);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = theCompact.getForcedWithdrawalStatus(swapper, id);
        vm.snapshotGasLastCall("getForcedWithdrawalStatus_pending");

        // Verify: status is pending
        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Pending), "Status should be pending");
        assertEq(enabledAt, withdrawableAt, "EnabledAt should match withdrawableAt");
    }

    function test_getForcedWithdrawalStatus_enabled() public {
        // Setup: register allocator, make a deposit, and enable forced withdrawal
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        vm.prank(swapper);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        // Test: get forced withdrawal status when enabled
        vm.prank(swapper);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = theCompact.getForcedWithdrawalStatus(swapper, id);
        vm.snapshotGasLastCall("getForcedWithdrawalStatus_enabled");

        // Verify: status is enabled
        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Enabled), "Status should be enabled");
        assertEq(enabledAt, withdrawableAt, "EnabledAt should match withdrawableAt");
    }

    function test_enableForcedWithdrawal_differentResetPeriods() public {
        // Setup: register allocator
        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        // Create token IDs with different reset periods
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
        uint256 amount = 1e18;

        // Make deposits and enable forced withdrawals for each reset period
        for (uint256 i = 0; i < resetPeriods.length; i++) {
            bytes12 lockTag = bytes12(
                bytes32((uint256(scope) << 255) | (uint256(resetPeriods[i]) << 252) | (uint256(allocatorId) << 160))
            );

            // Deal more ETH to swapper for each deposit
            vm.deal(swapper, 1e18);

            vm.prank(swapper);
            uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

            vm.prank(swapper);
            uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

            // Verify: withdrawable timestamp is correct
            assertEq(
                withdrawableAt,
                block.timestamp + expectedDurations[i],
                "Withdrawable timestamp should match expected duration"
            );
        }
    }

    function test_enableForcedWithdrawal_whenAlreadyEnabled() public {
        // Setup: register allocator, make a deposit, and enable forced withdrawal
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        vm.prank(swapper);
        uint256 firstWithdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Warp time forward a bit
        vm.warp(block.timestamp + 12 hours);

        // Test: re-enable the forced withdrawal
        vm.prank(swapper);
        uint256 secondWithdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Verify: new withdrawable timestamp is updated
        assertNotEq(firstWithdrawableAt, secondWithdrawableAt, "New withdrawable timestamp should be different");
        assertEq(secondWithdrawableAt, block.timestamp + 1 days, "New timestamp should be 1 day from current time");
    }

    function test_processForcedWithdrawal_exactTimestamp() public {
        // Setup: register allocator, make a deposit, and enable forced withdrawal
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;
        address recipient = address(0x1111111111111111111111111111111111111111);

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        vm.prank(swapper);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Warp to exactly when it becomes withdrawable
        vm.warp(withdrawableAt);

        // Test: process forced withdrawal at exact timestamp
        uint256 withdrawAmount = amount / 2;
        vm.prank(swapper);
        bool success = theCompact.forcedWithdrawal(id, recipient, withdrawAmount);

        // Verify: operation was successful
        assertTrue(success, "Processing forced withdrawal should succeed");

        // Verify: balances are updated correctly
        assertEq(theCompact.balanceOf(swapper, id), amount - withdrawAmount, "Swapper should have remaining tokens");
        assertEq(recipient.balance, withdrawAmount, "Recipient should have received tokens");
    }

    function test_processForcedWithdrawal_zeroAmount() public {
        // Setup: register allocator, make a deposit, and enable forced withdrawal
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;
        address recipient = address(0x1111111111111111111111111111111111111111);

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        vm.prank(swapper);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        // Test: process forced withdrawal with zero amount
        vm.prank(swapper);
        bool success = theCompact.forcedWithdrawal(id, recipient, 0);

        // Verify: operation was successful
        assertTrue(success, "Processing forced withdrawal should succeed");

        // Verify: balances are unchanged
        assertEq(theCompact.balanceOf(swapper, id), amount, "Swapper should still have all tokens");
        assertEq(recipient.balance, 0, "Recipient should not have received any tokens");
    }

    function test_disableForcedWithdrawal_justBeforeEnabling() public {
        // Setup: register allocator, make a deposit, and enable forced withdrawal
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;
        address recipient = address(0x1111111111111111111111111111111111111111);

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        vm.prank(swapper);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Warp to just before it becomes withdrawable
        vm.warp(withdrawableAt - 1);

        // Test: disable forced withdrawal just before it becomes enabled
        vm.prank(swapper);
        bool success = theCompact.disableForcedWithdrawal(id);

        // Verify: operation was successful
        assertTrue(success, "Disabling forced withdrawal should succeed");

        // Warp to after when it would have been enabled
        vm.warp(withdrawableAt + 1);

        // Try to withdraw - should revert
        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.PrematureWithdrawal.selector, id));
        theCompact.forcedWithdrawal(id, recipient, amount / 2);
    }

    function test_enableForcedWithdrawal_noTokenBalance() public {
        // Setup: register allocator and make a deposit
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, swapper);

        // Create a new address with no tokens
        address noTokenUser = makeAddr("noTokenUser");

        // Test: enable forced withdrawal with no token balance
        vm.prank(noTokenUser);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Verify: withdrawable timestamp is set correctly
        assertEq(withdrawableAt, block.timestamp + 1 days, "Withdrawable timestamp should be set correctly");

        // Verify: status is pending
        vm.prank(noTokenUser);
        (ForcedWithdrawalStatus status, uint256 enabledAt) = theCompact.getForcedWithdrawalStatus(noTokenUser, id);
        assertEq(uint256(status), uint256(ForcedWithdrawalStatus.Pending), "Status should be pending");
        assertEq(enabledAt, withdrawableAt, "EnabledAt should match withdrawableAt");
    }

    function test_processForcedWithdrawal_erc20Token() public {
        // Setup: register allocator and make a deposit with ERC20 token
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;
        address recipient = address(0x1111111111111111111111111111111111111111);

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositERC20(address(token), lockTag, amount, swapper);

        vm.prank(swapper);
        uint256 withdrawableAt = theCompact.enableForcedWithdrawal(id);

        // Warp to after the withdrawal is enabled
        vm.warp(withdrawableAt + 1);

        // Test: process forced withdrawal for ERC20 token
        uint256 withdrawAmount = amount / 2;
        vm.prank(swapper);
        bool success = theCompact.forcedWithdrawal(id, recipient, withdrawAmount);
        vm.snapshotGasLastCall("processForcedWithdrawal_erc20Token");

        // Verify: operation was successful
        assertTrue(success, "Processing forced withdrawal should succeed");

        // Verify: balances are updated correctly
        assertEq(theCompact.balanceOf(swapper, id), amount - withdrawAmount, "Swapper should have remaining tokens");
        assertEq(token.balanceOf(recipient), withdrawAmount, "Recipient should have received tokens");
    }
}
