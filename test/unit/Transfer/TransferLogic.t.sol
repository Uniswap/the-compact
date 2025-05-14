// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { Scope } from "src/types/Scope.sol";
import { AllocatedTransfer } from "src/types/Claims.sol";
import { AllocatedBatchTransfer } from "src/types/BatchClaims.sol";
import { Component, ComponentsById } from "src/types/Components.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import { AlwaysOKAllocator } from "src/test/AlwaysOKAllocator.sol";

import { MockERC20 } from "lib/solady/test/utils/mocks/MockERC20.sol";
import { ERC6909 } from "lib/solady/src/tokens/ERC6909.sol";

import "src/lib/IdLib.sol";
import "./MockTransferLogic.sol";

contract TransferLogicTest is Test {
    using IdLib for address;
    using IdLib for uint96;
    using IdLib for uint256;

    MockTransferLogic logic;
    AlwaysOKAllocator allocator;

    MockERC20 testToken = new MockERC20("Test Token", "TEST", 18);

    address sponsor;
    address recipient;
    uint256 testTokenId;
    uint96 allocatorId;
    bytes12 lockTag;

    function setUp() public {
        logic = new MockTransferLogic();

        sponsor = makeAddr("sponsor");
        recipient = makeAddr("recipient");
        allocator = new AlwaysOKAllocator();

        (allocatorId, lockTag) = _registerAllocator(address(allocator));

        testTokenId = logic.toIdIfRegistered(address(testToken), lockTag);
        testToken.mint(sponsor, 1000);

        _makeDeposit(sponsor, address(testToken), 1000, lockTag);

        vm.warp(1743479729);
    }

    function test_processSplitTransfer() public {
        Component[] memory recipients = new Component[](2);
        recipients[0] = Component({ claimant: _makeClaimant(recipient), amount: 300 });
        recipients[1] = Component({ claimant: _makeClaimant(sponsor), amount: 200 });

        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            id: testTokenId,
            recipients: recipients,
            allocatorData: bytes("")
        });

        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, recipient, testTokenId, 300);
        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, sponsor, testTokenId, 200);

        // Process the transfer
        vm.prank(sponsor);
        assertTrue(logic.processTransfer(transfer), "Transfer should be successful");
    }

    function test_processBatchTransfer() public {
        MockERC20 secondToken = new MockERC20("Second Token", "SECOND", 18);
        secondToken.mint(sponsor, 500);
        _makeDeposit(sponsor, address(secondToken), 500, lockTag);
        uint256 secondTokenId = logic.toIdIfRegistered(address(secondToken), lockTag);

        // Create components for first token
        Component[] memory portions1 = new Component[](1);
        portions1[0] = Component({ claimant: _makeClaimant(recipient), amount: 200 });

        // Create components for second token
        Component[] memory portions2 = new Component[](2);
        portions2[0] = Component({ claimant: _makeClaimant(makeAddr("recipient2")), amount: 150 });
        portions2[1] = Component({ claimant: _makeClaimant(makeAddr("recipient3")), amount: 100 });

        // Create ComponentsById array for batch transfer
        ComponentsById[] memory transfers = new ComponentsById[](2);
        transfers[0] = ComponentsById({ id: testTokenId, portions: portions1 });
        transfers[1] = ComponentsById({ id: secondTokenId, portions: portions2 });

        // Create AllocatedBatchTransfer struct
        AllocatedBatchTransfer memory batchTransfer = AllocatedBatchTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            transfers: transfers,
            allocatorData: bytes("")
        });

        // Should emit 3 transfers
        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, recipient, testTokenId, 200);
        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, makeAddr("recipient2"), secondTokenId, 150);
        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, makeAddr("recipient3"), secondTokenId, 100);

        // Process the batch transfer
        vm.prank(sponsor);
        assertTrue(logic.processBatchTransfer(batchTransfer), "Batch transfer should be successful");
    }

    function test_processSplitTransfer_expired() public {
        // Create components array
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({ claimant: _makeClaimant(recipient), amount: 100 });

        // Create AllocatedTransfer struct with expired timestamp
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 1,
            expires: block.timestamp - 1, // Expired
            id: testTokenId,
            recipients: recipients,
            allocatorData: bytes("")
        });

        // Process the transfer - should revert with ExpiredCompact
        vm.prank(sponsor);
        vm.expectRevert();
        logic.processTransfer(transfer);
    }

    function test_processTransfer_insufficientBalance() public {
        // Create components array requesting more than available
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({ claimant: _makeClaimant(recipient), amount: 1001 }); // More than the 1000 available

        // Create AllocatedTransfer struct
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            id: testTokenId,
            recipients: recipients,
            allocatorData: bytes("")
        });

        // Process the transfer - should revert with arithmetic error
        vm.prank(sponsor);
        vm.expectRevert();
        logic.processTransfer(transfer);
    }

    function test_processTransfer_zeroAmount() public {
        // Create components array with zero amount
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({ claimant: _makeClaimant(recipient), amount: 0 });

        // Create AllocatedTransfer struct
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            id: testTokenId,
            recipients: recipients,
            allocatorData: bytes("")
        });

        // Reverts because zero amount is disallowed
        vm.expectRevert(abi.encodePacked(bytes4(keccak256("InsufficientBalance()"))));
        vm.prank(sponsor);
        logic.processTransfer(transfer);
    }

    function test_processTransfer_zeroRecipients() public {
        // Create empty components array
        Component[] memory recipients = new Component[](0);

        // Create AllocatedTransfer struct
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            id: testTokenId,
            recipients: recipients,
            allocatorData: bytes("")
        });

        // Process the transfer
        vm.prank(sponsor);
        bool success = logic.processTransfer(transfer);

        // Verify the transfer was "successful" but no tokens moved
        assertTrue(success, "Transfer should be 'successful'");
        assertEq(testToken.balanceOf(sponsor), 0, "Sponsor should not have received any tokens");
    }

    function test_processSplitTransfer_sameRecipientMultipleTimes() public {
        // Create components array with same recipient multiple times
        Component[] memory recipients = new Component[](3);
        recipients[0] = Component({ claimant: _makeClaimant(recipient), amount: 100 });
        recipients[1] = Component({ claimant: _makeClaimant(recipient), amount: 200 }); // Same recipient
        recipients[2] = Component({ claimant: _makeClaimant(recipient), amount: 300 }); // Same recipient again

        // Create AllocatedTransfer struct
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            id: testTokenId,
            recipients: recipients,
            allocatorData: bytes("")
        });

        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, recipient, testTokenId, 100);
        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, recipient, testTokenId, 200);
        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, recipient, testTokenId, 300);

        vm.prank(sponsor);
        assertTrue(logic.processTransfer(transfer), "Transfer should be successful");
    }

    function test_processSplitTransfer_maxRecipients() public {
        // Create components array with a large number of recipients (100)
        Component[] memory recipients = new Component[](100);
        for (uint256 i = 0; i < 100; i++) {
            recipients[i] = Component({
                claimant: _makeClaimant(makeAddr(string(abi.encodePacked("recipient", vm.toString(i))))),
                amount: 10 // 10 tokens each, total 1000
             });
            vm.expectEmit(true, true, true, true);
            emit ERC6909.Transfer(sponsor, sponsor, recipients[i].claimant.toAddress(), testTokenId, 10);
        }

        // Create AllocatedTransfer struct
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            id: testTokenId,
            recipients: recipients,
            allocatorData: bytes("")
        });

        // Process the transfer
        vm.prank(sponsor);
        assertTrue(logic.processTransfer(transfer), "Transfer should be successful");
    }

    function test_processSplitBatchTransfer_emptyTransfers() public {
        // Create empty ComponentsById array
        ComponentsById[] memory transfers = new ComponentsById[](0);

        // Create AllocatedBatchTransfer struct
        AllocatedBatchTransfer memory batchTransfer = AllocatedBatchTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            transfers: transfers,
            allocatorData: bytes("")
        });

        // Process the batch transfer - should revert because of empty array check
        vm.prank(sponsor);
        vm.expectRevert();
        logic.processBatchTransfer(batchTransfer);
    }

    function test_processSplitBatchTransfer_mixedResults() public {
        MockERC20 secondToken = new MockERC20("Second Token", "SECOND", 18);
        secondToken.mint(sponsor, 500);
        _makeDeposit(sponsor, address(secondToken), 500, lockTag);
        uint256 secondTokenId = logic.toIdIfRegistered(address(secondToken), lockTag);

        // Create components with mixed scenarios:
        // - First transfer: normal transfer (acceptable)
        // - Second transfer: same recipient multiple times (acceptable)
        // - Third transfer: zero amount (disallowed)

        // First transfer components
        Component[] memory portions1 = new Component[](1);
        portions1[0] = Component({ claimant: _makeClaimant(recipient), amount: 200 });

        // Second transfer components (same recipient multiple times)
        address duplicateRecipient = makeAddr("duplicateRecipient");
        Component[] memory portions2 = new Component[](2);
        portions2[0] = Component({ claimant: _makeClaimant(duplicateRecipient), amount: 100 });
        portions2[1] = Component({ claimant: _makeClaimant(duplicateRecipient), amount: 150 });

        // Third transfer components (zero amount)
        Component[] memory portions3 = new Component[](1);
        portions3[0] = Component({ claimant: _makeClaimant(makeAddr("recipient2")), amount: 0 });

        // Create ComponentsById array
        ComponentsById[] memory transfers = new ComponentsById[](3);
        transfers[0] = ComponentsById({ id: testTokenId, portions: portions1 });
        transfers[1] = ComponentsById({ id: secondTokenId, portions: portions2 });
        transfers[2] = ComponentsById({ id: secondTokenId, portions: portions3 });

        // Create AllocatedBatchTransfer struct
        AllocatedBatchTransfer memory batchTransfer = AllocatedBatchTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            transfers: transfers,
            allocatorData: bytes("")
        });

        // Should emit 3 transfers (which are later reverted)
        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, recipient, testTokenId, 200);
        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, duplicateRecipient, secondTokenId, 100);
        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(sponsor, sponsor, duplicateRecipient, secondTokenId, 150);

        // Reverts because of the zero amount transfer
        vm.expectRevert(abi.encodePacked(bytes4(keccak256("InsufficientBalance()"))));

        vm.prank(sponsor);
        logic.processBatchTransfer(batchTransfer);
    }

    function test_inconsistentAllocatorsInBatchTransfer() public {
        // Create a second allocator
        AlwaysOKAllocator secondAllocator = new AlwaysOKAllocator();
        (, bytes12 secondLockTag) = _registerAllocator(address(secondAllocator));

        // Create tokens with different allocators
        MockERC20 firstToken = new MockERC20("First Token", "FIRST", 18);
        firstToken.mint(sponsor, 500);
        MockERC20 secondToken = new MockERC20("Second Token", "SECOND", 18);
        secondToken.mint(sponsor, 500);

        // Deposit with different allocators
        _makeDeposit(sponsor, address(firstToken), 500, lockTag); // First allocator
        _makeDeposit(sponsor, address(secondToken), 500, secondLockTag); // Second allocator

        uint256 firstTokenId = logic.toIdIfRegistered(address(firstToken), lockTag);
        uint256 secondTokenId = logic.toIdIfRegistered(address(secondToken), secondLockTag);

        // Create batch transfer with inconsistent allocators
        ComponentsById[] memory transfers = new ComponentsById[](2);

        Component[] memory portions1 = new Component[](1);
        portions1[0] = Component({ claimant: _makeClaimant(recipient), amount: 200 });
        transfers[0] = ComponentsById({ id: firstTokenId, portions: portions1 });

        Component[] memory portions2 = new Component[](1);
        portions2[0] = Component({ claimant: _makeClaimant(makeAddr("recipient2")), amount: 150 });
        transfers[1] = ComponentsById({ id: secondTokenId, portions: portions2 });

        AllocatedBatchTransfer memory batchTransfer = AllocatedBatchTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            transfers: transfers,
            allocatorData: bytes("")
        });

        // Should revert with inconsistent allocators
        vm.expectRevert();
        vm.prank(sponsor);
        logic.processBatchTransfer(batchTransfer);
    }

    function test_integerOverflowInAggregate() public {
        // Create components array with amounts that would overflow when summed
        Component[] memory recipients = new Component[](2);
        recipients[0] = Component({ claimant: _makeClaimant(recipient), amount: type(uint256).max });
        recipients[1] = Component({ claimant: _makeClaimant(makeAddr("recipient2")), amount: 1 });

        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            id: testTokenId,
            recipients: recipients,
            allocatorData: bytes("")
        });

        // Should revert with arithmetic overflow
        vm.expectRevert();
        vm.prank(sponsor);
        logic.processTransfer(transfer);
    }

    function test_unusualTokenIdBitPatterns() public {
        // Create a token ID with unusual bit patterns
        uint256 unusualTokenId = testTokenId | (1 << 159); // Set a bit right at the boundary

        // Create components array
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({ claimant: _makeClaimant(recipient), amount: 100 });

        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 1,
            expires: block.timestamp + 1 days,
            id: unusualTokenId,
            recipients: recipients,
            allocatorData: bytes("")
        });

        // Should either handle correctly or revert with a specific error
        vm.prank(sponsor);
        vm.expectRevert(); // Expect revert due to invalid token ID
        logic.processTransfer(transfer);
    }

    function _makeClaimant(address _recipient) internal view returns (uint256) {
        return abi.decode(abi.encodePacked(bytes12(bytes32(lockTag)), _recipient), (uint256));
    }

    function _registerAllocator(address _allocator) internal returns (uint96 id, bytes12 tag) {
        return logic.registerAllocator(_allocator);
    }

    function _makeDeposit(address guy, address asset, uint256 amount, bytes12 tag) internal returns (uint256 id) {
        vm.startPrank(guy);
        MockERC20(asset).approve(address(logic), amount);
        id = logic.depositERC20(asset, tag, amount, guy);
        vm.stopPrank();
    }
}
