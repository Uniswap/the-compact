// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";

import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { Component, ComponentsById } from "../../src/types/Components.sol";
import { AllocatedTransfer } from "../../src/types/Claims.sol";
import { AllocatedBatchTransfer } from "../../src/types/BatchClaims.sol";
import { IdLib } from "../../src/lib/IdLib.sol";

import { QualifiedAllocator } from "../../src/examples/allocator/QualifiedAllocator.sol";
import { AlwaysRevertingAllocator } from "../../src/test/AlwaysRevertingAllocator.sol";
import { AlwaysDenyingAllocator } from "../../src/test/AlwaysDenyingAllocator.sol";

import { Setup } from "./Setup.sol";

import { TestParams } from "./TestHelperStructs.sol";

contract AllocatedTransferTest is Setup {
    function test_transferSucceeds() public {
        // Setup test parameters
        uint256 amount = 1e18;

        // Recipient information
        address recipient = 0x1111111111111111111111111111111111111111;

        // Register allocator and create lock tag
        uint256 id;
        {
            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(alwaysOKAllocator);

            // Make deposit
            id = _makeDeposit(swapper, address(token), amount, lockTag);
        }

        {
            assertEq(theCompact.balanceOf(swapper, id), amount);
            assertEq(theCompact.balanceOf(recipient, id), 0);
        }

        vm.prank(swapper);
        theCompact.transfer(recipient, id, amount);

        {
            assertEq(theCompact.balanceOf(swapper, id), 0);
            assertEq(theCompact.balanceOf(recipient, id), amount);
        }
    }

    function test_revert_allocatorReverts() public {
        // Setup test parameters
        uint256 amount = 1e18;

        // Recipient information
        address recipient = 0x1111111111111111111111111111111111111111;

        // Register allocator and create lock tag
        uint256 id;
        address alwaysRevertingAllocator;
        {
            alwaysRevertingAllocator = address(new AlwaysRevertingAllocator());

            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(alwaysRevertingAllocator);

            // Make deposit
            id = _makeDeposit(swapper, address(token), amount, lockTag);
        }

        {
            assertEq(theCompact.balanceOf(swapper, id), amount);
            assertEq(theCompact.balanceOf(recipient, id), 0);
        }

        vm.prank(swapper);
        vm.expectRevert(
            abi.encodeWithSelector(AlwaysRevertingAllocator.AlwaysReverting.selector), alwaysRevertingAllocator
        );
        theCompact.transfer(recipient, id, amount);

        {
            assertEq(theCompact.balanceOf(swapper, id), amount);
            assertEq(theCompact.balanceOf(recipient, id), 0);
        }
    }

    function test_revert_allocatorDenies() public {
        // Setup test parameters
        uint256 amount = 1e18;

        // Recipient information
        address recipient = 0x1111111111111111111111111111111111111111;

        // Register allocator and create lock tag
        uint256 id;
        address alwaysDenyingAllocator;
        {
            alwaysDenyingAllocator = address(new AlwaysDenyingAllocator());

            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(alwaysDenyingAllocator);

            // Make deposit
            id = _makeDeposit(swapper, address(token), amount, lockTag);
        }

        {
            assertEq(theCompact.balanceOf(swapper, id), amount);
            assertEq(theCompact.balanceOf(recipient, id), 0);
        }

        vm.prank(swapper);
        vm.expectRevert(
            abi.encodeWithSelector(ITheCompact.UnallocatedTransfer.selector, swapper, swapper, recipient, id, amount),
            address(theCompact)
        );
        theCompact.transfer(recipient, id, amount);

        {
            assertEq(theCompact.balanceOf(swapper, id), amount);
            assertEq(theCompact.balanceOf(recipient, id), 0);
        }
    }
}
