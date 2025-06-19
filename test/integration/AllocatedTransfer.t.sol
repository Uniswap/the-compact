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
    function test_allocatedTransfer() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x2222222222222222222222222222222222222222;
        uint256 amountOne = 4e17;
        uint256 amountTwo = 6e17;

        // Register allocator and create lock tag
        uint256 id;
        {
            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            // Make deposit
            id = _makeDeposit(swapper, address(token), params.amount, lockTag);
        }

        // Create digest and allocator signature
        bytes memory allocatorData;
        {
            bytes32 claimHash =
                _createClaimHash(compactTypehash, swapper, swapper, params.nonce, params.deadline, id, params.amount);

            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            bytes32 r;
            bytes32 vs;
            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            allocatorData = abi.encodePacked(r, vs);
        }

        // Prepare recipients
        Component[] memory recipients;
        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(bytes32(id)), recipientOne), (uint256));
            uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(bytes32(id)), recipientTwo), (uint256));

            Component memory componentOne = Component({ claimant: claimantOne, amount: amountOne });
            Component memory componentTwo = Component({ claimant: claimantTwo, amount: amountTwo });

            recipients = new Component[](2);
            recipients[0] = componentOne;
            recipients[1] = componentTwo;
        }

        // Create and execute transfer
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: params.nonce,
            expires: params.deadline,
            allocatorData: allocatorData,
            id: id,
            recipients: recipients
        });

        vm.prank(swapper);
        bool status = theCompact.allocatedTransfer(transfer);
        vm.snapshotGasLastCall("Transfer");
        assert(status);

        // Verify balances
        assertEq(token.balanceOf(address(theCompact)), params.amount);
        assertEq(token.balanceOf(recipientOne), 0);
        assertEq(theCompact.balanceOf(swapper, id), 0);
        assertEq(theCompact.balanceOf(recipientOne, id), amountOne);
        assertEq(theCompact.balanceOf(recipientTwo, id), amountTwo);
    }

    function test_qualified_allocatedTransfer() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;
        params.recipient = 0x1111111111111111111111111111111111111111;

        // Setup qualified allocator
        uint256 id;
        {
            allocator = address(new QualifiedAllocator(vm.addr(allocatorPrivateKey), address(theCompact)));

            // Register allocator and create lock tag
            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            // Make deposit
            id = _makeDeposit(swapper, address(token), params.amount, lockTag);
        }

        // Create qualified digest and allocator signature
        bytes memory allocatorData;
        bytes32 qualificationArgument;
        bytes32 claimHash;
        {
            claimHash =
                _createClaimHash(compactTypehash, swapper, swapper, params.nonce, params.deadline, id, params.amount);

            qualificationArgument = keccak256("qualification");

            {
                bytes32 qualifiedDigest;
                {
                    bytes32 qualifiedHash = keccak256(
                        abi.encode(
                            keccak256("QualifiedClaim(bytes32 claimHash,bytes32 qualificationArg)"),
                            claimHash,
                            qualificationArgument
                        )
                    );

                    qualifiedDigest = _createDigest(theCompact.DOMAIN_SEPARATOR(), qualifiedHash);
                }

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, qualifiedDigest);
                allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Prepare recipients
        Component[] memory recipients;
        {
            uint256 claimant = abi.decode(abi.encodePacked(bytes12(bytes32(id)), params.recipient), (uint256));

            Component memory component = Component({ claimant: claimant, amount: params.amount });

            recipients = new Component[](1);
            recipients[0] = component;
        }

        // Create and execute transfer
        bool status;
        {
            AllocatedTransfer memory transfer = AllocatedTransfer({
                nonce: params.nonce,
                expires: params.deadline,
                allocatorData: abi.encode(allocatorData, qualificationArgument),
                id: id,
                recipients: recipients
            });

            vm.prank(swapper);
            status = theCompact.allocatedTransfer(transfer);
            vm.snapshotGasLastCall("qualified_basicTransfer");
            assert(status);
        }

        // Verify balances
        {
            assertEq(token.balanceOf(address(theCompact)), params.amount);
            assertEq(token.balanceOf(params.recipient), 0);
            assertEq(theCompact.balanceOf(swapper, id), 0);
            assertEq(theCompact.balanceOf(params.recipient, id), params.amount);
        }
    }

    function test_allocatedWithdrawal() public {
        // Setup test parameters
        TestParams memory params;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x2222222222222222222222222222222222222222;
        uint256 amountOne = 4e17;
        uint256 amountTwo = 6e17;

        // Register allocator and create lock tag
        uint256 id;
        {
            (, bytes12 lockTag) = _registerAllocator(allocator);

            // Make deposit
            id = _makeDeposit(swapper, address(token), params.amount, lockTag);
        }

        // Create digest and allocator signature
        bytes memory allocatorData;
        {
            bytes32 digest;
            {
                bytes32 claimHash = _createClaimHash(
                    compactTypehash, swapper, swapper, params.nonce, params.deadline, id, params.amount
                );

                digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
            }

            bytes32 r;
            bytes32 vs;
            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            allocatorData = abi.encodePacked(r, vs);
        }

        // Prepare recipients
        Component[] memory recipients;
        {
            uint256 claimantOne;
            uint256 claimantTwo;
            {
                claimantOne = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));
                claimantTwo = abi.decode(abi.encodePacked(bytes12(0), recipientTwo), (uint256));
            }

            {
                Component memory componentOne;
                Component memory componentTwo;

                componentOne = Component({ claimant: claimantOne, amount: amountOne });
                componentTwo = Component({ claimant: claimantTwo, amount: amountTwo });

                recipients = new Component[](2);
                recipients[0] = componentOne;
                recipients[1] = componentTwo;
            }
        }

        // Create and execute transfer
        {
            AllocatedTransfer memory transfer;
            {
                transfer = AllocatedTransfer({
                    nonce: params.nonce,
                    expires: params.deadline,
                    allocatorData: allocatorData,
                    id: id,
                    recipients: recipients
                });
            }

            {
                vm.prank(swapper);
                bool status = theCompact.allocatedTransfer(transfer);
                vm.snapshotGasLastCall("allocatedWithdrawal");
                assert(status);
            }
        }

        // Verify balances
        {
            assertEq(token.balanceOf(address(theCompact)), 0);
            assertEq(token.balanceOf(recipientOne), amountOne);
            assertEq(token.balanceOf(recipientTwo), amountTwo);
            assertEq(theCompact.balanceOf(swapper, id), 0);
            assertEq(theCompact.balanceOf(recipientOne, id), 0);
            assertEq(theCompact.balanceOf(recipientTwo, id), 0);
        }
    }

    function test_revert_allocatorNotRegistered() public {
        // Register allocator and create lock tag
        uint96 allocatorId = 0x0123456789ab;
        uint256 id = uint256(allocatorId) << 160 | uint256(uint160(address(token)));

        // Prepare recipients
        Component[] memory recipients = new Component[](0);

        // Create and execute transfer
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: 0,
            expires: block.timestamp + 1000,
            allocatorData: "",
            id: id,
            recipients: recipients
        });

        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(IdLib.NoAllocatorRegistered.selector, allocatorId));
        theCompact.allocatedTransfer(transfer);
    }

    function test_revert_allocatorReverts() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;

        // Register allocator and create lock tag
        uint256 id;
        address alwaysRevertingAllocator;
        {
            alwaysRevertingAllocator = address(new AlwaysRevertingAllocator());

            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(alwaysRevertingAllocator);

            // Make deposit
            id = _makeDeposit(swapper, address(token), params.amount, lockTag);
        }

        // Create digest and allocator signature
        bytes memory allocatorData;
        {
            bytes32 claimHash =
                _createClaimHash(compactTypehash, swapper, swapper, params.nonce, params.deadline, id, params.amount);

            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            bytes32 r;
            bytes32 vs;
            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            allocatorData = abi.encodePacked(r, vs);
        }

        // Prepare recipients
        Component[] memory recipients;
        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(bytes32(id)), recipientOne), (uint256));

            Component memory componentOne = Component({ claimant: claimantOne, amount: params.amount });

            recipients = new Component[](1);
            recipients[0] = componentOne;
        }

        // Create and execute transfer
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: params.nonce,
            expires: params.deadline,
            allocatorData: allocatorData,
            id: id,
            recipients: recipients
        });

        vm.prank(swapper);
        vm.expectRevert(
            abi.encodeWithSelector(AlwaysRevertingAllocator.AlwaysReverting.selector), alwaysRevertingAllocator
        );
        theCompact.allocatedTransfer(transfer);
    }

    function test_revert_allocatorDenies() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;

        // Register allocator and create lock tag
        uint256 id;
        address alwaysDenyingAllocator;
        {
            alwaysDenyingAllocator = address(new AlwaysDenyingAllocator());

            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(alwaysDenyingAllocator);

            // Make deposit
            id = _makeDeposit(swapper, address(token), params.amount, lockTag);
        }

        // Create digest and allocator signature
        bytes memory allocatorData;
        {
            bytes32 claimHash =
                _createClaimHash(compactTypehash, swapper, swapper, params.nonce, params.deadline, id, params.amount);

            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            bytes32 r;
            bytes32 vs;
            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            allocatorData = abi.encodePacked(r, vs);
        }

        // Prepare recipients
        Component[] memory recipients;
        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(bytes32(id)), recipientOne), (uint256));

            Component memory componentOne = Component({ claimant: claimantOne, amount: params.amount });

            recipients = new Component[](1);
            recipients[0] = componentOne;
        }

        // Create and execute transfer
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: params.nonce,
            expires: params.deadline,
            allocatorData: allocatorData,
            id: id,
            recipients: recipients
        });

        vm.prank(swapper);
        vm.expectRevert(
            abi.encodeWithSelector(ITheCompact.InvalidAllocation.selector, alwaysDenyingAllocator), address(theCompact)
        );
        theCompact.allocatedTransfer(transfer);
    }

    function test_revert_tokenTransferOverflows() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;

        // Register allocator and create lock tag
        uint256 id;
        {
            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            // Make deposit
            id = _makeDeposit(swapper, address(token), params.amount, lockTag);
        }

        // Create digest and allocator signature
        bytes memory allocatorData;
        {
            bytes32 claimHash =
                _createClaimHash(compactTypehash, swapper, swapper, params.nonce, params.deadline, id, params.amount);

            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            bytes32 r;
            bytes32 vs;
            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            allocatorData = abi.encodePacked(r, vs);
        }

        // Prepare recipients
        Component[] memory recipients;
        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(bytes32(id)), recipientOne), (uint256));

            Component memory componentOne = Component({ claimant: claimantOne, amount: params.amount });

            recipients = new Component[](1);
            recipients[0] = componentOne;
        }

        // Create and execute transfer
        AllocatedTransfer memory transfer = AllocatedTransfer({
            nonce: params.nonce,
            expires: params.deadline,
            allocatorData: allocatorData,
            id: id,
            recipients: recipients
        });

        bytes8 _ERC6909_MASTER_SLOT_SEED = 0xedcaa89a82293940;
        bytes32 slotRecipient = keccak256(abi.encodePacked(id, recipientOne, bytes4(""), _ERC6909_MASTER_SLOT_SEED));

        vm.assertTrue(params.amount > 0);
        vm.store(address(theCompact), slotRecipient, bytes32(type(uint256).max - params.amount + 1));

        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSignature("BalanceOverflow()"), address(theCompact));
        theCompact.allocatedTransfer(transfer);
    }
}
