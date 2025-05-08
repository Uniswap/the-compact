// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";

import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { Component, BatchClaimComponent } from "../../src/types/Components.sol";
import { Claim } from "../../src/types/Claims.sol";
import { BatchClaim } from "../../src/types/BatchClaims.sol";

import { Setup } from "./Setup.sol";

import {
    TestParams, CreateClaimHashWithWitnessArgs, CreateBatchClaimHashWithWitnessArgs
} from "./TestHelperStructs.sol";

import { EfficiencyLib } from "../../src/lib/EfficiencyLib.sol";

contract DepositAndRegisterTest is Setup {
    using EfficiencyLib for bytes12;
    using EfficiencyLib for address;

    function test_depositNativeAndRegisterAndClaim() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;
        params.recipient = 0x1111111111111111111111111111111111111111;

        // Additional parameters
        address arbiter = 0x2222222222222222222222222222222222222222;

        // Register allocator and setup tokens
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            vm.deal(swapper, params.amount);
        }

        uint256 witnessArgument = 234;
        bytes32 witness = keccak256(abi.encode(witnessArgument));

        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.id = lockTag.asUint256();
            args.amount = params.amount;
            args.witness = witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        {
            vm.prank(swapper);
            (params.id) = theCompact.depositNativeAndRegister{ value: params.amount }(
                lockTag, claimHash, compactWithWitnessTypehash
            );
            vm.snapshotGasLastCall("depositNativeAndRegister");

            assertEq(theCompact.balanceOf(swapper, params.id), params.amount);
            assertEq(address(theCompact).balance, params.amount);
            assertEq(params.id, lockTag.asUint256());
        }

        // Verify claim hash was registered
        {
            bool isActive;
            uint256 registeredAt;
            (isActive, registeredAt) = theCompact.getRegistrationStatus(swapper, claimHash, compactWithWitnessTypehash);
            assert(isActive);
            assertEq(registeredAt, block.timestamp);
        }

        // Prepare claim
        Claim memory claim;
        {
            // Create digest and get allocator signature
            bytes memory allocatorSignature;
            {
                bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), theCompact.DOMAIN_SEPARATOR(), claimHash));

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                allocatorSignature = abi.encodePacked(r, vs);
            }

            // Create recipients
            Component[] memory recipients;
            {
                recipients = new Component[](1);

                uint256 claimantId = uint256(bytes32(abi.encodePacked(bytes12(bytes32(params.id)), params.recipient)));

                recipients[0] = Component({ claimant: claimantId, amount: params.amount });
            }

            // Build the claim
            claim = Claim(
                allocatorSignature,
                "", // sponsorSignature
                swapper,
                params.nonce,
                params.deadline,
                witness,
                witnessTypestring,
                params.id,
                params.amount,
                recipients
            );
        }

        // Execute claim
        {
            vm.prank(arbiter);
            bytes32 returnedClaimHash = theCompact.claim(claim);
            assertEq(returnedClaimHash, claimHash);
        }

        // Verify balances
        assertEq(address(theCompact).balance, params.amount);
        assertEq(theCompact.balanceOf(swapper, params.id), 0);
        assertEq(theCompact.balanceOf(params.recipient, params.id), params.amount);
    }

    function test_depositERC20AndRegisterAndClaim() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;
        params.recipient = 0x1111111111111111111111111111111111111111;

        // Additional parameters
        address arbiter = 0x2222222222222222222222222222222222222222;

        // Register allocator and setup tokens
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            vm.prank(swapper);
            token.approve(address(theCompact), params.amount);
        }

        uint256 witnessArgument = 234;
        bytes32 witness = keccak256(abi.encode(witnessArgument));

        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.id = lockTag.asUint256() | address(token).asUint256();
            args.amount = params.amount;
            args.witness = witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        {
            vm.prank(swapper);
            (params.id) = theCompact.depositERC20AndRegister(
                address(token), lockTag, params.amount, claimHash, compactWithWitnessTypehash
            );
            vm.snapshotGasLastCall("depositERC20AndRegister");

            assertEq(theCompact.balanceOf(swapper, params.id), params.amount);
            assertEq(token.balanceOf(address(theCompact)), params.amount);
            assertEq(params.id, lockTag.asUint256() | address(token).asUint256());
        }

        // Verify claim hash was registered
        {
            bool isActive;
            uint256 registeredAt;
            (isActive, registeredAt) = theCompact.getRegistrationStatus(swapper, claimHash, compactWithWitnessTypehash);
            assert(isActive);
            assertEq(registeredAt, block.timestamp);
        }

        // Prepare claim
        Claim memory claim;
        {
            // Create digest and get allocator signature
            bytes memory allocatorSignature;
            {
                bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), theCompact.DOMAIN_SEPARATOR(), claimHash));

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                allocatorSignature = abi.encodePacked(r, vs);
            }

            // Create recipients
            Component[] memory recipients;
            {
                recipients = new Component[](1);

                uint256 claimantId = uint256(bytes32(abi.encodePacked(bytes12(bytes32(params.id)), params.recipient)));

                recipients[0] = Component({ claimant: claimantId, amount: params.amount });
            }

            // Build the claim
            claim = Claim(
                allocatorSignature,
                "", // sponsorSignature
                swapper,
                params.nonce,
                params.deadline,
                witness,
                witnessTypestring,
                params.id,
                params.amount,
                recipients
            );
        }

        // Execute claim
        {
            vm.prank(arbiter);
            bytes32 returnedClaimHash = theCompact.claim(claim);
            assertEq(returnedClaimHash, claimHash);
        }

        // Verify balances
        assertEq(token.balanceOf(address(theCompact)), params.amount);
        assertEq(theCompact.balanceOf(swapper, params.id), 0);
        assertEq(theCompact.balanceOf(params.recipient, params.id), params.amount);
    }

    function test_batchDepositAndRegisterMultipleAndClaim_lengthOne() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;
        params.recipient = 0x1111111111111111111111111111111111111111;

        // Additional parameters
        address arbiter = 0x2222222222222222222222222222222222222222;

        // Register allocator and setup tokens
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            params.id = address(0).asUint256() | lockTag.asUint256();

            vm.deal(swapper, params.amount);
        }

        // Create witness and deposit/register
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        bytes32 witness;
        {
            uint256 witnessArgument = 234;
            witness = keccak256(abi.encode(witnessTypehash, witnessArgument));

            idsAndAmounts[0][0] = params.id;
            idsAndAmounts[0][1] = params.amount;
        }

        // Get claim hash and typehash
        bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](1);
        {
            CreateBatchClaimHashWithWitnessArgs memory args;
            args.typehash = batchCompactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.idsAndAmountsHash = keccak256(abi.encodePacked(idsAndAmounts));
            args.witness = witness;

            claimHashesAndTypehashes[0][0] = _createBatchClaimHashWithWitness(args);
            claimHashesAndTypehashes[0][1] = batchCompactWithWitnessTypehash;
        }

        {
            vm.prank(swapper);
            (bool status) = theCompact.batchDepositAndRegisterMultiple{ value: params.amount }(
                idsAndAmounts, claimHashesAndTypehashes
            );
            vm.snapshotGasLastCall("batchDepositAndRegisterMultiple");

            assertEq(theCompact.balanceOf(swapper, params.id), params.amount);
            assertEq(address(theCompact).balance, params.amount);
            assert(status);
        }

        // Verify claim hash was registered
        {
            bool isActive;
            uint256 registeredAt;
            (isActive, registeredAt) = theCompact.getRegistrationStatus(
                swapper, claimHashesAndTypehashes[0][0], claimHashesAndTypehashes[0][1]
            );
            assert(isActive);
            assertEq(registeredAt, block.timestamp);
        }

        // Prepare claim
        BatchClaim memory claim;
        {
            // Create digest and get allocator signature
            bytes memory allocatorSignature;
            {
                bytes32 digest = keccak256(
                    abi.encodePacked(bytes2(0x1901), theCompact.DOMAIN_SEPARATOR(), claimHashesAndTypehashes[0][0])
                );

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                allocatorSignature = abi.encodePacked(r, vs);
            }

            // Create recipients
            Component[] memory recipients;
            {
                recipients = new Component[](1);

                uint256 claimantId = uint256(bytes32(abi.encodePacked(bytes12(bytes32(params.id)), params.recipient)));

                recipients[0] = Component({ claimant: claimantId, amount: params.amount });
            }

            BatchClaimComponent[] memory components = new BatchClaimComponent[](1);
            components[0].id = params.id;
            components[0].allocatedAmount = params.amount;
            components[0].portions = recipients;

            // Build the claim
            claim = BatchClaim(
                allocatorSignature,
                "", // sponsorSignature
                swapper,
                params.nonce,
                params.deadline,
                witness,
                witnessTypestring,
                components
            );
        }

        // Execute claim
        {
            vm.prank(arbiter);
            bytes32 returnedClaimHash = theCompact.batchClaim(claim);
            assertEq(returnedClaimHash, claimHashesAndTypehashes[0][0]);
        }

        // Verify balances
        assertEq(address(theCompact).balance, params.amount);
        assertEq(theCompact.balanceOf(swapper, params.id), 0);
        assertEq(theCompact.balanceOf(params.recipient, params.id), params.amount);
    }
}
