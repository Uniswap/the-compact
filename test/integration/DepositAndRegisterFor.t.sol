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

contract DepositAndRegisterForTest is Setup {
    using EfficiencyLib for address;
    using EfficiencyLib for bytes12;

    function test_depositNativeAndRegisterForAndClaim() public {
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
        address swapperSponsor = makeAddr("swapperSponsor");

        // Register allocator and setup tokens
        uint256 id;
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            vm.deal(swapperSponsor, params.amount);
        }

        // Create witness and deposit/register
        bytes32 registeredClaimHash;
        bytes32 witness;
        uint256 witnessArgument = 234;
        {
            witness = keccak256(abi.encode(witnessTypehash, witnessArgument));

            vm.prank(swapperSponsor);
            (id, registeredClaimHash) = theCompact.depositNativeAndRegisterFor{ value: params.amount }(
                address(swapper), lockTag, arbiter, params.nonce, params.deadline, compactWithWitnessTypehash, witness
            );
            vm.snapshotGasLastCall("depositNativeAndRegisterFor");

            assertEq(theCompact.balanceOf(swapper, id), params.amount);
            assertEq(address(theCompact).balance, params.amount);
        }

        // Verify claim hash
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.id = id;
            args.amount = params.amount;
            args.witness = witness;

            claimHash = _createClaimHashWithWitness(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isActive;
                uint256 registeredAt;
                (isActive, registeredAt) =
                    theCompact.getRegistrationStatus(swapper, claimHash, compactWithWitnessTypehash);
                assert(isActive);
                assertEq(registeredAt, block.timestamp);
            }
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

                uint256 claimantId = uint256(bytes32(abi.encodePacked(bytes12(bytes32(id)), params.recipient)));

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
                id,
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
        assertEq(theCompact.balanceOf(swapper, id), 0);
        assertEq(theCompact.balanceOf(params.recipient, id), params.amount);
    }

    function test_depositERC20AndRegisterForAndClaim() public {
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
        address swapperSponsor = makeAddr("swapperSponsor");

        // Register allocator and setup tokens
        uint256 id;
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            vm.prank(swapper);
            token.transfer(swapperSponsor, params.amount);

            vm.prank(swapperSponsor);
            token.approve(address(theCompact), params.amount);
        }

        // Create witness and deposit/register
        bytes32 registeredClaimHash;
        bytes32 witness;
        uint256 witnessArgument = 234;
        {
            witness = keccak256(abi.encode(witnessTypehash, witnessArgument));

            vm.prank(swapperSponsor);
            (id, registeredClaimHash,) = theCompact.depositERC20AndRegisterFor(
                address(swapper),
                address(token),
                lockTag,
                params.amount,
                arbiter,
                params.nonce,
                params.deadline,
                compactWithWitnessTypehash,
                witness
            );
            vm.snapshotGasLastCall("depositRegisterFor");

            assertEq(theCompact.balanceOf(swapper, id), params.amount);
            assertEq(token.balanceOf(address(theCompact)), params.amount);
        }

        // Verify claim hash
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.id = id;
            args.amount = params.amount;
            args.witness = witness;

            claimHash = _createClaimHashWithWitness(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isActive;
                uint256 registeredAt;
                (isActive, registeredAt) =
                    theCompact.getRegistrationStatus(swapper, claimHash, compactWithWitnessTypehash);
                assert(isActive);
                assertEq(registeredAt, block.timestamp);
            }
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

                uint256 claimantId = uint256(bytes32(abi.encodePacked(bytes12(bytes32(id)), params.recipient)));

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
                id,
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
        assertEq(theCompact.balanceOf(swapper, id), 0);
        assertEq(theCompact.balanceOf(params.recipient, id), params.amount);
    }

    function test_batchDepositERC20AndRegisterForAndClaim_lengthOne() public {
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
        address swapperSponsor = makeAddr("swapperSponsor");

        // Register allocator and setup tokens
        uint256 id;
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            id = address(token).asUint256() | lockTag.asUint256();

            vm.prank(swapper);
            token.transfer(swapperSponsor, params.amount);

            vm.prank(swapperSponsor);
            token.approve(address(theCompact), params.amount);
        }

        // Create witness and deposit/register
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        bytes32 registeredClaimHash;
        bytes32 witness;
        {
            uint256 witnessArgument = 234;
            witness = keccak256(abi.encode(witnessTypehash, witnessArgument));

            idsAndAmounts[0][0] = id;
            idsAndAmounts[0][1] = params.amount;

            uint256[] memory registeredAmounts;
            vm.prank(swapperSponsor);
            (registeredClaimHash, registeredAmounts) = theCompact.batchDepositAndRegisterFor(
                address(swapper),
                idsAndAmounts,
                arbiter,
                params.nonce,
                params.deadline,
                batchCompactWithWitnessTypehash,
                witness
            );
            vm.snapshotGasLastCall("batchDepositRegisterFor");

            assertEq(theCompact.balanceOf(swapper, id), params.amount);
            assertEq(token.balanceOf(address(theCompact)), params.amount);
            assertEq(registeredAmounts.length, 1);
            assertEq(registeredAmounts[0], idsAndAmounts[0][1]);
        }

        // Verify claim hash
        bytes32 claimHash;
        {
            CreateBatchClaimHashWithWitnessArgs memory args;
            args.typehash = batchCompactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.idsAndAmountsHash = keccak256(abi.encodePacked(idsAndAmounts));
            args.witness = witness;

            claimHash = _createBatchClaimHashWithWitness(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isActive;
                uint256 registeredAt;
                (isActive, registeredAt) =
                    theCompact.getRegistrationStatus(swapper, claimHash, batchCompactWithWitnessTypehash);
                assert(isActive);
                assertEq(registeredAt, block.timestamp);
            }
        }

        // Prepare claim
        BatchClaim memory claim;
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

                uint256 claimantId = uint256(bytes32(abi.encodePacked(bytes12(bytes32(id)), params.recipient)));

                recipients[0] = Component({ claimant: claimantId, amount: params.amount });
            }

            BatchClaimComponent[] memory components = new BatchClaimComponent[](1);
            components[0].id = id;
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
            assertEq(returnedClaimHash, claimHash);
        }

        // Verify balances
        assertEq(token.balanceOf(address(theCompact)), params.amount);
        assertEq(theCompact.balanceOf(swapper, id), 0);
        assertEq(theCompact.balanceOf(params.recipient, id), params.amount);
    }
}
