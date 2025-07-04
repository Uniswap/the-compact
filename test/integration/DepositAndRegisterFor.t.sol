// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";

import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { Component, BatchClaimComponent } from "../../src/types/Components.sol";
import { Claim } from "../../src/types/Claims.sol";
import { BatchClaim } from "../../src/types/BatchClaims.sol";
import { COMPACT_TYPEHASH, BATCH_COMPACT_TYPEHASH } from "src/types/EIP712Types.sol";

import { Setup } from "./Setup.sol";

import {
    TestParams, CreateClaimHashWithWitnessArgs, CreateBatchClaimHashWithWitnessArgs
} from "./TestHelperStructs.sol";

import { EfficiencyLib } from "../../src/lib/EfficiencyLib.sol";

import { MockERC1271Wallet } from "../../lib/solady/test/utils/mocks/MockERC1271Wallet.sol";
import { AlwaysOkayERC1271 } from "../../src/test/AlwaysOkayERC1271.sol";

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
                bool isRegistered = theCompact.isRegistered(swapper, claimHash, compactWithWitnessTypehash);
                assert(isRegistered);
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

        // Verify registration was consumed
        {
            bool isRegistered = theCompact.isRegistered(swapper, claimHash, compactWithWitnessTypehash);
            assert(!isRegistered);
        }
    }

    function test_depositNativeAndRegisterForNoWitnessAndClaim() public {
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

        // Create deposit/register
        bytes32 registeredClaimHash;
        {
            vm.prank(swapperSponsor);
            (id, registeredClaimHash) = theCompact.depositNativeAndRegisterFor{ value: params.amount }(
                address(swapper), lockTag, arbiter, params.nonce, params.deadline, COMPACT_TYPEHASH, bytes32(0)
            );
            vm.snapshotGasLastCall("depositNativeAndRegisterForNoWitness");

            assertEq(theCompact.balanceOf(swapper, id), params.amount);
            assertEq(address(theCompact).balance, params.amount);
        }

        // Verify claim hash
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = COMPACT_TYPEHASH;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.id = id;
            args.amount = params.amount;
            args.witness = bytes32(0);

            claimHash = _createClaimHash(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isActive = theCompact.isRegistered(swapper, claimHash, COMPACT_TYPEHASH);
                assert(isActive);
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
                bytes23(0), // witness
                "", // witnessTypestring
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

        // Verify registration was consumed
        {
            bool isRegistered = theCompact.isRegistered(swapper, claimHash, COMPACT_TYPEHASH);
            assert(!isRegistered);
        }
    }

    function test_depositERC20AndRegisterForNoWitnessAndClaim() public {
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
        {
            vm.prank(swapperSponsor);
            (id, registeredClaimHash,) = theCompact.depositERC20AndRegisterFor(
                address(swapper),
                address(token),
                lockTag,
                params.amount,
                arbiter,
                params.nonce,
                params.deadline,
                COMPACT_TYPEHASH,
                bytes32(0) // witness
            );
            vm.snapshotGasLastCall("depositERC20AndRegisterForNoWitness");

            assertEq(theCompact.balanceOf(swapper, id), params.amount);
            assertEq(token.balanceOf(address(theCompact)), params.amount);
        }

        // Verify claim hash
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = COMPACT_TYPEHASH;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.id = id;
            args.amount = params.amount;
            args.witness = bytes32(0);

            claimHash = _createClaimHash(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isActive = theCompact.isRegistered(swapper, claimHash, COMPACT_TYPEHASH);
                assert(isActive);
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
                bytes32(0), // witness
                "", // witnessTypestring
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

        // Verify registration was consumed
        {
            bool isRegistered = theCompact.isRegistered(swapper, claimHash, COMPACT_TYPEHASH);
            assert(!isRegistered);
        }
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
            vm.snapshotGasLastCall("depositERC20AndRegisterFor");

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
                bool isRegistered = theCompact.isRegistered(swapper, claimHash, compactWithWitnessTypehash);
                assert(isRegistered);
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

        // Verify registration was consumed
        {
            bool isRegistered = theCompact.isRegistered(swapper, claimHash, compactWithWitnessTypehash);
            assert(!isRegistered);
        }
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
            vm.snapshotGasLastCall("batchDepositRegisterForLengthOne");

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
            args.idsAndAmountsHash = _hashOfHashes(idsAndAmounts);
            args.witness = witness;

            claimHash = _createBatchClaimHashWithWitness(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isRegistered = theCompact.isRegistered(swapper, claimHash, batchCompactWithWitnessTypehash);
                assert(isRegistered);
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

        // Verify registration was consumed
        {
            bool isRegistered = theCompact.isRegistered(swapper, claimHash, batchCompactWithWitnessTypehash);
            assert(!isRegistered);
        }
    }

    function test_batchDepositERC20AndRegisterForAndClaim() public {
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
        uint256 id2;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            id = address(token).asUint256() | lockTag.asUint256();
            id2 = address(anotherToken).asUint256() | lockTag.asUint256();

            vm.prank(swapper);
            token.transfer(swapperSponsor, params.amount);

            vm.prank(swapperSponsor);
            token.approve(address(theCompact), params.amount);

            vm.prank(swapper);
            anotherToken.transfer(swapperSponsor, params.amount);

            vm.prank(swapperSponsor);
            anotherToken.approve(address(theCompact), params.amount);
        }

        // Create witness and deposit/register
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        bytes32 registeredClaimHash;
        bytes32 witness;
        {
            witness = keccak256(abi.encode(witnessTypehash, 234));

            idsAndAmounts[0][0] = id;
            idsAndAmounts[0][1] = params.amount;

            idsAndAmounts[1][0] = id2;
            idsAndAmounts[1][1] = params.amount;

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

            assertEq(theCompact.balanceOf(swapper, id), params.amount);
            assertEq(token.balanceOf(address(theCompact)), params.amount);
            assertEq(theCompact.balanceOf(swapper, id2), params.amount);
            assertEq(anotherToken.balanceOf(address(theCompact)), params.amount);
            assertEq(registeredAmounts.length, 2);
            assertEq(registeredAmounts[0], idsAndAmounts[0][1]);
            assertEq(registeredAmounts[1], idsAndAmounts[1][1]);
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
            args.idsAndAmountsHash = _hashOfHashes(idsAndAmounts);
            args.witness = witness;

            claimHash = _createBatchClaimHashWithWitness(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isActive = theCompact.isRegistered(swapper, claimHash, batchCompactWithWitnessTypehash);
                assert(isActive);
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

            BatchClaimComponent[] memory components = new BatchClaimComponent[](2);
            components[0].id = id;
            components[0].allocatedAmount = params.amount;
            components[0].portions = recipients;

            components[1].id = id2;
            components[1].allocatedAmount = params.amount;
            components[1].portions = recipients;

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
        assertEq(anotherToken.balanceOf(address(theCompact)), params.amount);
        assertEq(theCompact.balanceOf(swapper, id2), 0);
        assertEq(theCompact.balanceOf(params.recipient, id2), params.amount);

        // Verify registration was consumed
        {
            bool isRegistered = theCompact.isRegistered(swapper, claimHash, batchCompactWithWitnessTypehash);
            assert(!isRegistered);
        }
    }

    function test_batchDepositAndRegisterForNoWitnessAndClaim() public {
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
        uint256 id2;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            id = address(token).asUint256() | lockTag.asUint256();
            id2 = address(anotherToken).asUint256() | lockTag.asUint256();

            vm.prank(swapper);
            token.transfer(swapperSponsor, params.amount);

            vm.prank(swapperSponsor);
            token.approve(address(theCompact), params.amount);

            vm.prank(swapper);
            anotherToken.transfer(swapperSponsor, params.amount);

            vm.prank(swapperSponsor);
            anotherToken.approve(address(theCompact), params.amount);
        }

        // Create witness and deposit/register
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        bytes32 registeredClaimHash;
        {
            idsAndAmounts[0][0] = id;
            idsAndAmounts[0][1] = params.amount;

            idsAndAmounts[1][0] = id2;
            idsAndAmounts[1][1] = params.amount;

            uint256[] memory registeredAmounts;
            vm.prank(swapperSponsor);
            (registeredClaimHash, registeredAmounts) = theCompact.batchDepositAndRegisterFor(
                address(swapper),
                idsAndAmounts,
                arbiter,
                params.nonce,
                params.deadline,
                BATCH_COMPACT_TYPEHASH,
                bytes32(0)
            );

            assertEq(theCompact.balanceOf(swapper, id), params.amount);
            assertEq(token.balanceOf(address(theCompact)), params.amount);
            assertEq(theCompact.balanceOf(swapper, id2), params.amount);
            assertEq(anotherToken.balanceOf(address(theCompact)), params.amount);
            assertEq(registeredAmounts.length, 2);
            assertEq(registeredAmounts[0], idsAndAmounts[0][1]);
            assertEq(registeredAmounts[1], idsAndAmounts[1][1]);
        }

        // Verify claim hash
        bytes32 claimHash;
        {
            CreateBatchClaimHashWithWitnessArgs memory args;
            args.typehash = BATCH_COMPACT_TYPEHASH;
            args.arbiter = arbiter;
            args.sponsor = swapper;
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.idsAndAmountsHash = _hashOfHashes(idsAndAmounts);
            args.witness = "";

            claimHash = _createBatchClaimHash(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isActive = theCompact.isRegistered(swapper, claimHash, BATCH_COMPACT_TYPEHASH);
                assert(isActive);
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

            BatchClaimComponent[] memory components = new BatchClaimComponent[](2);
            components[0].id = id;
            components[0].allocatedAmount = params.amount;
            components[0].portions = recipients;

            components[1].id = id2;
            components[1].allocatedAmount = params.amount;
            components[1].portions = recipients;

            // Build the claim
            claim = BatchClaim(
                allocatorSignature,
                "", // sponsorSignature
                swapper,
                params.nonce,
                params.deadline,
                "", // witness
                "", // witnessTypestring
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
        assertEq(anotherToken.balanceOf(address(theCompact)), params.amount);
        assertEq(theCompact.balanceOf(swapper, id2), 0);
        assertEq(theCompact.balanceOf(params.recipient, id2), params.amount);
    }

    function test_revert_InconsistentAllocators() public {
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
        uint256 id2;
        bytes12 lockTag2;
        {
            uint96 allocatorId;
            uint96 allocatorId2;
            (allocatorId, lockTag) = _registerAllocator(allocator);
            (allocatorId2, lockTag2) = _registerAllocator(alwaysOKAllocator);

            id = address(token).asUint256() | lockTag.asUint256();
            id2 = address(anotherToken).asUint256() | lockTag2.asUint256();

            vm.prank(swapper);
            token.transfer(swapperSponsor, params.amount);

            vm.prank(swapperSponsor);
            token.approve(address(theCompact), params.amount);

            vm.prank(swapper);
            anotherToken.transfer(swapperSponsor, params.amount);

            vm.prank(swapperSponsor);
            anotherToken.approve(address(theCompact), params.amount);
        }

        // Create witness and deposit/register
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        bytes32 witness;
        {
            uint256 witnessArgument = 234;
            witness = keccak256(abi.encode(witnessTypehash, witnessArgument));

            idsAndAmounts[0][0] = id;
            idsAndAmounts[0][1] = params.amount;

            idsAndAmounts[1][0] = id2;
            idsAndAmounts[1][1] = params.amount;

            vm.prank(swapperSponsor);
            vm.expectRevert(abi.encodeWithSelector(ITheCompact.InconsistentAllocators.selector));
            theCompact.batchDepositAndRegisterFor(
                address(swapper),
                idsAndAmounts,
                arbiter,
                params.nonce,
                params.deadline,
                batchCompactWithWitnessTypehash,
                witness
            );

            assertEq(theCompact.balanceOf(swapper, id), 0);
            assertEq(token.balanceOf(address(theCompact)), 0);
            assertEq(theCompact.balanceOf(swapper, id2), 0);
            assertEq(anotherToken.balanceOf(address(theCompact)), 0);
        }
    }

    function test_addressZeroReplacedWithCaller() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 5e17;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Additional parameters
        address arbiter = 0x2222222222222222222222222222222222222222;

        // Register allocator and setup tokens
        uint256 id;
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(alwaysOKAllocator);
        }

        // Deposit some funds
        id = _makeDeposit(swapper, address(token), params.amount, lockTag);

        // Send to address(0)
        vm.prank(swapper);
        theCompact.transfer(address(0), id, params.amount);

        // ensure address(0) has balance of id
        assertGt(theCompact.balanceOf(address(0), id), 0);

        assertTrue(token.balanceOf(swapper) >= params.amount, "swapper does not have enough balance");

        // Create witness and deposit/register
        bytes32 registeredClaimHash;
        {
            vm.prank(swapper);
            token.approve(address(theCompact), params.amount);

            vm.prank(swapper);
            (id, registeredClaimHash,) = theCompact.depositERC20AndRegisterFor(
                address(0), // insert address(0) as this is replaced for the deposit, but not the registration
                address(token),
                lockTag,
                params.amount,
                arbiter,
                params.nonce,
                params.deadline,
                COMPACT_TYPEHASH,
                bytes32(0) // witness
            );
            vm.snapshotGasLastCall("depositERC20AndRegisterForNoWitnessZeroReplaced");

            assertEq(theCompact.balanceOf(swapper, id), params.amount);
            assertEq(token.balanceOf(address(theCompact)), params.amount * 2); // 2x because address(0) and the user will have that balance
        }

        // Verify claim hash
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = COMPACT_TYPEHASH;
            args.arbiter = arbiter;
            args.sponsor = address(0); // insert address(0) to withdraw from address(0)
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.id = id;
            args.amount = params.amount;
            args.witness = bytes32(0);

            // Claim hash expecting the sponsor to be address zero should fail
            claimHash = _createClaimHash(args);
            assertNotEq(registeredClaimHash, claimHash);
            // Replacing the sponsor with the caller should work
            args.sponsor = swapper;
            claimHash = _createClaimHash(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isActive = theCompact.isRegistered(address(0), claimHash, COMPACT_TYPEHASH);
                assert(!isActive); // address(0) must not have registrations
                isActive = theCompact.isRegistered(swapper, claimHash, COMPACT_TYPEHASH);
                assert(isActive); // swapper received the registration instead
            }
        }

        // Prepare claim
        Claim memory claim;
        {
            // Skipping AllocatorSignature as its the AlwaysOKAllocator

            // Create recipients
            Component[] memory recipients;
            {
                recipients = new Component[](1);

                uint256 claimantId = uint256(bytes32(abi.encodePacked(bytes12(bytes32(id)), swapper)));

                recipients[0] = Component({ claimant: claimantId, amount: params.amount });
            }

            // Build the claim
            claim = Claim(
                "", // allocatorSignature
                "", // sponsorSignature
                address(0), // sponsor
                params.nonce,
                params.deadline,
                bytes32(0), // witness
                "", // witnessTypestring
                id,
                params.amount,
                recipients
            );
        }

        // Execute claim
        {
            vm.prank(arbiter);
            vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidSignature.selector));
            theCompact.claim(claim);
        }

        // Verify balances
        assertEq(token.balanceOf(address(theCompact)), params.amount * 2);
        assertEq(theCompact.balanceOf(swapper, id), params.amount); // swapper keeps their balance
        assertEq(theCompact.balanceOf(address(0), id), params.amount); // address(0) gets the balance

        // Verify the adapted registration is still available
        {
            bool isRegistered = theCompact.isRegistered(swapper, claimHash, COMPACT_TYPEHASH);
            assert(isRegistered);
        }
    }

    function test_depositNativeAndRegisterForAndClaimWithEIP1271Sponsor() public {
        // Create EIP-1271 wallet that will act as the sponsor
        (, uint256 erc1271SignerPrivateKey) = makeAddrAndKey("erc1271Signer");
        address erc1271Signer = vm.addr(erc1271SignerPrivateKey);
        MockERC1271Wallet erc1271Sponsor = new MockERC1271Wallet(erc1271Signer);

        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;
        params.recipient = 0x1111111111111111111111111111111111111111;

        address arbiter = 0x2222222222222222222222222222222222222222;
        address depositMaker = makeAddr("depositMaker");

        // Register allocator and setup tokens
        uint256 id;
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);
            vm.deal(depositMaker, params.amount);
        }

        // Create witness and deposit/register
        bytes32 registeredClaimHash;
        bytes32 witness;
        uint256 witnessArgument = 234;
        {
            witness = keccak256(abi.encode(witnessTypehash, witnessArgument));

            vm.prank(depositMaker);
            (id, registeredClaimHash) = theCompact.depositNativeAndRegisterFor{ value: params.amount }(
                address(erc1271Sponsor),
                lockTag,
                arbiter,
                params.nonce,
                params.deadline,
                compactWithWitnessTypehash,
                witness
            );
            vm.snapshotGasLastCall("depositNativeAndRegisterForWithEIP1271");

            assertEq(theCompact.balanceOf(address(erc1271Sponsor), id), params.amount);
            assertEq(address(theCompact).balance, params.amount);
        }

        // Verify claim hash
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = address(erc1271Sponsor);
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.id = id;
            args.amount = params.amount;
            args.witness = witness;

            claimHash = _createClaimHashWithWitness(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isRegistered =
                    theCompact.isRegistered(address(erc1271Sponsor), claimHash, compactWithWitnessTypehash);
                assert(isRegistered);
            }
        }

        // Prepare claim with EIP-1271 sponsor signature
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

            // Build the claim (use registration, so no sponsor signature needed)
            claim = Claim(
                allocatorSignature,
                "", // sponsorSignature
                address(erc1271Sponsor),
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
        assertEq(theCompact.balanceOf(address(erc1271Sponsor), id), 0);
        assertEq(theCompact.balanceOf(params.recipient, id), params.amount);

        // Verify registration was consumed
        {
            bool isRegistered = theCompact.isRegistered(address(erc1271Sponsor), claimHash, compactWithWitnessTypehash);
            assertFalse(isRegistered, "Registration should be consumed");
        }
    }

    function test_depositERC20AndRegisterForAndClaimWithEIP1271Sponsor() public {
        // Create EIP-1271 wallet that will act as the sponsor
        AlwaysOkayERC1271 erc1271Sponsor = new AlwaysOkayERC1271();

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
        address depositMaker = makeAddr("depositMaker");

        // Register allocator and setup tokens
        uint256 id;
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            vm.prank(swapper);
            token.transfer(depositMaker, params.amount);

            vm.prank(depositMaker);
            token.approve(address(theCompact), params.amount);
        }

        // Create witness and deposit/register
        bytes32 registeredClaimHash;
        bytes32 witness;
        uint256 witnessArgument = 234;
        {
            witness = keccak256(abi.encode(witnessTypehash, witnessArgument));

            vm.prank(depositMaker);
            (id, registeredClaimHash,) = theCompact.depositERC20AndRegisterFor(
                address(erc1271Sponsor),
                address(token),
                lockTag,
                params.amount,
                arbiter,
                params.nonce,
                params.deadline,
                compactWithWitnessTypehash,
                witness
            );
            vm.snapshotGasLastCall("depositERC20AndRegisterForWithEIP1271");

            assertEq(theCompact.balanceOf(address(erc1271Sponsor), id), params.amount);
            assertEq(token.balanceOf(address(theCompact)), params.amount);
        }

        // Verify claim hash
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = address(erc1271Sponsor);
            args.nonce = params.nonce;
            args.expires = params.deadline;
            args.id = id;
            args.amount = params.amount;
            args.witness = witness;

            claimHash = _createClaimHashWithWitness(args);
            assertEq(registeredClaimHash, claimHash);

            {
                bool isRegistered =
                    theCompact.isRegistered(address(erc1271Sponsor), claimHash, compactWithWitnessTypehash);
                assert(isRegistered);
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

            // Build the claim (use registration, so no sponsor signature needed)
            claim = Claim(
                allocatorSignature,
                "", // sponsorSignature
                address(erc1271Sponsor),
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
        assertEq(theCompact.balanceOf(address(erc1271Sponsor), id), 0);
        assertEq(theCompact.balanceOf(params.recipient, id), params.amount);

        // Verify registration was consumed
        {
            bool isRegistered = theCompact.isRegistered(address(erc1271Sponsor), claimHash, compactWithWitnessTypehash);
            assertFalse(isRegistered, "Registration should be consumed");
        }
    }

    function test_batchDepositAndRegisterForAndBatchClaimWithEIP1271Sponsor() public {
        // Create EIP-1271 wallet that will act as the sponsor
        (, uint256 erc1271SignerPrivateKey) = makeAddrAndKey("erc1271Signer");
        address erc1271Signer = vm.addr(erc1271SignerPrivateKey);
        MockERC1271Wallet erc1271Sponsor = new MockERC1271Wallet(erc1271Signer);

        // Setup test parameters in a separate function to reduce stack depth
        (TestParams memory params, address arbiter, address depositMaker, bytes12 lockTag) =
            _setupBatchEIP1271TestParams();

        // Prepare batch data in a separate function
        (uint256[2][] memory idsAndAmounts, bytes32 witness) = _prepareBatchData(lockTag, params.amount);

        // Execute deposit and register
        bytes32 registeredClaimHash = _executeBatchDepositAndRegister(
            depositMaker, address(erc1271Sponsor), idsAndAmounts, arbiter, params, witness
        );

        // Verify the claim hash
        bytes32 claimHash =
            _verifyBatchClaimHash(address(erc1271Sponsor), arbiter, params, idsAndAmounts, witness, registeredClaimHash);

        // Prepare and execute the batch claim
        _executeBatchClaim(address(erc1271Sponsor), arbiter, claimHash, params, idsAndAmounts, witness);

        // Verify final balances and registration consumption
        _verifyFinalState(address(erc1271Sponsor), claimHash, params.recipient, idsAndAmounts);
    }

    function _setupBatchEIP1271TestParams()
        private
        returns (TestParams memory params, address arbiter, address depositMaker, bytes12 lockTag)
    {
        params = TestParams({
            resetPeriod: ResetPeriod.TenMinutes,
            scope: Scope.Multichain,
            amount: 1e18,
            nonce: 0,
            deadline: block.timestamp + 1000,
            recipient: 0x1111111111111111111111111111111111111111,
            id: 0 // Not used directly in this setup
         });

        arbiter = 0x2222222222222222222222222222222222222222;
        depositMaker = makeAddr("depositMaker");

        uint96 allocatorId;
        (allocatorId, lockTag) = _registerAllocator(allocator);

        vm.prank(swapper);
        token.transfer(depositMaker, params.amount);
        vm.prank(depositMaker);
        token.approve(address(theCompact), params.amount);

        vm.prank(swapper);
        anotherToken.transfer(depositMaker, params.amount);
        vm.prank(depositMaker);
        anotherToken.approve(address(theCompact), params.amount);
    }

    function _prepareBatchData(bytes12 lockTag, uint256 amount)
        private
        view
        returns (uint256[2][] memory idsAndAmounts, bytes32 witness)
    {
        uint256 id = address(token).asUint256() | lockTag.asUint256();
        uint256 id2 = address(anotherToken).asUint256() | lockTag.asUint256();

        idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = id;
        idsAndAmounts[0][1] = amount;
        idsAndAmounts[1][0] = id2;
        idsAndAmounts[1][1] = amount;

        uint256 witnessArgument = 234;
        witness = keccak256(abi.encode(witnessTypehash, witnessArgument));
    }

    function _executeBatchDepositAndRegister(
        address depositMaker,
        address erc1271Sponsor,
        uint256[2][] memory idsAndAmounts,
        address arbiter,
        TestParams memory params,
        bytes32 witness
    ) private returns (bytes32 registeredClaimHash) {
        uint256[] memory registeredAmounts;
        vm.prank(depositMaker);
        (registeredClaimHash, registeredAmounts) = theCompact.batchDepositAndRegisterFor(
            erc1271Sponsor,
            idsAndAmounts,
            arbiter,
            params.nonce,
            params.deadline,
            batchCompactWithWitnessTypehash,
            witness
        );
        vm.snapshotGasLastCall("batchDepositAndRegisterForWithEIP1271");

        assertEq(theCompact.balanceOf(erc1271Sponsor, idsAndAmounts[0][0]), params.amount);
        assertEq(token.balanceOf(address(theCompact)), params.amount);
        assertEq(theCompact.balanceOf(erc1271Sponsor, idsAndAmounts[1][0]), params.amount);
        assertEq(anotherToken.balanceOf(address(theCompact)), params.amount);
        assertEq(registeredAmounts.length, 2);
        assertEq(registeredAmounts[0], idsAndAmounts[0][1]);
        assertEq(registeredAmounts[1], idsAndAmounts[1][1]);
    }

    function _verifyBatchClaimHash(
        address erc1271Sponsor,
        address arbiter,
        TestParams memory params,
        uint256[2][] memory idsAndAmounts,
        bytes32 witness,
        bytes32 registeredClaimHash
    ) private pure returns (bytes32 claimHash) {
        CreateBatchClaimHashWithWitnessArgs memory args;
        args.typehash = batchCompactWithWitnessTypehash;
        args.arbiter = arbiter;
        args.sponsor = erc1271Sponsor;
        args.nonce = params.nonce;
        args.expires = params.deadline;
        args.idsAndAmountsHash = _hashOfHashes(idsAndAmounts);
        args.witness = witness;

        claimHash = _createBatchClaimHashWithWitness(args);
        assertEq(registeredClaimHash, claimHash);
    }

    function _executeBatchClaim(
        address erc1271Sponsor,
        address arbiter,
        bytes32 claimHash,
        TestParams memory params,
        uint256[2][] memory idsAndAmounts,
        bytes32 witness
    ) private {
        // Create digest and get allocator signature
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), theCompact.DOMAIN_SEPARATOR(), claimHash));
        (bytes32 r, bytes32 vs) = vm.signCompact(allocatorPrivateKey, digest);
        bytes memory allocatorSignature = abi.encodePacked(r, vs);

        // Create recipients
        Component[] memory recipients = new Component[](1);
        uint256 claimantId = uint256(bytes32(abi.encodePacked(bytes12(bytes32(idsAndAmounts[0][0])), params.recipient)));
        recipients[0] = Component({ claimant: claimantId, amount: params.amount });

        BatchClaimComponent[] memory components = new BatchClaimComponent[](2);
        components[0].id = idsAndAmounts[0][0];
        components[0].allocatedAmount = params.amount;
        components[0].portions = recipients;
        components[1].id = idsAndAmounts[1][0];
        components[1].allocatedAmount = params.amount;
        components[1].portions = recipients;

        // Build the claim
        BatchClaim memory batchClaim = BatchClaim(
            allocatorSignature,
            "", // sponsorSignature (using registration)
            erc1271Sponsor,
            params.nonce,
            params.deadline,
            witness,
            witnessTypestring,
            components
        );

        // Execute claim
        vm.prank(arbiter);
        bytes32 returnedClaimHash = theCompact.batchClaim(batchClaim);
        assertEq(returnedClaimHash, claimHash);
    }

    function _verifyFinalState(
        address erc1271Sponsor,
        bytes32 claimHash,
        address recipient,
        uint256[2][] memory idsAndAmounts
    ) private view {
        uint256 id1 = idsAndAmounts[0][0];
        uint256 amount1 = idsAndAmounts[0][1];
        uint256 id2 = idsAndAmounts[1][0];

        assertEq(token.balanceOf(address(theCompact)), amount1);
        assertEq(theCompact.balanceOf(erc1271Sponsor, id1), 0);
        assertEq(theCompact.balanceOf(recipient, id1), amount1);
        assertEq(anotherToken.balanceOf(address(theCompact)), amount1);
        assertEq(theCompact.balanceOf(erc1271Sponsor, id2), 0);
        assertEq(theCompact.balanceOf(recipient, id2), amount1);

        bool isRegistered = theCompact.isRegistered(erc1271Sponsor, claimHash, batchCompactWithWitnessTypehash);
        assertFalse(isRegistered);
    }
}
