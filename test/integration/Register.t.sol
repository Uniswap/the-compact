// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";

import { Claim } from "../../src/types/Claims.sol";

import { Setup } from "./Setup.sol";

import { CreateClaimHashWithWitnessArgs } from "./TestHelperStructs.sol";

import { Component } from "../../src/types/Components.sol";

import { MockERC1271Wallet } from "../../lib/solady/test/utils/mocks/MockERC1271Wallet.sol";
import { AlwaysOkayERC1271 } from "../../src/test/AlwaysOkayERC1271.sol";

contract RegisterTest is Setup {
    function test_registerAndClaim() public {
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = 1e18;

        address arbiter = 0x2222222222222222222222222222222222222222;
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x3333333333333333333333333333333333333333;
        uint256 amountOne = 4e17;
        uint256 amountTwo = 6e17;

        {
            (, bytes12 lockTag) = _registerAllocator(allocator);

            claim.id = _makeDeposit(swapper, claim.allocatedAmount, lockTag);
            claim.witness = _createCompactWitness(234);
        }

        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = claim.sponsor;
            args.nonce = claim.nonce;
            args.expires = claim.expires;
            args.id = claim.id;
            args.amount = claim.allocatedAmount;
            args.witness = claim.witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

        {
            (bytes32 r, bytes32 vs) = vm.signCompact(allocatorPrivateKey, digest);
            claim.allocatorData = abi.encodePacked(r, vs);
        }

        uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(bytes32(claim.id)), recipientOne), (uint256));
        uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(bytes32(claim.id)), recipientTwo), (uint256));

        Component[] memory recipients;
        {
            Component memory splitOne = Component({ claimant: claimantOne, amount: amountOne });

            Component memory splitTwo = Component({ claimant: claimantTwo, amount: amountTwo });

            recipients = new Component[](2);
            recipients[0] = splitOne;
            recipients[1] = splitTwo;
        }

        claim.sponsorSignature = "";
        claim.witnessTypestring = witnessTypestring;
        claim.claimants = recipients;

        vm.prank(swapper);
        {
            (bool status) = theCompact.register(claimHash, compactWithWitnessTypehash);
            vm.snapshotGasLastCall("register");
            assert(status);
        }

        {
            bool isRegistered = theCompact.isRegistered(swapper, claimHash, compactWithWitnessTypehash);
            assert(isRegistered);
        }

        vm.prank(arbiter);
        (bytes32 returnedClaimHash) = theCompact.claim(claim);
        vm.snapshotGasLastCall("claim");
        assertEq(returnedClaimHash, claimHash);

        assertEq(address(theCompact).balance, claim.allocatedAmount);
        assertEq(recipientOne.balance, 0);
        assertEq(recipientTwo.balance, 0);
        assertEq(theCompact.balanceOf(swapper, claim.id), 0);
        assertEq(theCompact.balanceOf(recipientOne, claim.id), amountOne);
        assertEq(theCompact.balanceOf(recipientTwo, claim.id), amountTwo);
    }

    function test_registerMultipleAndClaim_lengthOne() public {
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = 1e18;

        address arbiter = 0x2222222222222222222222222222222222222222;
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x3333333333333333333333333333333333333333;
        uint256 amountOne = 4e17;
        uint256 amountTwo = 6e17;

        {
            (, bytes12 lockTag) = _registerAllocator(allocator);

            claim.id = _makeDeposit(swapper, claim.allocatedAmount, lockTag);
            claim.witness = _createCompactWitness(234);
        }

        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = claim.sponsor;
            args.nonce = claim.nonce;
            args.expires = claim.expires;
            args.id = claim.id;
            args.amount = claim.allocatedAmount;
            args.witness = claim.witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

        {
            (bytes32 r, bytes32 vs) = vm.signCompact(allocatorPrivateKey, digest);
            claim.allocatorData = abi.encodePacked(r, vs);
        }

        uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(bytes32(claim.id)), recipientOne), (uint256));
        uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(bytes32(claim.id)), recipientTwo), (uint256));

        Component[] memory recipients;
        {
            Component memory splitOne = Component({ claimant: claimantOne, amount: amountOne });

            Component memory splitTwo = Component({ claimant: claimantTwo, amount: amountTwo });

            recipients = new Component[](2);
            recipients[0] = splitOne;
            recipients[1] = splitTwo;
        }

        claim.sponsorSignature = "";
        claim.witnessTypestring = witnessTypestring;
        claim.claimants = recipients;

        vm.prank(swapper);
        {
            bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](1);
            claimHashesAndTypehashes[0][0] = claimHash;
            claimHashesAndTypehashes[0][1] = compactWithWitnessTypehash;
            (bool status) = theCompact.registerMultiple(claimHashesAndTypehashes);
            vm.snapshotGasLastCall("registerMultiple");
            assert(status);
        }

        {
            bool isRegistered = theCompact.isRegistered(swapper, claimHash, compactWithWitnessTypehash);
            assert(isRegistered);
        }

        vm.prank(arbiter);
        (bytes32 returnedClaimHash) = theCompact.claim(claim);
        vm.snapshotGasLastCall("claim");
        assertEq(returnedClaimHash, claimHash);

        assertEq(address(theCompact).balance, claim.allocatedAmount);
        assertEq(recipientOne.balance, 0);
        assertEq(recipientTwo.balance, 0);
        assertEq(theCompact.balanceOf(swapper, claim.id), 0);
        assertEq(theCompact.balanceOf(recipientOne, claim.id), amountOne);
        assertEq(theCompact.balanceOf(recipientTwo, claim.id), amountTwo);
    }

    function test_registerAndClaimWithEIP1271Sponsor() public {
        // Create EIP-1271 wallet that will act as the sponsor
        (, uint256 erc1271SignerPrivateKey) = makeAddrAndKey("erc1271Signer");
        address erc1271Signer = vm.addr(erc1271SignerPrivateKey);
        MockERC1271Wallet erc1271Sponsor = new MockERC1271Wallet(erc1271Signer);

        // Give the EIP-1271 sponsor some tokens
        vm.deal(address(erc1271Sponsor), 2e18);

        Claim memory claim;
        claim.sponsor = address(erc1271Sponsor);
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = 1e18;

        address arbiter = 0x2222222222222222222222222222222222222222;
        address recipientOne = 0x1111111111111111111111111111111111111111;
        uint256 amountOne = 1e18;

        {
            (, bytes12 lockTag) = _registerAllocator(allocator);

            // Make deposit from the EIP-1271 sponsor
            vm.prank(address(erc1271Sponsor));
            claim.id = theCompact.depositNative{ value: claim.allocatedAmount }(lockTag, address(erc1271Sponsor));
            claim.witness = _createCompactWitness(234);
        }

        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = arbiter;
            args.sponsor = claim.sponsor;
            args.nonce = claim.nonce;
            args.expires = claim.expires;
            args.id = claim.id;
            args.amount = claim.allocatedAmount;
            args.witness = claim.witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

        // Create allocator signature (EOA)
        {
            (bytes32 r, bytes32 vs) = vm.signCompact(allocatorPrivateKey, digest);
            claim.allocatorData = abi.encodePacked(r, vs);
        }

        // Register the claim hash using the EIP-1271 sponsor
        vm.prank(address(erc1271Sponsor));
        {
            (bool status) = theCompact.register(claimHash, compactWithWitnessTypehash);
            vm.snapshotGasLastCall("registerWithEIP1271");
            assert(status);
        }

        // Verify registration
        {
            bool isRegistered = theCompact.isRegistered(address(erc1271Sponsor), claimHash, compactWithWitnessTypehash);
            assert(isRegistered);
        }

        uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(bytes32(claim.id)), recipientOne), (uint256));

        Component[] memory recipients;
        {
            Component memory splitOne = Component({ claimant: claimantOne, amount: amountOne });
            recipients = new Component[](1);
            recipients[0] = splitOne;
        }

        claim.sponsorSignature = "";
        claim.witnessTypestring = witnessTypestring;
        claim.claimants = recipients;

        // Execute claim (should use registration, not signature validation)
        vm.prank(arbiter);
        (bytes32 returnedClaimHash) = theCompact.claim(claim);
        vm.snapshotGasLastCall("registerAndClaimWithEIP1271");
        assertEq(returnedClaimHash, claimHash);

        assertEq(address(theCompact).balance, claim.allocatedAmount);
        assertEq(recipientOne.balance, 0);
        assertEq(theCompact.balanceOf(address(erc1271Sponsor), claim.id), 0);
        assertEq(theCompact.balanceOf(recipientOne, claim.id), amountOne);
    }

    // Test registerMultiple with EIP-1271 sponsor
    function test_registerMultipleWithEIP1271Sponsor() public {
        // Create EIP-1271 wallet that always approves
        AlwaysOkayERC1271 erc1271Sponsor = new AlwaysOkayERC1271();

        // Give the EIP-1271 sponsor some tokens
        vm.deal(address(erc1271Sponsor), 4e18);

        Claim memory claim1;
        claim1.sponsor = address(erc1271Sponsor);
        claim1.nonce = 0;
        claim1.expires = block.timestamp + 1000;
        claim1.allocatedAmount = 1e18;

        Claim memory claim2;
        claim2.sponsor = address(erc1271Sponsor);
        claim2.nonce = 1;
        claim2.expires = block.timestamp + 1000;
        claim2.allocatedAmount = 1e18;

        address arbiter = 0x2222222222222222222222222222222222222222;

        bytes32 claimHash1;
        bytes32 claimHash2;

        {
            (, bytes12 lockTag) = _registerAllocator(allocator);

            // Make deposits from the EIP-1271 sponsor
            vm.startPrank(address(erc1271Sponsor));
            claim1.id = theCompact.depositNative{ value: claim1.allocatedAmount + claim2.allocatedAmount }(
                lockTag, address(erc1271Sponsor)
            );
            claim2.id = claim1.id;
            vm.stopPrank();

            claim1.witness = _createCompactWitness(234);
            claim2.witness = _createCompactWitness(456);
        }

        // Create claim hashes
        {
            CreateClaimHashWithWitnessArgs memory claimArgs;
            claimArgs.typehash = compactWithWitnessTypehash;
            claimArgs.arbiter = arbiter;
            claimArgs.sponsor = claim1.sponsor;
            claimArgs.nonce = claim1.nonce;
            claimArgs.expires = claim1.expires;
            claimArgs.id = claim1.id;
            claimArgs.amount = claim1.allocatedAmount;
            claimArgs.witness = claim1.witness;
            claimHash1 = _createClaimHashWithWitness(claimArgs);

            claimArgs.typehash = compactWithWitnessTypehash;
            claimArgs.arbiter = arbiter;
            claimArgs.sponsor = claim2.sponsor;
            claimArgs.nonce = claim2.nonce;
            claimArgs.expires = claim2.expires;
            claimArgs.id = claim2.id;
            claimArgs.amount = claim2.allocatedAmount;
            claimArgs.witness = claim2.witness;
            claimHash2 = _createClaimHashWithWitness(claimArgs);
        }

        // Register multiple claim hashes using the EIP-1271 sponsor
        vm.prank(address(erc1271Sponsor));
        {
            bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](2);
            claimHashesAndTypehashes[0][0] = claimHash1;
            claimHashesAndTypehashes[0][1] = compactWithWitnessTypehash;
            claimHashesAndTypehashes[1][0] = claimHash2;
            claimHashesAndTypehashes[1][1] = compactWithWitnessTypehash;

            (bool status) = theCompact.registerMultiple(claimHashesAndTypehashes);
            vm.snapshotGasLastCall("registerMultipleWithEIP1271");
            assertTrue(status);
        }

        // Verify both registrations
        {
            assertTrue(theCompact.isRegistered(address(erc1271Sponsor), claimHash1, compactWithWitnessTypehash));
            assertTrue(theCompact.isRegistered(address(erc1271Sponsor), claimHash2, compactWithWitnessTypehash));
        }

        // Check that balances are correct
        assertEq(address(theCompact).balance, claim1.allocatedAmount + claim2.allocatedAmount);
        assertEq(
            theCompact.balanceOf(address(erc1271Sponsor), claim1.id), claim1.allocatedAmount + claim2.allocatedAmount
        );
    }
}
