// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";

import { Claim } from "../../src/types/Claims.sol";

import { Setup } from "./Setup.sol";

import { CreateClaimHashWithWitnessArgs } from "./TestHelperStructs.sol";

import { Component } from "../../src/types/Components.sol";

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
            (bool isActive, uint256 registeredAt) =
                theCompact.getRegistrationStatus(swapper, claimHash, compactWithWitnessTypehash);
            assert(isActive);
            assertEq(registeredAt, block.timestamp);
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
            vm.snapshotGasLastCall("registeMultiple");
            assert(status);
        }

        {
            (bool isActive, uint256 registeredAt) =
                theCompact.getRegistrationStatus(swapper, claimHash, compactWithWitnessTypehash);
            assert(isActive);
            assertEq(registeredAt, block.timestamp);
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
}
