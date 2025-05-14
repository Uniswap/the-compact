// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";

import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { Component, BatchClaimComponent } from "../../src/types/Components.sol";
import { Claim } from "../../src/types/Claims.sol";
import { BatchClaim } from "../../src/types/BatchClaims.sol";
import { MultichainClaim, ExogenousMultichainClaim } from "../../src/types/MultichainClaims.sol";
import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../../src/types/BatchMultichainClaims.sol";

import { AlwaysDenyingAllocator } from "../../src/test/AlwaysDenyingAllocator.sol";
import { AlwaysRevertingAllocator } from "../../src/test/AlwaysRevertingAllocator.sol";
import { Setup } from "./Setup.sol";

import {
    TestParams,
    CreateClaimHashWithWitnessArgs,
    CreateBatchClaimHashWithWitnessArgs,
    BatchMultichainClaimArgs
} from "./TestHelperStructs.sol";

contract ClaimTest is Setup {
    function test_claimAndWithdraw() public {
        // Initialize claim struct
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = 1e18;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x3333333333333333333333333333333333333333;
        uint256 amountOne = 4e17;
        uint256 amountTwo = 6e17;
        address arbiter = 0x2222222222222222222222222222222222222222;

        // Register allocator, make deposit and create witness
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            claim.id = _makeDeposit(swapper, claim.allocatedAmount, lockTag);
            claim.witness = _createCompactWitness(234);
        }

        // Create claim hash
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

        // Create signatures
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

        {
            bytes32 r;
            bytes32 vs;

            // Create sponsor signature
            {
                (r, vs) = vm.signCompact(swapperPrivateKey, digest);
                claim.sponsorSignature = abi.encodePacked(r, vs);
            }

            // Create allocator signature
            {
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Prepare recipients
        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));
            uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(0), recipientTwo), (uint256));

            Component[] memory recipients;
            {
                Component memory splitOne = Component({ claimant: claimantOne, amount: amountOne });
                Component memory splitTwo = Component({ claimant: claimantTwo, amount: amountTwo });

                recipients = new Component[](2);
                recipients[0] = splitOne;
                recipients[1] = splitTwo;
            }

            claim.witnessTypestring = witnessTypestring;
            claim.claimants = recipients;
        }

        // Execute claim
        bytes32 returnedClaimHash;
        {
            vm.prank(arbiter);
            returnedClaimHash = theCompact.claim(claim);
            vm.snapshotGasLastCall("claimAndWithdraw");
            assertEq(returnedClaimHash, claimHash);
        }

        // Verify balances
        assertEq(address(theCompact).balance, 0);
        assertEq(recipientOne.balance, amountOne);
        assertEq(recipientTwo.balance, amountTwo);
        assertEq(theCompact.balanceOf(swapper, claim.id), 0);
        assertEq(theCompact.balanceOf(recipientOne, claim.id), 0);
        assertEq(theCompact.balanceOf(recipientTwo, claim.id), 0);
    }

    function test_splitClaimWithWitness() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize claim
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = 1e18;
        claim.witnessTypestring = witnessTypestring;

        // Register allocator and make deposit
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            claim.id = _makeDeposit(swapper, 1e18, lockTag);

            // Create witness
            uint256 witnessArgument = 234;
            claim.witness = _createCompactWitness(witnessArgument);
        }

        // Create claim hash
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            {
                args.typehash = compactWithWitnessTypehash;
                args.arbiter = 0x2222222222222222222222222222222222222222;
                args.sponsor = claim.sponsor;
                args.nonce = claim.nonce;
                args.expires = claim.expires;
                args.id = claim.id;
                args.amount = claim.allocatedAmount;
                args.witness = claim.witness;
            }

            claimHash = _createClaimHashWithWitness(args);
        }

        // Create signatures
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            {
                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(swapperPrivateKey, digest);
                claim.sponsorSignature = abi.encodePacked(r, vs);
            }

            {
                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Create split components
        {
            uint256 claimantOne = abi.decode(
                abi.encodePacked(bytes12(bytes32(claim.id)), 0x1111111111111111111111111111111111111111), (uint256)
            );
            uint256 claimantTwo = abi.decode(
                abi.encodePacked(bytes12(bytes32(claim.id)), 0x3333333333333333333333333333333333333333), (uint256)
            );

            Component[] memory recipients;
            {
                Component memory splitOne = Component({ claimant: claimantOne, amount: 4e17 });
                Component memory splitTwo = Component({ claimant: claimantTwo, amount: 6e17 });

                recipients = new Component[](2);
                recipients[0] = splitOne;
                recipients[1] = splitTwo;

                claim.claimants = recipients;
            }
        }

        // Execute claim
        bytes32 returnedClaimHash;
        {
            vm.prank(0x2222222222222222222222222222222222222222);
            returnedClaimHash = theCompact.claim(claim);
            vm.snapshotGasLastCall("splitClaimWithWitness");
            assertEq(returnedClaimHash, claimHash);
        }

        // Verify balances
        {
            assertEq(address(theCompact).balance, 1e18);
            assertEq(0x1111111111111111111111111111111111111111.balance, 0);
            assertEq(0x3333333333333333333333333333333333333333.balance, 0);
            assertEq(theCompact.balanceOf(swapper, claim.id), 0);

            assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, claim.id), 4e17);
            assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, claim.id), 6e17);
        }
    }

    function test_splitBatchClaimWithWitness() public {
        // Setup test parameters
        TestParams memory params;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize batch claim
        BatchClaim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = block.timestamp + 1000;
        claim.witnessTypestring = witnessTypestring;

        // Register allocator and make deposits
        uint256 id;
        uint256 anotherId;
        uint256 aThirdId;
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            id = _makeDeposit(swapper, 1e18, lockTag);
            anotherId = _makeDeposit(swapper, address(token), 1e18, lockTag);
            aThirdId = _makeDeposit(swapper, address(anotherToken), 1e18, lockTag);

            assertEq(theCompact.balanceOf(swapper, id), 1e18);
            assertEq(theCompact.balanceOf(swapper, anotherId), 1e18);
            assertEq(theCompact.balanceOf(swapper, aThirdId), 1e18);
        }

        // Create idsAndAmounts and witness
        uint256[2][] memory idsAndAmounts;
        {
            idsAndAmounts = new uint256[2][](3);
            idsAndAmounts[0] = [id, 1e18];
            idsAndAmounts[1] = [anotherId, 1e18];
            idsAndAmounts[2] = [aThirdId, 1e18];

            uint256 witnessArgument = 234;
            claim.witness = _createCompactWitness(witnessArgument);
        }

        // Create claim hash
        bytes32 claimHash;
        {
            CreateBatchClaimHashWithWitnessArgs memory args;
            {
                args.typehash = keccak256(
                    "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)"
                );
                args.arbiter = 0x2222222222222222222222222222222222222222;
                args.sponsor = claim.sponsor;
                args.nonce = claim.nonce;
                args.expires = claim.expires;
                args.idsAndAmountsHash = keccak256(abi.encodePacked(idsAndAmounts));
                args.witness = claim.witness;
            }

            claimHash = _createBatchClaimHashWithWitness(args);
        }

        // Create signatures
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            {
                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(swapperPrivateKey, digest);
                claim.sponsorSignature = abi.encodePacked(r, vs);
            }

            {
                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Create batch claim components
        {
            BatchClaimComponent[] memory claims = new BatchClaimComponent[](3);

            // First claim component
            {
                uint256 claimantOne = abi.decode(
                    abi.encodePacked(bytes12(bytes32(id)), 0x1111111111111111111111111111111111111111), (uint256)
                );
                uint256 claimantTwo = abi.decode(
                    abi.encodePacked(bytes12(bytes32(id)), 0x3333333333333333333333333333333333333333), (uint256)
                );

                Component[] memory portions = new Component[](2);
                portions[0] = Component({ claimant: claimantOne, amount: 4e17 });
                portions[1] = Component({ claimant: claimantTwo, amount: 6e17 });

                claims[0] = BatchClaimComponent({ id: id, allocatedAmount: 1e18, portions: portions });
            }

            // Second claim component
            {
                uint256 claimantThree = abi.decode(
                    abi.encodePacked(bytes12(bytes32(anotherId)), 0x1111111111111111111111111111111111111111), (uint256)
                );

                Component[] memory anotherPortion = new Component[](1);
                anotherPortion[0] = Component({ claimant: claimantThree, amount: 1e18 });

                claims[1] = BatchClaimComponent({ id: anotherId, allocatedAmount: 1e18, portions: anotherPortion });
            }

            // Third claim component
            {
                uint256 claimantFour = abi.decode(
                    abi.encodePacked(bytes12(bytes32(aThirdId)), 0x3333333333333333333333333333333333333333), (uint256)
                );

                Component[] memory aThirdPortion = new Component[](1);
                aThirdPortion[0] = Component({ claimant: claimantFour, amount: 1e18 });

                claims[2] = BatchClaimComponent({ id: aThirdId, allocatedAmount: 1e18, portions: aThirdPortion });
            }

            claim.claims = claims;
        }

        // Execute claim
        bytes32 returnedClaimHash;
        {
            vm.prank(0x2222222222222222222222222222222222222222);
            returnedClaimHash = theCompact.batchClaim(claim);
            vm.snapshotGasLastCall("splitBatchClaimWithWitness");
            assertEq(returnedClaimHash, claimHash);
        }

        // Verify balances
        {
            assertEq(address(theCompact).balance, 1e18);
            assertEq(token.balanceOf(address(theCompact)), 1e18);
            assertEq(anotherToken.balanceOf(address(theCompact)), 1e18);

            assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, id), 4e17);
            assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, id), 6e17);
            assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, anotherId), 1e18);
            assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, aThirdId), 1e18);
        }
    }

    function test_revert_allocatorDeniesClaim() public {
        // Initialize claim struct
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = 1e18;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;
        uint256 amountOne = 1e18;
        address arbiter = 0x2222222222222222222222222222222222222222;

        // Register allocator, make deposit and create witness
        address alwaysDenyingAllocator = address(new AlwaysDenyingAllocator());
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(alwaysDenyingAllocator);
            }

            claim.id = _makeDeposit(swapper, claim.allocatedAmount, lockTag);
            claim.witness = _createCompactWitness(234);
        }

        // Create claim hash
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

        // Create signatures
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

        {
            bytes32 r;
            bytes32 vs;

            // Create sponsor signature
            {
                (r, vs) = vm.signCompact(swapperPrivateKey, digest);
                claim.sponsorSignature = abi.encodePacked(r, vs);
            }

            // Create allocator signature
            {
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Prepare recipients
        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));

            Component[] memory recipients;
            {
                Component memory recipient = Component({ claimant: claimantOne, amount: amountOne });

                recipients = new Component[](1);
                recipients[0] = recipient;
            }

            claim.witnessTypestring = witnessTypestring;
            claim.claimants = recipients;
        }

        // Execute claim
        vm.prank(arbiter);
        vm.expectRevert(
            abi.encodeWithSelector(ITheCompact.InvalidAllocation.selector, alwaysDenyingAllocator), address(theCompact)
        );
        theCompact.claim(claim);

        // Verify balances
        assertEq(address(theCompact).balance, claim.allocatedAmount);
        assertEq(recipientOne.balance, 0);
        assertEq(theCompact.balanceOf(swapper, claim.id), claim.allocatedAmount);
        assertEq(theCompact.balanceOf(recipientOne, claim.id), 0);
    }

    function test_revert_allocatorReverts() public {
        // Initialize claim struct
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = 1e18;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;
        uint256 amountOne = 1e18;
        address arbiter = 0x2222222222222222222222222222222222222222;

        // Register allocator, make deposit and create witness
        address alwaysRevertingAllocator = address(new AlwaysRevertingAllocator());
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(alwaysRevertingAllocator);
            }

            claim.id = _makeDeposit(swapper, claim.allocatedAmount, lockTag);
            claim.witness = _createCompactWitness(234);
        }

        // Create claim hash
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

        // Create signatures
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

        {
            bytes32 r;
            bytes32 vs;

            // Create sponsor signature
            {
                (r, vs) = vm.signCompact(swapperPrivateKey, digest);
                claim.sponsorSignature = abi.encodePacked(r, vs);
            }

            // Create allocator signature
            {
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Prepare recipients
        {
            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));

            Component[] memory recipients;
            {
                Component memory recipient = Component({ claimant: claimantOne, amount: amountOne });

                recipients = new Component[](1);
                recipients[0] = recipient;
            }

            claim.witnessTypestring = witnessTypestring;
            claim.claimants = recipients;
        }

        // Execute claim
        vm.prank(arbiter);
        vm.expectRevert(
            abi.encodeWithSelector(AlwaysRevertingAllocator.AlwaysReverting.selector), address(alwaysRevertingAllocator)
        );
        theCompact.claim(claim);

        // Verify balances
        assertEq(address(theCompact).balance, claim.allocatedAmount);
        assertEq(recipientOne.balance, 0);
        assertEq(theCompact.balanceOf(swapper, claim.id), claim.allocatedAmount);
        assertEq(theCompact.balanceOf(recipientOne, claim.id), 0);
    }
}
