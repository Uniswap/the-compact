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
import { ConsumerLib } from "../../src/lib/ConsumerLib.sol";
import { Setup } from "./Setup.sol";

import {
    TestParams,
    CreateClaimHashWithWitnessArgs,
    CreateBatchClaimHashWithWitnessArgs,
    BatchMultichainClaimArgs
} from "./TestHelperStructs.sol";

contract MultichainClaimTest is Setup {
    function test_multichainClaimWithWitness() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize multichain claim
        MultichainClaim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = params.deadline;
        claim.witnessTypestring = witnessTypestring;

        // Set up chain IDs
        uint256 anotherChainId = 7171717;
        uint256 thirdChainId = 41414141;

        // Register allocator and make deposits
        uint256 id;
        uint256 anotherId;
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            id = _makeDeposit(swapper, 1e18, lockTag);
            anotherId = _makeDeposit(swapper, address(token), 1e18, lockTag);

            claim.id = id;
            claim.allocatedAmount = 1e18;
        }

        // Create ids and amounts arrays
        uint256[2][] memory idsAndAmountsOne;
        uint256[2][] memory idsAndAmountsTwo;
        {
            idsAndAmountsOne = new uint256[2][](1);
            idsAndAmountsOne[0] = [id, 1e18];

            idsAndAmountsTwo = new uint256[2][](1);
            idsAndAmountsTwo[0] = [anotherId, 1e18];
        }

        // Create witness
        {
            uint256 witnessArgument = 234;
            claim.witness = _createCompactWitness(witnessArgument);
        }

        // Create element hashes
        bytes32[] memory elementHashes = new bytes32[](3);
        {
            bytes32 elementTypehash = multichainElementsWithWitnessTypehash;

            elementHashes[0] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    block.chainid,
                    _hashOfHashes(idsAndAmountsOne),
                    claim.witness
                )
            );

            elementHashes[1] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    anotherChainId,
                    _hashOfHashes(idsAndAmountsTwo),
                    claim.witness
                )
            );

            elementHashes[2] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    thirdChainId,
                    _hashOfHashes(idsAndAmountsTwo),
                    claim.witness
                )
            );
        }

        // Create multichain claim hash
        bytes32 claimHash;
        {
            bytes32 multichainTypehash = multichainCompactWithWitnessTypehash;

            claimHash = keccak256(
                abi.encode(
                    multichainTypehash,
                    claim.sponsor,
                    claim.nonce,
                    claim.expires,
                    keccak256(abi.encodePacked(elementHashes))
                )
            );
        }

        // Store initial domain separator
        bytes32 initialDomainSeparator = theCompact.DOMAIN_SEPARATOR();

        // Create signatures
        {
            bytes32 digest = _createDigest(initialDomainSeparator, claimHash);

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

        // Set up additional chains
        {
            bytes32[] memory additionalChains = new bytes32[](2);
            additionalChains[0] = elementHashes[1];
            additionalChains[1] = elementHashes[2];
            claim.additionalChains = additionalChains;
        }

        // Create components
        {
            uint256 claimantOne = abi.decode(
                abi.encodePacked(bytes12(bytes32(id)), 0x1111111111111111111111111111111111111111), (uint256)
            );
            uint256 claimantTwo = abi.decode(
                abi.encodePacked(bytes12(bytes32(id)), 0x3333333333333333333333333333333333333333), (uint256)
            );

            Component[] memory recipients;
            {
                Component memory componentOne = Component({ claimant: claimantOne, amount: 4e17 });
                Component memory componentTwo = Component({ claimant: claimantTwo, amount: 6e17 });

                recipients = new Component[](2);
                recipients[0] = componentOne;
                recipients[1] = componentTwo;
            }

            claim.claimants = recipients;
        }

        // Execute claim and verify - first part
        {
            uint256 snapshotId = vm.snapshotState();

            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.multichainClaim(claim);
                vm.snapshotGasLastCall("multichainClaimWithWitness");
                assertEq(returnedClaimHash, claimHash);

                assertEq(address(theCompact).balance, 1e18);
                assertEq(0x1111111111111111111111111111111111111111.balance, 0);
                assertEq(0x3333333333333333333333333333333333333333.balance, 0);
                assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, id), 4e17);
                assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, id), 6e17);
            }

            vm.revertToAndDelete(snapshotId);
        }

        // Change to "new chain" and execute exogenous claim
        {
            // Save current chain ID and switch to another
            uint256 notarizedChainId = abi.decode(abi.encode(block.chainid), (uint256));
            vm.chainId(anotherChainId);
            assertEq(block.chainid, anotherChainId);

            // Get new domain separator
            bytes32 anotherDomainSeparator = theCompact.DOMAIN_SEPARATOR();
            assert(initialDomainSeparator != anotherDomainSeparator);

            // Create exogenous allocator signature
            bytes memory exogenousAllocatorData;
            {
                bytes32 digest = _createDigest(anotherDomainSeparator, claimHash);

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                exogenousAllocatorData = abi.encodePacked(r, vs);
            }

            // Set up exogenous claim
            ExogenousMultichainClaim memory anotherClaim;
            {
                bytes32[] memory additionalChains = new bytes32[](2);
                additionalChains[0] = elementHashes[0];
                additionalChains[1] = elementHashes[2];

                anotherClaim.allocatorData = exogenousAllocatorData;
                anotherClaim.sponsorSignature = claim.sponsorSignature;
                anotherClaim.sponsor = claim.sponsor;
                anotherClaim.nonce = claim.nonce;
                anotherClaim.expires = claim.expires;
                anotherClaim.witness = claim.witness;
                anotherClaim.witnessTypestring = claim.witnessTypestring;
                anotherClaim.additionalChains = additionalChains;
                anotherClaim.chainIndex = 0;
                anotherClaim.notarizedChainId = notarizedChainId; // Changed from exogenousChainId to notarizedChainId
                anotherClaim.id = anotherId;
                anotherClaim.allocatedAmount = 1e18;
                anotherClaim.claimants = claim.claimants;
            }

            // Execute exogenous claim
            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.exogenousClaim(anotherClaim);
                vm.snapshotGasLastCall("exogenousMultichainClaimWithWitness");
                assertEq(returnedClaimHash, claimHash);

                assertEq(theCompact.balanceOf(swapper, anotherId), 0);
                assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, anotherId), 4e17);
                assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, anotherId), 6e17);
            }

            // Change back to original chain
            vm.chainId(notarizedChainId);
            assertEq(block.chainid, notarizedChainId);
        }
    }

    function test_BatchMultichainClaimWithWitness() public {
        BatchMultichainClaimArgs memory args;

        // Setup test parameters
        args.params.deadline = block.timestamp + 1000;

        // Initialize batch multichain claim
        args.claim.sponsor = swapper;
        args.claim.nonce = 0;
        args.claim.expires = args.params.deadline;
        args.claim.witnessTypestring = witnessTypestring;

        // Set up chain IDs
        args.anotherChainId = 7171717;

        // Register allocator and make deposits
        args.ids = new uint256[](3);
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            args.ids[0] = _makeDeposit(swapper, 1e18, lockTag);
            args.ids[1] = _makeDeposit(swapper, address(token), 1e18, lockTag);
            assertEq(theCompact.balanceOf(swapper, args.ids[1]), 1e18);

            args.ids[2] = _makeDeposit(swapper, address(anotherToken), 1e18, lockTag);
            assertEq(theCompact.balanceOf(swapper, args.ids[2]), 1e18);

            vm.stopPrank();

            assertEq(theCompact.balanceOf(swapper, args.ids[0]), 1e18);
            assertEq(theCompact.balanceOf(swapper, args.ids[1]), 1e18);
            assertEq(theCompact.balanceOf(swapper, args.ids[2]), 1e18);
        }

        // Create idsAndAmounts arrays
        {
            args.idsAndAmountsOne = new uint256[2][](1);
            args.idsAndAmountsOne[0] = [args.ids[0], 1e18];

            args.idsAndAmountsTwo = new uint256[2][](2);
            args.idsAndAmountsTwo[0] = [args.ids[1], 1e18];
            args.idsAndAmountsTwo[1] = [args.ids[2], 1e18];
        }

        // Create witness
        {
            uint256 witnessArgument = 234;
            args.claim.witness = _createCompactWitness(witnessArgument);
        }

        // Create element hashes
        {
            bytes32 elementTypehash = multichainElementsWithWitnessTypehash;

            args.allocationHashOne = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    block.chainid,
                    _hashOfHashes(args.idsAndAmountsOne),
                    args.claim.witness
                )
            );

            args.allocationHashTwo = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    args.anotherChainId,
                    _hashOfHashes(args.idsAndAmountsTwo),
                    args.claim.witness
                )
            );
        }

        // Create additional chains
        {
            bytes32[] memory additionalChains = new bytes32[](1);
            additionalChains[0] = args.allocationHashTwo;
            args.claim.additionalChains = additionalChains;
        }

        // Create multichain claim hash
        {
            bytes32 multichainTypehash = multichainCompactWithWitnessTypehash;

            args.claimHash = keccak256(
                abi.encode(
                    multichainTypehash,
                    args.claim.sponsor,
                    args.claim.nonce,
                    args.claim.expires,
                    keccak256(abi.encodePacked(args.allocationHashOne, args.allocationHashTwo))
                )
            );
        }

        // Store initial domain separator
        args.initialDomainSeparator = theCompact.DOMAIN_SEPARATOR();

        // Create signatures
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), args.claimHash);

            {
                (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
                args.claim.sponsorSignature = abi.encodePacked(r, vs);
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                args.claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Create batch claim components
        args.claim.claims = new BatchClaimComponent[](1);
        {
            Component[] memory recipients = new Component[](2);
            {
                uint256 claimantOne = abi.decode(
                    abi.encodePacked(bytes12(bytes32(args.ids[0])), 0x1111111111111111111111111111111111111111),
                    (uint256)
                );
                uint256 claimantTwo = abi.decode(
                    abi.encodePacked(bytes12(bytes32(args.ids[0])), 0x3333333333333333333333333333333333333333),
                    (uint256)
                );

                Component memory componentOne = Component({ claimant: claimantOne, amount: 4e17 });
                Component memory componentTwo = Component({ claimant: claimantTwo, amount: 6e17 });

                recipients[0] = componentOne;
                recipients[1] = componentTwo;
            }
            args.claim.claims[0] = BatchClaimComponent({ id: args.ids[0], allocatedAmount: 1e18, portions: recipients });
        }

        // Execute claim and verify - first part
        {
            uint256 snapshotId = vm.snapshotState();

            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.batchMultichainClaim(args.claim);
                vm.snapshotGasLastCall("batchMultichainClaimWithWitness");
                assertEq(returnedClaimHash, args.claimHash);

                assertEq(address(theCompact).balance, 1e18);
                assertEq(0x1111111111111111111111111111111111111111.balance, 0);
                assertEq(0x3333333333333333333333333333333333333333.balance, 0);
                assertEq(theCompact.balanceOf(swapper, args.ids[0]), 0);
                assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, args.ids[0]), 4e17);
                assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, args.ids[0]), 6e17);
            }

            vm.revertToStateAndDelete(snapshotId);
        }

        // Change to "new chain" and execute exogenous claim
        {
            // Save current chain ID and switch to another
            uint256 notarizedChainId = abi.decode(abi.encode(block.chainid), (uint256));
            vm.chainId(args.anotherChainId);
            assertEq(block.chainid, args.anotherChainId);

            assert(args.initialDomainSeparator != theCompact.DOMAIN_SEPARATOR());

            // Prepare additional chains
            bytes32[] memory additionalChains = new bytes32[](1);
            additionalChains[0] = args.allocationHashOne;

            // Create new recipients for different IDs
            BatchClaimComponent[] memory newClaims = new BatchClaimComponent[](2);
            {
                // First claim component
                {
                    uint256 claimantOne = abi.decode(
                        abi.encodePacked(bytes12(bytes32(args.ids[1])), 0x1111111111111111111111111111111111111111),
                        (uint256)
                    );

                    Component[] memory anotherRecipient = new Component[](1);
                    anotherRecipient[0] = Component({ claimant: claimantOne, amount: 1e18 });

                    newClaims[0] =
                        BatchClaimComponent({ id: args.ids[1], allocatedAmount: 1e18, portions: anotherRecipient });
                }

                // Second claim component
                {
                    uint256 claimantOne = abi.decode(
                        abi.encodePacked(bytes12(bytes32(args.ids[2])), 0x1111111111111111111111111111111111111111),
                        (uint256)
                    );
                    uint256 claimantTwo = abi.decode(
                        abi.encodePacked(bytes12(bytes32(args.ids[2])), 0x3333333333333333333333333333333333333333),
                        (uint256)
                    );

                    Component[] memory aThirdPortion = new Component[](2);
                    aThirdPortion[0] = Component({ claimant: claimantOne, amount: 4e17 });
                    aThirdPortion[1] = Component({ claimant: claimantTwo, amount: 6e17 });

                    newClaims[1] =
                        BatchClaimComponent({ id: args.ids[2], allocatedAmount: 1e18, portions: aThirdPortion });
                }
            }

            // Create exogenous allocator signature
            {
                bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), args.claimHash);
                (bytes32 r, bytes32 vs) = vm.signCompact(allocatorPrivateKey, digest);
                args.anotherClaim.allocatorData = abi.encodePacked(r, vs);
            }

            args.anotherClaim.sponsorSignature = args.claim.sponsorSignature;
            args.anotherClaim.sponsor = args.claim.sponsor;
            args.anotherClaim.nonce = args.claim.nonce;
            args.anotherClaim.expires = args.claim.expires;
            args.anotherClaim.witness = args.claim.witness;
            args.anotherClaim.witnessTypestring = "uint256 witnessArgument";
            args.anotherClaim.additionalChains = additionalChains;
            args.anotherClaim.chainIndex = 0;
            args.anotherClaim.notarizedChainId = notarizedChainId;
            args.anotherClaim.claims = newClaims;

            // Execute exogenous claim
            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.exogenousBatchClaim(args.anotherClaim);
                vm.snapshotGasLastCall("exogenousBatchMultichainClaimWithWitness");
                assertEq(returnedClaimHash, args.claimHash);
            }

            // Verify balances
            assertEq(theCompact.balanceOf(swapper, args.ids[1]), 0);
            assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, args.ids[1]), 1e18);
            assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, args.ids[2]), 4e17);
            assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, args.ids[2]), 6e17);

            // Change back to original chain
            vm.chainId(notarizedChainId);
            assertEq(block.chainid, notarizedChainId);
        }
    }

    function test_cancelMultichainClaimWithWitness() public {
        // Initialize multichain claim
        MultichainClaim memory claim;
        claim.sponsor = swapper;
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.witnessTypestring = witnessTypestring;

        // Set up chain IDs
        uint256 anotherChainId = 7171717;
        uint256 thirdChainId = 41414141;

        // Register allocator and make deposits
        uint256 id;
        uint256 anotherId;
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            id = _makeDeposit(swapper, 1e18, lockTag);
            anotherId = _makeDeposit(swapper, address(token), 1e18, lockTag);

            claim.id = id;
            claim.allocatedAmount = 1e18;
        }

        // Create ids and amounts arrays
        uint256[2][] memory idsAndAmountsOne;
        uint256[2][] memory idsAndAmountsTwo;
        {
            idsAndAmountsOne = new uint256[2][](1);
            idsAndAmountsOne[0] = [id, 1e18];

            idsAndAmountsTwo = new uint256[2][](1);
            idsAndAmountsTwo[0] = [anotherId, 1e18];
        }

        // Create witness
        {
            uint256 witnessArgument = 234;
            claim.witness = _createCompactWitness(witnessArgument);
        }

        // Create element hashes
        bytes32[] memory elementHashes = new bytes32[](3);
        {
            bytes32 elementTypehash = multichainElementsWithWitnessTypehash;

            elementHashes[0] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    block.chainid,
                    _hashOfHashes(idsAndAmountsOne),
                    claim.witness
                )
            );

            elementHashes[1] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    anotherChainId,
                    _hashOfHashes(idsAndAmountsTwo),
                    claim.witness
                )
            );

            elementHashes[2] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    thirdChainId,
                    _hashOfHashes(idsAndAmountsTwo),
                    claim.witness
                )
            );
        }

        // Create multichain claim hash
        bytes32 claimHash;
        {
            bytes32 multichainTypehash = multichainCompactWithWitnessTypehash;

            claimHash = keccak256(
                abi.encode(
                    multichainTypehash,
                    claim.sponsor,
                    claim.nonce,
                    claim.expires,
                    keccak256(abi.encodePacked(elementHashes))
                )
            );
        }

        // Store initial domain separator
        bytes32 initialDomainSeparator = theCompact.DOMAIN_SEPARATOR();

        // Create signatures
        {
            bytes32 digest = _createDigest(initialDomainSeparator, claimHash);

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

        // Set up additional chains
        {
            bytes32[] memory additionalChains = new bytes32[](2);
            additionalChains[0] = elementHashes[1];
            additionalChains[1] = elementHashes[2];
            claim.additionalChains = additionalChains;
        }

        // Create future recipients
        Component[] memory recipients;
        {
            uint256 claimantOne = abi.decode(
                abi.encodePacked(bytes12(bytes32(id)), 0x1111111111111111111111111111111111111111), (uint256)
            );
            uint256 claimantTwo = abi.decode(
                abi.encodePacked(bytes12(bytes32(anotherId)), 0x3333333333333333333333333333333333333333), (uint256)
            );

            recipients = new Component[](2);
            recipients[0] = Component({ claimant: claimantOne, amount: 4e17 });
            recipients[1] = Component({ claimant: claimantTwo, amount: 6e17 });
        }
        // Set empty claimants
        {
            claim.claimants = new Component[](0);
        }

        // Cancel claim and verify - first part
        {
            uint256 snapshotId = vm.snapshotState();

            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.multichainClaim(claim);
                vm.snapshotGasLastCall("cancelMultichainClaimWithWitness");
                assertEq(returnedClaimHash, claimHash);

                assertEq(address(theCompact).balance, 1e18);
                assertEq(theCompact.balanceOf(claim.sponsor, id), 1e18);
            }

            // Create components with recipients
            {
                claim.claimants = recipients;
            }
            // Retry claim
            {
                vm.prank(0x2222222222222222222222222222222222222222);
                vm.expectRevert(
                    abi.encodeWithSelector(ConsumerLib.InvalidNonce.selector, allocator, claim.nonce),
                    address(theCompact)
                );
                theCompact.multichainClaim(claim);
            }
            vm.revertToAndDelete(snapshotId);
        }

        // Change to "new chain" and execute exogenous claim
        {
            // Save current chain ID and switch to another
            uint256 notarizedChainId = abi.decode(abi.encode(block.chainid), (uint256));
            vm.chainId(anotherChainId);
            assertEq(block.chainid, anotherChainId);

            // Get new domain separator
            bytes32 anotherDomainSeparator = theCompact.DOMAIN_SEPARATOR();
            assert(initialDomainSeparator != anotherDomainSeparator);

            // Create exogenous allocator signature
            bytes memory exogenousAllocatorData;
            {
                bytes32 digest = _createDigest(anotherDomainSeparator, claimHash);

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                exogenousAllocatorData = abi.encodePacked(r, vs);
            }

            // Set up exogenous claim
            ExogenousMultichainClaim memory anotherClaim;
            {
                bytes32[] memory additionalChains = new bytes32[](2);
                additionalChains[0] = elementHashes[0];
                additionalChains[1] = elementHashes[2];

                anotherClaim.allocatorData = exogenousAllocatorData;
                anotherClaim.sponsorSignature = claim.sponsorSignature;
                anotherClaim.sponsor = claim.sponsor;
                anotherClaim.nonce = claim.nonce;
                anotherClaim.expires = claim.expires;
                anotherClaim.witness = claim.witness;
                anotherClaim.witnessTypestring = claim.witnessTypestring;
                anotherClaim.additionalChains = additionalChains;
                anotherClaim.chainIndex = 0;
                anotherClaim.notarizedChainId = notarizedChainId;
                anotherClaim.id = anotherId;
                anotherClaim.allocatedAmount = 1e18;
                anotherClaim.claimants = new Component[](0); // add empty claimants
            }

            // Cancel exogenous claim
            {
                assertEq(theCompact.balanceOf(swapper, anotherId), 1e18);
                assertEq(token.balanceOf(address(theCompact)), 1e18);

                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.exogenousClaim(anotherClaim);
                vm.snapshotGasLastCall("cancelExogenousMultichainClaimWithWitness");
                assertEq(returnedClaimHash, claimHash);

                assertEq(theCompact.balanceOf(swapper, anotherId), 1e18);
                assertEq(token.balanceOf(address(theCompact)), 1e18);
            }

            // Retry claim with claimants
            {
                anotherClaim.claimants = recipients;

                vm.prank(0x2222222222222222222222222222222222222222);
                vm.expectRevert(
                    abi.encodeWithSelector(ConsumerLib.InvalidNonce.selector, allocator, 0 /*nonce*/ ),
                    address(theCompact)
                );
                theCompact.exogenousClaim(anotherClaim);

                assertEq(theCompact.balanceOf(swapper, anotherId), 1e18);
                assertEq(token.balanceOf(address(theCompact)), 1e18);
            }

            // Change back to original chain
            vm.chainId(notarizedChainId);
            assertEq(block.chainid, notarizedChainId);
        }
    }

    function test_cancelBatchMultichainClaimWithWitness() public {
        BatchMultichainClaimArgs memory args;

        // Setup test parameters
        args.params.deadline = block.timestamp + 1000;

        // Initialize batch multichain claim
        args.claim.sponsor = swapper;
        args.claim.nonce = 0;
        args.claim.expires = args.params.deadline;
        args.claim.witnessTypestring = witnessTypestring;

        // Set up chain IDs
        args.anotherChainId = 7171717;

        // Register allocator and make deposits
        args.ids = new uint256[](3);
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            args.ids[0] = _makeDeposit(swapper, 1e18, lockTag);
            args.ids[1] = _makeDeposit(swapper, address(token), 1e18, lockTag);
            assertEq(theCompact.balanceOf(swapper, args.ids[1]), 1e18);

            args.ids[2] = _makeDeposit(swapper, address(anotherToken), 1e18, lockTag);
            assertEq(theCompact.balanceOf(swapper, args.ids[2]), 1e18);

            vm.stopPrank();

            assertEq(theCompact.balanceOf(swapper, args.ids[0]), 1e18);
            assertEq(theCompact.balanceOf(swapper, args.ids[1]), 1e18);
            assertEq(theCompact.balanceOf(swapper, args.ids[2]), 1e18);
        }

        // Create idsAndAmounts arrays
        {
            args.idsAndAmountsOne = new uint256[2][](1);
            args.idsAndAmountsOne[0] = [args.ids[0], 1e18];

            args.idsAndAmountsTwo = new uint256[2][](2);
            args.idsAndAmountsTwo[0] = [args.ids[1], 1e18];
            args.idsAndAmountsTwo[1] = [args.ids[2], 1e18];
        }

        // Create witness
        {
            uint256 witnessArgument = 234;
            args.claim.witness = _createCompactWitness(witnessArgument);
        }

        // Create element hashes
        {
            bytes32 elementTypehash = multichainElementsWithWitnessTypehash;

            args.allocationHashOne = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    block.chainid,
                    _hashOfHashes(args.idsAndAmountsOne),
                    args.claim.witness
                )
            );

            args.allocationHashTwo = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    args.anotherChainId,
                    _hashOfHashes(args.idsAndAmountsTwo),
                    args.claim.witness
                )
            );
        }

        // Create additional chains
        {
            bytes32[] memory additionalChains = new bytes32[](1);
            additionalChains[0] = args.allocationHashTwo;
            args.claim.additionalChains = additionalChains;
        }

        // Create multichain claim hash
        {
            bytes32 multichainTypehash = multichainCompactWithWitnessTypehash;

            args.claimHash = keccak256(
                abi.encode(
                    multichainTypehash,
                    args.claim.sponsor,
                    args.claim.nonce,
                    args.claim.expires,
                    keccak256(abi.encodePacked(args.allocationHashOne, args.allocationHashTwo))
                )
            );
        }

        // Store initial domain separator
        args.initialDomainSeparator = theCompact.DOMAIN_SEPARATOR();

        // Create signatures
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), args.claimHash);

            {
                (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
                args.claim.sponsorSignature = abi.encodePacked(r, vs);
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                args.claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Create recipients used for later
        Component[] memory recipients = new Component[](2);
        {
            {
                uint256 claimantOne = abi.decode(
                    abi.encodePacked(bytes12(bytes32(args.ids[0])), 0x1111111111111111111111111111111111111111),
                    (uint256)
                );
                uint256 claimantTwo = abi.decode(
                    abi.encodePacked(bytes12(bytes32(args.ids[0])), 0x3333333333333333333333333333333333333333),
                    (uint256)
                );

                Component memory componentOne = Component({ claimant: claimantOne, amount: 4e17 });
                Component memory componentTwo = Component({ claimant: claimantTwo, amount: 6e17 });

                recipients[0] = componentOne;
                recipients[1] = componentTwo;
            }
        }
        // Create batch claim components
        args.claim.claims = new BatchClaimComponent[](1);
        args.claim.claims[0] =
            BatchClaimComponent({ id: args.ids[0], allocatedAmount: 1e18, portions: new Component[](0) }); // Add empty recipients array

        // Cancel claim and verify - first part
        {
            uint256 snapshotId = vm.snapshotState();

            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.batchMultichainClaim(args.claim);
                vm.snapshotGasLastCall("cancelBatchMultichainClaimWithWitness");
                assertEq(returnedClaimHash, args.claimHash);

                assertEq(address(theCompact).balance, 1e18);
                assertEq(theCompact.balanceOf(swapper, args.ids[0]), 1e18);
            }

            // Try to claim again with recipients
            {
                args.claim.claims[0].portions = recipients;
                vm.prank(0x2222222222222222222222222222222222222222);
                vm.expectRevert(
                    abi.encodeWithSelector(ConsumerLib.InvalidNonce.selector, allocator, args.claim.nonce),
                    address(theCompact)
                );
                theCompact.batchMultichainClaim(args.claim);
            }

            vm.revertToStateAndDelete(snapshotId);
        }

        // Change to "new chain" and execute exogenous claim
        {
            // Save current chain ID and switch to another
            uint256 notarizedChainId = abi.decode(abi.encode(block.chainid), (uint256));
            vm.chainId(args.anotherChainId);
            assertEq(block.chainid, args.anotherChainId);

            assert(args.initialDomainSeparator != theCompact.DOMAIN_SEPARATOR());

            // Prepare additional chains
            bytes32[] memory additionalChains = new bytes32[](1);
            additionalChains[0] = args.allocationHashOne;

            // Create new recipients for different IDs
            BatchClaimComponent[] memory newClaims = new BatchClaimComponent[](2);
            {
                // First claim component
                {
                    newClaims[0] =
                        BatchClaimComponent({ id: args.ids[1], allocatedAmount: 1e18, portions: new Component[](0) }); // Add empty recipients array
                }

                // Second claim component
                {
                    newClaims[1] =
                        BatchClaimComponent({ id: args.ids[2], allocatedAmount: 1e18, portions: new Component[](0) }); // Add empty recipients array
                }
            }

            // Create exogenous allocator signature
            {
                bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), args.claimHash);
                (bytes32 r, bytes32 vs) = vm.signCompact(allocatorPrivateKey, digest);
                args.anotherClaim.allocatorData = abi.encodePacked(r, vs);
            }

            args.anotherClaim.sponsorSignature = args.claim.sponsorSignature;
            args.anotherClaim.sponsor = args.claim.sponsor;
            args.anotherClaim.nonce = args.claim.nonce;
            args.anotherClaim.expires = args.claim.expires;
            args.anotherClaim.witness = args.claim.witness;
            args.anotherClaim.witnessTypestring = "uint256 witnessArgument";
            args.anotherClaim.additionalChains = additionalChains;
            args.anotherClaim.chainIndex = 0;
            args.anotherClaim.notarizedChainId = notarizedChainId;
            args.anotherClaim.claims = newClaims;

            // Execute exogenous claim
            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.exogenousBatchClaim(args.anotherClaim);
                vm.snapshotGasLastCall("cancelExogenousBatchMultichainClaimWithWitness");
                assertEq(returnedClaimHash, args.claimHash);
            }

            // Verify balances
            assertEq(theCompact.balanceOf(swapper, args.ids[1]), 1e18);
            assertEq(theCompact.balanceOf(swapper, args.ids[2]), 1e18);

            // Try to claim again with recipients
            {
                args.anotherClaim.claims[0].portions = recipients;
                args.anotherClaim.claims[1].portions = recipients;
                vm.prank(0x2222222222222222222222222222222222222222);
                vm.expectRevert(
                    abi.encodeWithSelector(ConsumerLib.InvalidNonce.selector, allocator, args.claim.nonce),
                    address(theCompact)
                );
                theCompact.exogenousBatchClaim(args.anotherClaim);
            }

            // Change back to original chain
            vm.chainId(notarizedChainId);
            assertEq(block.chainid, notarizedChainId);
        }
    }

    function test_multichainClaim() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize multichain claim
        MultichainClaim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = params.deadline;
        claim.witnessTypestring = "";

        // Set up chain IDs
        uint256 anotherChainId = 7171717;
        uint256 thirdChainId = 41414141;

        // Register allocator and make deposits
        uint256 id;
        uint256 anotherId;
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            id = _makeDeposit(swapper, 1e18, lockTag);
            anotherId = _makeDeposit(swapper, address(token), 1e18, lockTag);

            claim.id = id;
            claim.allocatedAmount = 1e18;
        }

        // Create ids and amounts arrays
        uint256[2][] memory idsAndAmountsOne;
        uint256[2][] memory idsAndAmountsTwo;
        {
            idsAndAmountsOne = new uint256[2][](1);
            idsAndAmountsOne[0] = [id, 1e18];

            idsAndAmountsTwo = new uint256[2][](1);
            idsAndAmountsTwo[0] = [anotherId, 1e18];
        }

        // Create element hashes
        bytes32[] memory elementHashes = new bytes32[](3);
        {
            bytes32 elementTypehash = multichainElementsTypehash;

            elementHashes[0] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    block.chainid,
                    _hashOfHashes(idsAndAmountsOne)
                )
            );

            elementHashes[1] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    anotherChainId,
                    _hashOfHashes(idsAndAmountsTwo)
                )
            );

            elementHashes[2] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    thirdChainId,
                    _hashOfHashes(idsAndAmountsTwo)
                )
            );
        }

        // Create multichain claim hash
        bytes32 claimHash;
        {
            bytes32 multichainTypehash = multichainCompactTypehash;

            claimHash = keccak256(
                abi.encode(
                    multichainTypehash,
                    claim.sponsor,
                    claim.nonce,
                    claim.expires,
                    keccak256(abi.encodePacked(elementHashes))
                )
            );
        }

        // Store initial domain separator
        bytes32 initialDomainSeparator = theCompact.DOMAIN_SEPARATOR();

        // Create signatures
        {
            bytes32 digest = _createDigest(initialDomainSeparator, claimHash);

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

        // Set up additional chains
        {
            bytes32[] memory additionalChains = new bytes32[](2);
            additionalChains[0] = elementHashes[1];
            additionalChains[1] = elementHashes[2];
            claim.additionalChains = additionalChains;
        }

        // Create components
        {
            uint256 claimantOne = abi.decode(
                abi.encodePacked(bytes12(bytes32(id)), 0x1111111111111111111111111111111111111111), (uint256)
            );
            uint256 claimantTwo = abi.decode(
                abi.encodePacked(bytes12(bytes32(id)), 0x3333333333333333333333333333333333333333), (uint256)
            );

            Component[] memory recipients;
            {
                Component memory componentOne = Component({ claimant: claimantOne, amount: 4e17 });
                Component memory componentTwo = Component({ claimant: claimantTwo, amount: 6e17 });

                recipients = new Component[](2);
                recipients[0] = componentOne;
                recipients[1] = componentTwo;
            }

            claim.claimants = recipients;
        }

        // Execute claim and verify - first part
        {
            uint256 snapshotId = vm.snapshotState();

            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.multichainClaim(claim);
                vm.snapshotGasLastCall("multichainClaim");
                assertEq(returnedClaimHash, claimHash);

                assertEq(address(theCompact).balance, 1e18);
                assertEq(0x1111111111111111111111111111111111111111.balance, 0);
                assertEq(0x3333333333333333333333333333333333333333.balance, 0);
                assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, id), 4e17);
                assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, id), 6e17);
            }

            vm.revertToAndDelete(snapshotId);
        }

        // Change to "new chain" and execute exogenous claim
        {
            // Save current chain ID and switch to another
            uint256 notarizedChainId = abi.decode(abi.encode(block.chainid), (uint256));
            vm.chainId(anotherChainId);
            assertEq(block.chainid, anotherChainId);

            // Get new domain separator
            bytes32 anotherDomainSeparator = theCompact.DOMAIN_SEPARATOR();
            assert(initialDomainSeparator != anotherDomainSeparator);

            // Create exogenous allocator signature
            bytes memory exogenousAllocatorData;
            {
                bytes32 digest = _createDigest(anotherDomainSeparator, claimHash);

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                exogenousAllocatorData = abi.encodePacked(r, vs);
            }

            // Set up exogenous claim
            ExogenousMultichainClaim memory anotherClaim;
            {
                bytes32[] memory additionalChains = new bytes32[](2);
                additionalChains[0] = elementHashes[0];
                additionalChains[1] = elementHashes[2];

                anotherClaim.allocatorData = exogenousAllocatorData;
                anotherClaim.sponsorSignature = claim.sponsorSignature;
                anotherClaim.sponsor = claim.sponsor;
                anotherClaim.nonce = claim.nonce;
                anotherClaim.expires = claim.expires;
                anotherClaim.witness = bytes32(0); // empty witness
                anotherClaim.witnessTypestring = ""; // empty witness typestring
                anotherClaim.additionalChains = additionalChains;
                anotherClaim.chainIndex = 0;
                anotherClaim.notarizedChainId = notarizedChainId; // Changed from exogenousChainId to notarizedChainId
                anotherClaim.id = anotherId;
                anotherClaim.allocatedAmount = 1e18;
                anotherClaim.claimants = claim.claimants;
            }

            // Execute exogenous claim
            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.exogenousClaim(anotherClaim);
                vm.snapshotGasLastCall("exogenousMultichainClaim");
                assertEq(returnedClaimHash, claimHash);

                assertEq(theCompact.balanceOf(swapper, anotherId), 0);
                assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, anotherId), 4e17);
                assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, anotherId), 6e17);
            }

            // Change back to original chain
            vm.chainId(notarizedChainId);
            assertEq(block.chainid, notarizedChainId);
        }
    }

    function test_BatchMultichainClaim() public {
        BatchMultichainClaimArgs memory args;

        // Setup test parameters
        args.params.deadline = block.timestamp + 1000;

        // Initialize batch multichain claim
        args.claim.sponsor = swapper;
        args.claim.nonce = 0;
        args.claim.expires = args.params.deadline;
        args.claim.witnessTypestring = "";

        // Set up chain IDs
        args.anotherChainId = 7171717;

        // Register allocator and make deposits
        args.ids = new uint256[](3);
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            args.ids[0] = _makeDeposit(swapper, 1e18, lockTag);
            args.ids[1] = _makeDeposit(swapper, address(token), 1e18, lockTag);
            assertEq(theCompact.balanceOf(swapper, args.ids[1]), 1e18);

            args.ids[2] = _makeDeposit(swapper, address(anotherToken), 1e18, lockTag);
            assertEq(theCompact.balanceOf(swapper, args.ids[2]), 1e18);

            vm.stopPrank();

            assertEq(theCompact.balanceOf(swapper, args.ids[0]), 1e18);
            assertEq(theCompact.balanceOf(swapper, args.ids[1]), 1e18);
            assertEq(theCompact.balanceOf(swapper, args.ids[2]), 1e18);
        }

        // Create idsAndAmounts arrays
        {
            args.idsAndAmountsOne = new uint256[2][](1);
            args.idsAndAmountsOne[0] = [args.ids[0], 1e18];

            args.idsAndAmountsTwo = new uint256[2][](2);
            args.idsAndAmountsTwo[0] = [args.ids[1], 1e18];
            args.idsAndAmountsTwo[1] = [args.ids[2], 1e18];
        }

        // Create element hashes
        {
            bytes32 elementTypehash = multichainElementsTypehash;

            args.allocationHashOne = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    block.chainid,
                    _hashOfHashes(args.idsAndAmountsOne)
                )
            );

            args.allocationHashTwo = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    args.anotherChainId,
                    _hashOfHashes(args.idsAndAmountsTwo)
                )
            );
        }

        // Create additional chains
        {
            bytes32[] memory additionalChains = new bytes32[](1);
            additionalChains[0] = args.allocationHashTwo;
            args.claim.additionalChains = additionalChains;
        }

        // Create multichain claim hash
        {
            bytes32 multichainTypehash = multichainCompactTypehash;

            args.claimHash = keccak256(
                abi.encode(
                    multichainTypehash,
                    args.claim.sponsor,
                    args.claim.nonce,
                    args.claim.expires,
                    keccak256(abi.encodePacked(args.allocationHashOne, args.allocationHashTwo))
                )
            );
        }

        // Store initial domain separator
        args.initialDomainSeparator = theCompact.DOMAIN_SEPARATOR();

        // Create signatures
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), args.claimHash);

            {
                (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
                args.claim.sponsorSignature = abi.encodePacked(r, vs);
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                args.claim.allocatorData = abi.encodePacked(r, vs);
            }
        }

        // Create batch claim components
        args.claim.claims = new BatchClaimComponent[](1);
        {
            Component[] memory recipients = new Component[](2);
            {
                uint256 claimantOne = abi.decode(
                    abi.encodePacked(bytes12(bytes32(args.ids[0])), 0x1111111111111111111111111111111111111111),
                    (uint256)
                );
                uint256 claimantTwo = abi.decode(
                    abi.encodePacked(bytes12(bytes32(args.ids[0])), 0x3333333333333333333333333333333333333333),
                    (uint256)
                );

                Component memory componentOne = Component({ claimant: claimantOne, amount: 4e17 });
                Component memory componentTwo = Component({ claimant: claimantTwo, amount: 6e17 });

                recipients[0] = componentOne;
                recipients[1] = componentTwo;
            }
            args.claim.claims[0] = BatchClaimComponent({ id: args.ids[0], allocatedAmount: 1e18, portions: recipients });
        }

        // Execute claim and verify - first part
        {
            uint256 snapshotId = vm.snapshotState();

            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.batchMultichainClaim(args.claim);
                vm.snapshotGasLastCall("batchMultichainClaim");
                assertEq(returnedClaimHash, args.claimHash);

                assertEq(address(theCompact).balance, 1e18);
                assertEq(0x1111111111111111111111111111111111111111.balance, 0);
                assertEq(0x3333333333333333333333333333333333333333.balance, 0);
                assertEq(theCompact.balanceOf(swapper, args.ids[0]), 0);
                assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, args.ids[0]), 4e17);
                assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, args.ids[0]), 6e17);
            }

            vm.revertToStateAndDelete(snapshotId);
        }

        // Change to "new chain" and execute exogenous claim
        {
            // Save current chain ID and switch to another
            uint256 notarizedChainId = abi.decode(abi.encode(block.chainid), (uint256));
            vm.chainId(args.anotherChainId);
            assertEq(block.chainid, args.anotherChainId);

            assert(args.initialDomainSeparator != theCompact.DOMAIN_SEPARATOR());

            // Prepare additional chains
            bytes32[] memory additionalChains = new bytes32[](1);
            additionalChains[0] = args.allocationHashOne;

            // Create new recipients for different IDs
            BatchClaimComponent[] memory newClaims = new BatchClaimComponent[](2);
            {
                // First claim component
                {
                    uint256 claimantOne = abi.decode(
                        abi.encodePacked(bytes12(bytes32(args.ids[1])), 0x1111111111111111111111111111111111111111),
                        (uint256)
                    );

                    Component[] memory anotherRecipient = new Component[](1);
                    anotherRecipient[0] = Component({ claimant: claimantOne, amount: 1e18 });

                    newClaims[0] =
                        BatchClaimComponent({ id: args.ids[1], allocatedAmount: 1e18, portions: anotherRecipient });
                }

                // Second claim component
                {
                    uint256 claimantOne = abi.decode(
                        abi.encodePacked(bytes12(bytes32(args.ids[2])), 0x1111111111111111111111111111111111111111),
                        (uint256)
                    );
                    uint256 claimantTwo = abi.decode(
                        abi.encodePacked(bytes12(bytes32(args.ids[2])), 0x3333333333333333333333333333333333333333),
                        (uint256)
                    );

                    Component[] memory aThirdPortion = new Component[](2);
                    aThirdPortion[0] = Component({ claimant: claimantOne, amount: 4e17 });
                    aThirdPortion[1] = Component({ claimant: claimantTwo, amount: 6e17 });

                    newClaims[1] =
                        BatchClaimComponent({ id: args.ids[2], allocatedAmount: 1e18, portions: aThirdPortion });
                }
            }

            // Create exogenous allocator signature
            {
                bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), args.claimHash);
                (bytes32 r, bytes32 vs) = vm.signCompact(allocatorPrivateKey, digest);
                args.anotherClaim.allocatorData = abi.encodePacked(r, vs);
            }

            args.anotherClaim.sponsorSignature = args.claim.sponsorSignature;
            args.anotherClaim.sponsor = args.claim.sponsor;
            args.anotherClaim.nonce = args.claim.nonce;
            args.anotherClaim.expires = args.claim.expires;
            args.anotherClaim.witness = bytes32(0); // empty witness
            args.anotherClaim.witnessTypestring = ""; // empty witness typestring
            args.anotherClaim.additionalChains = additionalChains;
            args.anotherClaim.chainIndex = 0;
            args.anotherClaim.notarizedChainId = notarizedChainId;
            args.anotherClaim.claims = newClaims;

            // Execute exogenous claim
            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.exogenousBatchClaim(args.anotherClaim);
                vm.snapshotGasLastCall("exogenousBatchMultichainClaim");
                assertEq(returnedClaimHash, args.claimHash);
            }

            // Verify balances
            assertEq(theCompact.balanceOf(swapper, args.ids[1]), 0);
            assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, args.ids[1]), 1e18);
            assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, args.ids[2]), 4e17);
            assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, args.ids[2]), 6e17);

            // Change back to original chain
            vm.chainId(notarizedChainId);
            assertEq(block.chainid, notarizedChainId);
        }
    }

    function test_revert_ChainIndexOutOfRange() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize multichain claim
        MultichainClaim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = params.deadline;
        claim.witnessTypestring = "";

        // Set up chain IDs
        uint256 anotherChainId = 7171717;
        uint256 thirdChainId = 41414141;

        // Register allocator and make deposits
        uint256 id;
        uint256 anotherId;
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }

            id = _makeDeposit(swapper, 1e18, lockTag);
            anotherId = _makeDeposit(swapper, address(token), 1e18, lockTag);

            claim.id = id;
            claim.allocatedAmount = 1e18;
        }

        // Create ids and amounts arrays
        uint256[2][] memory idsAndAmountsOne;
        uint256[2][] memory idsAndAmountsTwo;
        {
            idsAndAmountsOne = new uint256[2][](1);
            idsAndAmountsOne[0] = [id, 1e18];

            idsAndAmountsTwo = new uint256[2][](1);
            idsAndAmountsTwo[0] = [anotherId, 1e18];
        }

        // Create element hashes
        bytes32[] memory elementHashes = new bytes32[](3);
        {
            bytes32 elementTypehash = multichainElementsTypehash;

            elementHashes[0] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    block.chainid,
                    _hashOfHashes(idsAndAmountsOne)
                )
            );

            elementHashes[1] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    anotherChainId,
                    _hashOfHashes(idsAndAmountsTwo)
                )
            );

            elementHashes[2] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    thirdChainId,
                    _hashOfHashes(idsAndAmountsTwo)
                )
            );
        }

        // Create multichain claim hash
        bytes32 claimHash;
        {
            bytes32 multichainTypehash = multichainCompactTypehash;

            claimHash = keccak256(
                abi.encode(
                    multichainTypehash,
                    claim.sponsor,
                    claim.nonce,
                    claim.expires,
                    keccak256(abi.encodePacked(elementHashes))
                )
            );
        }

        // Store initial domain separator
        bytes32 initialDomainSeparator = theCompact.DOMAIN_SEPARATOR();

        // Create signatures
        {
            bytes32 digest = _createDigest(initialDomainSeparator, claimHash);

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

        // Set up additional chains
        {
            bytes32[] memory additionalChains = new bytes32[](2);
            additionalChains[0] = elementHashes[1];
            additionalChains[1] = elementHashes[2];
            claim.additionalChains = additionalChains;
        }

        // Create components
        {
            uint256 claimantOne = abi.decode(
                abi.encodePacked(bytes12(bytes32(id)), 0x1111111111111111111111111111111111111111), (uint256)
            );
            uint256 claimantTwo = abi.decode(
                abi.encodePacked(bytes12(bytes32(id)), 0x3333333333333333333333333333333333333333), (uint256)
            );

            Component[] memory recipients;
            {
                Component memory componentOne = Component({ claimant: claimantOne, amount: 4e17 });
                Component memory componentTwo = Component({ claimant: claimantTwo, amount: 6e17 });

                recipients = new Component[](2);
                recipients[0] = componentOne;
                recipients[1] = componentTwo;
            }

            claim.claimants = recipients;
        }

        // Execute claim and verify - first part
        {
            uint256 snapshotId = vm.snapshotState();

            {
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.multichainClaim(claim);
                vm.snapshotGasLastCall("multichainClaim");
                assertEq(returnedClaimHash, claimHash);

                assertEq(address(theCompact).balance, 1e18);
                assertEq(0x1111111111111111111111111111111111111111.balance, 0);
                assertEq(0x3333333333333333333333333333333333333333.balance, 0);
                assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, id), 4e17);
                assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, id), 6e17);
            }

            vm.revertToAndDelete(snapshotId);
        }

        // Change to "new chain" and execute exogenous claim
        {
            // Save current chain ID and switch to another
            uint256 notarizedChainId = abi.decode(abi.encode(block.chainid), (uint256));
            vm.chainId(anotherChainId);
            assertEq(block.chainid, anotherChainId);

            // Get new domain separator
            bytes32 anotherDomainSeparator = theCompact.DOMAIN_SEPARATOR();
            assert(initialDomainSeparator != anotherDomainSeparator);

            // Create exogenous allocator signature
            bytes memory exogenousAllocatorData;
            {
                bytes32 digest = _createDigest(anotherDomainSeparator, claimHash);

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                exogenousAllocatorData = abi.encodePacked(r, vs);
            }

            // Set up exogenous claim
            ExogenousMultichainClaim memory anotherClaim;
            {
                bytes32[] memory additionalChains = new bytes32[](2);
                additionalChains[0] = elementHashes[0];
                additionalChains[1] = elementHashes[2];

                anotherClaim.allocatorData = exogenousAllocatorData;
                anotherClaim.sponsorSignature = claim.sponsorSignature;
                anotherClaim.sponsor = claim.sponsor;
                anotherClaim.nonce = claim.nonce;
                anotherClaim.expires = claim.expires;
                anotherClaim.witness = bytes32(0); // empty witness
                anotherClaim.witnessTypestring = ""; // empty witness typestring
                anotherClaim.additionalChains = additionalChains;
                anotherClaim.chainIndex = 2; // index out of range
                anotherClaim.notarizedChainId = notarizedChainId; // Changed from exogenousChainId to notarizedChainId
                anotherClaim.id = anotherId;
                anotherClaim.allocatedAmount = 1e18;
                anotherClaim.claimants = claim.claimants;
            }

            // Execute exogenous claim
            {
                vm.prank(0x2222222222222222222222222222222222222222);
                vm.expectRevert(abi.encodeWithSelector(ITheCompact.ChainIndexOutOfRange.selector));
                theCompact.exogenousClaim(anotherClaim);
            }

            // Change back to original chain
            vm.chainId(notarizedChainId);
            assertEq(block.chainid, notarizedChainId);
        }
    }

    function test_revert_notMultichainScope() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.ChainSpecific;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize multichain claim
        MultichainClaim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = params.deadline;
        claim.witnessTypestring = witnessTypestring;

        // Set up chain IDs
        uint256 anotherChainId = 7171717;
        uint256 thirdChainId = 41414141;

        // Register allocator and make deposits
        uint256 id;
        uint256 anotherId;
        {
            bytes12 lockTag;
            {
                uint96 allocatorId;
                (allocatorId, lockTag) = _registerAllocator(allocator);
                // Change lockTag to `chainSpecific`
                lockTag = lockTag | bytes12(bytes1(uint8(128)));
            }

            id = _makeDeposit(swapper, 1e18, lockTag);
            anotherId = _makeDeposit(swapper, address(token), 1e18, lockTag);

            claim.id = id;
            claim.allocatedAmount = 1e18;
        }

        // Create ids and amounts arrays
        uint256[2][] memory idsAndAmountsOne;
        uint256[2][] memory idsAndAmountsTwo;
        {
            idsAndAmountsOne = new uint256[2][](1);
            idsAndAmountsOne[0] = [id, 1e18];

            idsAndAmountsTwo = new uint256[2][](1);
            idsAndAmountsTwo[0] = [anotherId, 1e18];
        }

        // Create witness
        {
            uint256 witnessArgument = 234;
            claim.witness = _createCompactWitness(witnessArgument);
        }

        // Create element hashes
        bytes32[] memory elementHashes = new bytes32[](3);
        {
            bytes32 elementTypehash = multichainElementsWithWitnessTypehash;

            elementHashes[0] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    block.chainid,
                    _hashOfHashes(idsAndAmountsOne),
                    claim.witness
                )
            );

            elementHashes[1] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    anotherChainId,
                    _hashOfHashes(idsAndAmountsTwo),
                    claim.witness
                )
            );

            elementHashes[2] = keccak256(
                abi.encode(
                    elementTypehash,
                    0x2222222222222222222222222222222222222222, // arbiter
                    thirdChainId,
                    _hashOfHashes(idsAndAmountsTwo),
                    claim.witness
                )
            );
        }

        // Create multichain claim hash
        bytes32 claimHash;
        {
            bytes32 multichainTypehash = multichainCompactWithWitnessTypehash;

            claimHash = keccak256(
                abi.encode(
                    multichainTypehash,
                    claim.sponsor,
                    claim.nonce,
                    claim.expires,
                    keccak256(abi.encodePacked(elementHashes))
                )
            );
        }

        // Store initial domain separator
        bytes32 initialDomainSeparator = theCompact.DOMAIN_SEPARATOR();

        // Create signatures
        {
            bytes32 digest = _createDigest(initialDomainSeparator, claimHash);

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

        // Set up additional chains
        {
            bytes32[] memory additionalChains = new bytes32[](2);
            additionalChains[0] = elementHashes[1];
            additionalChains[1] = elementHashes[2];
            claim.additionalChains = additionalChains;
        }

        // Create components
        {
            uint256 claimantOne = abi.decode(
                abi.encodePacked(bytes12(bytes32(id)), 0x1111111111111111111111111111111111111111), (uint256)
            );
            uint256 claimantTwo = abi.decode(
                abi.encodePacked(bytes12(bytes32(id)), 0x3333333333333333333333333333333333333333), (uint256)
            );

            Component[] memory recipients;
            {
                Component memory componentOne = Component({ claimant: claimantOne, amount: 4e17 });
                Component memory componentTwo = Component({ claimant: claimantTwo, amount: 6e17 });

                recipients = new Component[](2);
                recipients[0] = componentOne;
                recipients[1] = componentTwo;
            }

            claim.claimants = recipients;
        }

        // Execute claim and verify - first part
        {
            uint256 snapshotId = vm.snapshotState();

            {
                // The home chain ID works with tokens scoped to `ChainSpecific`
                vm.prank(0x2222222222222222222222222222222222222222);
                bytes32 returnedClaimHash = theCompact.multichainClaim(claim);
                assertEq(returnedClaimHash, claimHash);

                assertEq(address(theCompact).balance, 1e18);
                assertEq(0x1111111111111111111111111111111111111111.balance, 0);
                assertEq(0x3333333333333333333333333333333333333333.balance, 0);
                assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, id), 4e17);
                assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, id), 6e17);
            }

            vm.revertToAndDelete(snapshotId);
        }

        // Change to "new chain" and execute exogenous claim
        {
            // Save current chain ID and switch to another
            uint256 notarizedChainId = abi.decode(abi.encode(block.chainid), (uint256));
            vm.chainId(anotherChainId);
            assertEq(block.chainid, anotherChainId);

            // Get new domain separator
            bytes32 anotherDomainSeparator = theCompact.DOMAIN_SEPARATOR();
            assert(initialDomainSeparator != anotherDomainSeparator);

            // Create exogenous allocator signature
            bytes memory exogenousAllocatorData;
            {
                bytes32 digest = _createDigest(anotherDomainSeparator, claimHash);

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
                exogenousAllocatorData = abi.encodePacked(r, vs);
            }

            // Set up exogenous claim
            ExogenousMultichainClaim memory anotherClaim;
            {
                bytes32[] memory additionalChains = new bytes32[](2);
                additionalChains[0] = elementHashes[0];
                additionalChains[1] = elementHashes[2];

                anotherClaim.allocatorData = exogenousAllocatorData;
                anotherClaim.sponsorSignature = claim.sponsorSignature;
                anotherClaim.sponsor = claim.sponsor;
                anotherClaim.nonce = claim.nonce;
                anotherClaim.expires = claim.expires;
                anotherClaim.witness = claim.witness;
                anotherClaim.witnessTypestring = claim.witnessTypestring;
                anotherClaim.additionalChains = additionalChains;
                anotherClaim.chainIndex = 0;
                anotherClaim.notarizedChainId = notarizedChainId; // Changed from exogenousChainId to notarizedChainId
                anotherClaim.id = anotherId;
                anotherClaim.allocatedAmount = 1e18;
                anotherClaim.claimants = claim.claimants;
            }

            // Execute exogenous claim
            {
                // The exogenous chain ID does not work with tokens scoped to `ChainSpecific`
                vm.prank(0x2222222222222222222222222222222222222222);
                vm.expectRevert(
                    abi.encodeWithSelector(ITheCompact.InvalidScope.selector, anotherId), address(theCompact)
                );
                theCompact.exogenousClaim(anotherClaim);
            }

            // Change back to original chain
            vm.chainId(notarizedChainId);
            assertEq(block.chainid, notarizedChainId);
        }
    }
}
