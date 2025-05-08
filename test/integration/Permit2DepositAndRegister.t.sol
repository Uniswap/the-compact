// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

import { CompactCategory } from "../../src/types/CompactCategory.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { Component } from "../../src/types/Components.sol";
import { Claim } from "../../src/types/Claims.sol";
import { BatchClaim } from "../../src/types/BatchClaims.sol";

import { EIP712, Setup } from "./Setup.sol";

import {
    LockDetails,
    TestParams,
    CreateClaimHashWithWitnessArgs,
    CreateBatchClaimHashWithWitnessArgs,
    CreatePermitBatchWitnessDigestArgs,
    SetupPermitCallExpectationArgs,
    DepositDetails,
    BatchClaimComponent
} from "./TestHelperStructs.sol";

contract Permit2DepositAndRegisterTest is Setup {
    function test_depositAndRegisterWithWitnessViaPermit2ThenClaim() public virtual {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize claim
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = params.amount;
        claim.witnessTypestring = witnessTypestring;
        claim.sponsorSignature = "";

        // Create domain separator
        bytes32 domainSeparator;
        {
            domainSeparator = keccak256(
                abi.encode(permit2EIP712DomainHash, keccak256(bytes("Permit2")), block.chainid, address(permit2))
            );
            assertEq(domainSeparator, EIP712(permit2).DOMAIN_SEPARATOR());
        }

        // Create witness and id
        LockDetails memory expectedDetails;
        uint96 allocatorId;
        {
            // Register allocator and setup
            bytes12 lockTag;
            {
                (allocatorId, lockTag) = _registerAllocator(allocator);
            }
            expectedDetails.lockTag = lockTag;

            uint256 witnessArgument = 234;
            claim.witness = _createCompactWitness(witnessArgument);
            claim.id = uint256(bytes32(lockTag)) | uint256(uint160(address(token)));
        }

        // Create claim hash
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = 0x2222222222222222222222222222222222222222;
            args.sponsor = claim.sponsor;
            args.nonce = claim.nonce;
            args.expires = claim.expires;
            args.id = claim.id;
            args.amount = claim.allocatedAmount;
            args.witness = claim.witness;

            claimHash = _createClaimHashWithWitness(args);
        }

        // Create activation typehash and permit signature
        bytes memory signature;
        ISignatureTransfer.PermitTransferFrom memory permit;
        {
            bytes32 activationTypehash = keccak256(
                bytes(
                    string.concat("Activation(address activator,uint256 id,Compact compact)", compactWitnessTypestring)
                )
            );

            {
                bytes32 tokenPermissionsHash = keccak256(
                    abi.encode(
                        keccak256("TokenPermissions(address token,uint256 amount)"), address(token), params.amount
                    )
                );

                bytes32 permitWitnessHash;
                {
                    bytes32 activationHash =
                        keccak256(abi.encode(activationTypehash, address(1010), claim.id, claimHash));

                    permitWitnessHash = keccak256(
                        abi.encode(
                            keccak256(
                                "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Activation witness)Activation(address activator,uint256 id,Compact compact)Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)Mandate(uint256 witnessArgument)TokenPermissions(address token,uint256 amount)"
                            ),
                            tokenPermissionsHash,
                            address(theCompact), // spender
                            params.nonce,
                            params.deadline,
                            activationHash
                        )
                    );
                }

                bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, permitWitnessHash));

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(swapperPrivateKey, digest);
                signature = abi.encodePacked(r, vs);
            }

            // Create permit
            {
                permit = ISignatureTransfer.PermitTransferFrom({
                    permitted: ISignatureTransfer.TokenPermissions({ token: address(token), amount: params.amount }),
                    nonce: params.nonce,
                    deadline: params.deadline
                });
            }

            // Setup expectation for permitWitnessTransferFrom call
            {
                bytes32 activationHash = keccak256(abi.encode(activationTypehash, address(1010), claim.id, claimHash));

                vm.expectCall(
                    address(permit2),
                    abi.encodeWithSignature(
                        "permitWitnessTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes32,string,bytes)",
                        permit,
                        ISignatureTransfer.SignatureTransferDetails({
                            to: address(theCompact),
                            requestedAmount: params.amount
                        }),
                        swapper,
                        activationHash,
                        "Activation witness)Activation(address activator,uint256 id,Compact compact)Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)Mandate(uint256 witnessArgument)TokenPermissions(address token,uint256 amount)",
                        signature
                    )
                );
            }
        }

        // Deposit and register
        {
            vm.prank(address(1010));
            uint256 returnedId = theCompact.depositERC20AndRegisterViaPermit2(
                permit,
                swapper,
                expectedDetails.lockTag,
                claimHash,
                CompactCategory.Compact,
                witnessTypestring,
                signature
            );
            vm.snapshotGasLastCall("depositAndRegisterViaPermit2");
            assertEq(returnedId, claim.id);

            bool isActive;
            uint256 registeredAt;
            (isActive, registeredAt) = theCompact.getRegistrationStatus(swapper, claimHash, compactWithWitnessTypehash);
            assert(isActive);
            assertEq(registeredAt, block.timestamp);
        }

        // Verify lock details
        {
            expectedDetails.token = address(token);
            expectedDetails.allocator = allocator;
            expectedDetails.resetPeriod = params.resetPeriod;
            expectedDetails.scope = params.scope;

            _verifyLockDetails(claim.id, params, expectedDetails, allocatorId);

            assertEq(token.balanceOf(address(theCompact)), params.amount);
            assertEq(theCompact.balanceOf(swapper, claim.id), params.amount);
        }

        // Create allocator signature
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);

            bytes32 r;
            bytes32 vs;
            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            claim.allocatorData = abi.encodePacked(r, vs);
        }

        uint256 amountOne = 4e17;
        uint256 amountTwo = 6e17;

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
                Component memory splitOne = Component({ claimant: claimantOne, amount: amountOne });
                Component memory splitTwo = Component({ claimant: claimantTwo, amount: amountTwo });

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
            vm.snapshotGasLastCall("claim");
            assertEq(returnedClaimHash, claimHash);
        }

        // Verify balances
        assertEq(token.balanceOf(address(theCompact)), params.amount);
        assertEq(theCompact.balanceOf(swapper, claim.id), 0);
        assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, claim.id), amountOne);
        assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, claim.id), amountTwo);
    }

    function test_batchDepositAndRegisterWithWitnessViaPermit2ThenClaim() public virtual {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Initialize claim data
        BatchClaim memory claim;
        claim.sponsor = swapper;
        claim.nonce = params.nonce;
        claim.expires = block.timestamp + 1000;
        claim.witnessTypestring = witnessTypestring;

        // Register allocator and setup basic variables
        uint96 allocatorId;
        bytes12 lockTag;
        {
            (allocatorId, lockTag) = _registerAllocator(allocator);
        }

        // Create domain separator
        bytes32 domainSeparator;
        {
            domainSeparator = keccak256(
                abi.encode(permit2EIP712DomainHash, keccak256(bytes("Permit2")), block.chainid, address(permit2))
            );
            assertEq(domainSeparator, EIP712(permit2).DOMAIN_SEPARATOR());
        }

        // Create witness and typestring
        bytes32 typehash;
        {
            claim.witness = _createCompactWitness(234);

            string memory typestring =
                "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)";
            typehash = keccak256(bytes(typestring));
        }

        // Create ids and idsAndAmounts
        uint256[] memory ids;
        uint256[2][] memory idsAndAmounts;
        {
            uint256 id = (uint256(params.scope) << 255) | (uint256(params.resetPeriod) << 252)
                | (uint256(allocatorId) << 160) | uint256(uint160(address(0)));
            uint256 anotherId = (uint256(params.scope) << 255) | (uint256(params.resetPeriod) << 252)
                | (uint256(allocatorId) << 160) | uint256(uint160(address(token)));
            uint256 aThirdId = (uint256(params.scope) << 255) | (uint256(params.resetPeriod) << 252)
                | (uint256(allocatorId) << 160) | uint256(uint160(address(anotherToken)));

            ids = new uint256[](3);
            idsAndAmounts = new uint256[2][](3);

            ids[0] = id;
            ids[1] = anotherId;
            ids[2] = aThirdId;

            idsAndAmounts[0][0] = id;
            idsAndAmounts[0][1] = 1e18; // amount
            idsAndAmounts[1][0] = anotherId;
            idsAndAmounts[1][1] = 1e18; // anotherAmount
            idsAndAmounts[2][0] = aThirdId;
            idsAndAmounts[2][1] = 1e18; // aThirdAmount
        }

        // Create claim hash
        bytes32 claimHash;
        {
            CreateBatchClaimHashWithWitnessArgs memory args;
            {
                args.typehash = typehash;
                args.arbiter = 0x2222222222222222222222222222222222222222;
                args.sponsor = claim.sponsor;
                args.nonce = params.nonce;
                args.expires = claim.expires;
                args.idsAndAmountsHash = keccak256(abi.encodePacked(idsAndAmounts));
                args.witness = claim.witness;
            }

            claimHash = _createBatchClaimHashWithWitness(args);
        }

        // Create activation typehash
        bytes32 activationTypehash;
        {
            string memory typestring =
                "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)";
            activationTypehash = keccak256(
                bytes(
                    string.concat("BatchActivation(address activator,uint256[] ids,BatchCompact compact)", typestring)
                )
            );
        }

        // Create token permissions and signature
        ISignatureTransfer.TokenPermissions[] memory tokenPermissions;
        bytes memory signature;
        {
            tokenPermissions = new ISignatureTransfer.TokenPermissions[](3);
            tokenPermissions[0] = ISignatureTransfer.TokenPermissions({ token: address(0), amount: 1e18 });
            tokenPermissions[1] = ISignatureTransfer.TokenPermissions({ token: address(token), amount: 1e18 });
            tokenPermissions[2] = ISignatureTransfer.TokenPermissions({ token: address(anotherToken), amount: 1e18 });

            // Create signature
            {
                bytes32 tokenPermissionsHash;
                {
                    bytes32[] memory tokenPermissionsHashes = new bytes32[](2);

                    tokenPermissionsHashes[0] = keccak256(
                        abi.encode(keccak256("TokenPermissions(address token,uint256 amount)"), tokenPermissions[0])
                    );
                    tokenPermissionsHashes[0] = keccak256(
                        abi.encode(keccak256("TokenPermissions(address token,uint256 amount)"), tokenPermissions[1])
                    );
                    tokenPermissionsHashes[1] = keccak256(
                        abi.encode(keccak256("TokenPermissions(address token,uint256 amount)"), tokenPermissions[2])
                    );

                    tokenPermissionsHash = keccak256(abi.encodePacked(tokenPermissionsHashes));
                }

                bytes32 digest;
                {
                    CreatePermitBatchWitnessDigestArgs memory args;
                    {
                        args.domainSeparator = domainSeparator;
                        args.tokenPermissionsHash = tokenPermissionsHash;
                        args.spender = address(theCompact);
                        args.nonce = params.nonce;
                        args.deadline = params.deadline;
                        args.activationTypehash = activationTypehash;
                        args.idsHash = keccak256(abi.encodePacked(ids));
                        args.claimHash = claimHash;
                    }

                    digest = _createPermitBatchWitnessDigest(args);
                }

                bytes32 r;
                bytes32 vs;
                (r, vs) = vm.signCompact(swapperPrivateKey, digest);
                signature = abi.encodePacked(r, vs);
            }
        }

        {
            SetupPermitCallExpectationArgs memory args;
            args.activationTypehash = activationTypehash;
            args.ids = ids;
            args.claimHash = claimHash;
            args.nonce = params.nonce;
            args.deadline = params.deadline;
            args.signature = signature;

            _setupPermitCallExpectation(args);
        }

        // Deposit and register
        uint256[] memory returnedIds;
        {
            DepositDetails memory depositDetails;
            depositDetails.nonce = params.nonce;
            depositDetails.deadline = params.deadline;
            depositDetails.lockTag = lockTag;

            vm.prank(address(1010));
            vm.deal(address(1010), 1e18);
            returnedIds = theCompact.batchDepositAndRegisterViaPermit2{ value: 1e18 }(
                swapper,
                tokenPermissions,
                depositDetails,
                claimHash,
                CompactCategory.BatchCompact,
                witnessTypestring,
                signature
            );
            vm.snapshotGasLastCall("batchDepositAndRegisterWithWitnessViaPermit2");

            assertEq(returnedIds.length, 3);
            assertEq(returnedIds[0], ids[0]);
            assertEq(returnedIds[1], ids[1]);
            assertEq(returnedIds[2], ids[2]);

            assertEq(theCompact.balanceOf(swapper, ids[0]), 1e18);
            assertEq(theCompact.balanceOf(swapper, ids[1]), 1e18);
            assertEq(theCompact.balanceOf(swapper, ids[2]), 1e18);

            bool isActive;
            uint256 registeredAt;
            (isActive, registeredAt) = theCompact.getRegistrationStatus(swapper, claimHash, typehash);
            assert(isActive);
            assertEq(registeredAt, block.timestamp);
        }

        // Regenerate claim hash
        {
            CreateBatchClaimHashWithWitnessArgs memory args;
            {
                args.typehash = keccak256(
                    "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)"
                );
                args.arbiter = 0x2222222222222222222222222222222222222222;
                args.sponsor = swapper;
                args.nonce = params.nonce;
                args.expires = claim.expires;
                args.idsAndAmountsHash = keccak256(abi.encodePacked(idsAndAmounts));
                args.witness = claim.witness;
            }

            claimHash = _createBatchClaimHashWithWitness(args);
        }

        // Create signatures for claim
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

        // Create claim components
        {
            BatchClaimComponent[] memory claims = new BatchClaimComponent[](3);
            {
                uint256 claimantOne = abi.decode(
                    abi.encodePacked(bytes12(bytes32(ids[0])), 0x1111111111111111111111111111111111111111), (uint256)
                );
                uint256 claimantTwo = abi.decode(
                    abi.encodePacked(bytes12(bytes32(ids[0])), 0x3333333333333333333333333333333333333333), (uint256)
                );
                uint256 claimantThree = abi.decode(
                    abi.encodePacked(bytes12(bytes32(ids[1])), 0x1111111111111111111111111111111111111111), (uint256)
                );
                uint256 claimantFour = abi.decode(
                    abi.encodePacked(bytes12(bytes32(ids[2])), 0x3333333333333333333333333333333333333333), (uint256)
                );

                {
                    Component[] memory portions = new Component[](2);
                    portions[0] = Component({ claimant: claimantOne, amount: 4e17 });
                    portions[1] = Component({ claimant: claimantTwo, amount: 6e17 });
                    claims[0] = BatchClaimComponent({ id: ids[0], allocatedAmount: 1e18, portions: portions });
                }

                {
                    Component[] memory anotherPortion = new Component[](1);
                    anotherPortion[0] = Component({ claimant: claimantThree, amount: 1e18 });
                    claims[1] = BatchClaimComponent({ id: ids[1], allocatedAmount: 1e18, portions: anotherPortion });
                }

                {
                    Component[] memory aThirdPortion = new Component[](1);
                    aThirdPortion[0] = Component({ claimant: claimantFour, amount: 1e18 });
                    claims[2] = BatchClaimComponent({ id: ids[2], allocatedAmount: 1e18, portions: aThirdPortion });
                }
            }

            claim.claims = claims;
        }

        // Execute claim
        bytes32 returnedClaimHash;
        {
            vm.prank(0x2222222222222222222222222222222222222222);
            returnedClaimHash = theCompact.batchClaim(claim);
            vm.snapshotGasLastCall("batchClaimRegisteredWithDepositWithWitness");
            assertEq(returnedClaimHash, claimHash);
        }

        // Verify balances
        assertEq(address(theCompact).balance, 1e18);
        assertEq(token.balanceOf(address(theCompact)), 1e18);
        assertEq(anotherToken.balanceOf(address(theCompact)), 1e18);

        assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, ids[0]), 4e17);
        assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, ids[0]), 6e17);
        assertEq(theCompact.balanceOf(0x1111111111111111111111111111111111111111, ids[1]), 1e18);
        assertEq(theCompact.balanceOf(0x3333333333333333333333333333333333333333, ids[2]), 1e18);
    }
}
