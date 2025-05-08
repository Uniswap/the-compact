// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";

import { EIP712, Setup } from "./Setup.sol";

import { TestParams, LockDetails, DepositDetails } from "./TestHelperStructs.sol";

contract Permit2DepositTest is Setup {
    function test_depositERC20ViaPermit2AndURI() public virtual {
        // Setup test variables
        TestParams memory params;
        params.recipient = 0x1111111111111111111111111111111111111111;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Register allocator and create lock tag
        uint96 allocatorId;
        bytes12 lockTag;
        {
            vm.prank(allocator);
            allocatorId = theCompact.__registerAllocator(allocator, "");

            lockTag = bytes12(
                bytes32(
                    (uint256(params.scope) << 255) | (uint256(params.resetPeriod) << 252)
                        | (uint256(allocatorId) << 160)
                )
            );
        }

        // Create domain separator and digest
        bytes32 domainSeparator;
        bytes32 digest;
        {
            domainSeparator = keccak256(
                abi.encode(permit2EIP712DomainHash, keccak256(bytes("Permit2")), block.chainid, address(permit2))
            );

            assertEq(domainSeparator, EIP712(permit2).DOMAIN_SEPARATOR());

            bytes32 witnessHash = keccak256(
                abi.encode(keccak256("CompactDeposit(bytes12 lockTag,address recipient)"), lockTag, params.recipient)
            );

            digest = _createPermitWitnessDigest(
                domainSeparator,
                address(token),
                params.amount,
                address(theCompact),
                params.nonce,
                params.deadline,
                witnessHash
            );
        }

        // Create signature and permit
        bytes memory signature;
        ISignatureTransfer.PermitTransferFrom memory permit;
        {
            (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
            signature = abi.encodePacked(r, vs);

            permit = ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({ token: address(token), amount: params.amount }),
                nonce: params.nonce,
                deadline: params.deadline
            });
        }

        // Setup expectations and make deposit
        uint256 id;
        {
            bytes32 witnessHash = keccak256(
                abi.encode(keccak256("CompactDeposit(bytes12 lockTag,address recipient)"), lockTag, params.recipient)
            );

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
                    witnessHash,
                    "CompactDeposit witness)CompactDeposit(bytes12 lockTag,address recipient)TokenPermissions(address token,uint256 amount)",
                    signature
                )
            );

            id = theCompact.depositERC20ViaPermit2(permit, swapper, lockTag, params.recipient, signature);
            vm.snapshotGasLastCall("depositERC20ViaPermit2AndURI");
        }

        // Verify lock details
        {
            LockDetails memory lockDetails;
            (lockDetails.token, lockDetails.allocator, lockDetails.resetPeriod, lockDetails.scope, lockDetails.lockTag)
            = theCompact.getLockDetails(id);

            assertEq(lockDetails.token, address(token));
            assertEq(lockDetails.allocator, allocator);
            assertEq(uint256(lockDetails.resetPeriod), uint256(params.resetPeriod));
            assertEq(uint256(lockDetails.scope), uint256(params.scope));
            assertEq(
                id,
                (uint256(params.scope) << 255) | (uint256(params.resetPeriod) << 252) | (uint256(allocatorId) << 160)
                    | uint256(uint160(address(token)))
            );
            assertEq(lockDetails.lockTag, lockTag);
        }

        // Verify balances and token URI
        {
            assertEq(token.balanceOf(address(theCompact)), params.amount);
            assertEq(theCompact.balanceOf(params.recipient, id), params.amount);
            assert(bytes(theCompact.tokenURI(id)).length > 0);
        }
    }

    function test_depositBatchViaPermit2SingleERC20() public virtual {
        // Setup test variables
        TestParams memory params;
        params.recipient = 0x1111111111111111111111111111111111111111;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Register allocator and create lock tag
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

        // Prepare tokens and amounts arrays
        address[] memory tokens;
        uint256[] memory amounts;
        {
            tokens = new address[](1);
            amounts = new uint256[](1);
            tokens[0] = address(token);
            amounts[0] = params.amount;
        }

        // Create signature and token permissions
        bytes memory signature;
        ISignatureTransfer.PermitBatchTransferFrom memory permit;
        ISignatureTransfer.SignatureTransferDetails[] memory signatureTransferDetails;

        {
            ISignatureTransfer.TokenPermissions[] memory tokenPermissions;
            {
                (signature, tokenPermissions) = _createPermit2BatchSignature(
                    tokens, amounts, params.nonce, params.deadline, lockTag, params.recipient, swapperPrivateKey
                );
            }

            // Create permit and transfer details
            {
                signatureTransferDetails = new ISignatureTransfer.SignatureTransferDetails[](1);
                signatureTransferDetails[0] = ISignatureTransfer.SignatureTransferDetails({
                    to: address(theCompact),
                    requestedAmount: params.amount
                });

                permit = ISignatureTransfer.PermitBatchTransferFrom({
                    permitted: tokenPermissions,
                    nonce: params.nonce,
                    deadline: params.deadline
                });
            }
        }

        uint256[] memory ids;

        {
            // Prepare deposit details and expectations
            DepositDetails memory details;

            {
                details = DepositDetails({ nonce: params.nonce, deadline: params.deadline, lockTag: lockTag });

                bytes32 witnessHash = keccak256(
                    abi.encode(
                        keccak256("CompactDeposit(bytes12 lockTag,address recipient)"), lockTag, params.recipient
                    )
                );

                vm.expectCall(
                    address(permit2),
                    abi.encodeWithSignature(
                        "permitWitnessTransferFrom(((address,uint256)[],uint256,uint256),(address,uint256)[],address,bytes32,string,bytes)",
                        permit,
                        signatureTransferDetails,
                        swapper,
                        witnessHash,
                        "CompactDeposit witness)CompactDeposit(bytes12 lockTag,address recipient)TokenPermissions(address token,uint256 amount)",
                        signature
                    )
                );
            }

            // Make deposit
            {
                ids = theCompact.batchDepositViaPermit2(swapper, permit.permitted, details, params.recipient, signature);
                vm.snapshotGasLastCall("depositBatchViaPermit2SingleERC20");

                assertEq(ids.length, 1);
            }
        }

        // Verify lock details
        {
            LockDetails memory expectedDetails;
            expectedDetails.token = address(token);
            expectedDetails.allocator = allocator;
            expectedDetails.resetPeriod = params.resetPeriod;
            expectedDetails.scope = params.scope;
            expectedDetails.lockTag = lockTag;

            _verifyLockDetails(ids[0], params, expectedDetails, allocatorId);
        }

        // Verify balances and token URI
        {
            assertEq(token.balanceOf(address(theCompact)), params.amount);
            assertEq(theCompact.balanceOf(params.recipient, ids[0]), params.amount);
            assert(bytes(theCompact.tokenURI(ids[0])).length > 0);
        }
    }

    function test_depositBatchViaPermit2NativeAndERC20() public virtual {
        // Setup test variables
        TestParams memory params;
        params.recipient = 0x1111111111111111111111111111111111111111;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.amount = 1e18;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Register allocator and create lock tag
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

        // Prepare tokens and amounts arrays
        address[] memory tokens;
        uint256[] memory amounts;
        {
            tokens = new address[](2);
            amounts = new uint256[](2);
            tokens[0] = address(0);
            amounts[0] = params.amount;
            tokens[1] = address(token);
            amounts[1] = params.amount;
        }

        // Create signature and token permissions
        bytes memory signature;
        ISignatureTransfer.TokenPermissions[] memory tokenPermissions;
        {
            (signature, tokenPermissions) = _createPermit2BatchSignature(
                tokens, amounts, params.nonce, params.deadline, lockTag, params.recipient, swapperPrivateKey
            );
        }

        uint256[] memory ids;

        {
            {
                // Create permit and transfer details for the ERC20 token
                ISignatureTransfer.SignatureTransferDetails[] memory signatureTransferDetails;
                ISignatureTransfer.PermitBatchTransferFrom memory permitOnCall;
                {
                    ISignatureTransfer.TokenPermissions[] memory tokenPermissionsOnCall;
                    {
                        tokenPermissionsOnCall = new ISignatureTransfer.TokenPermissions[](1);
                        tokenPermissionsOnCall[0] =
                            ISignatureTransfer.TokenPermissions({ token: address(token), amount: params.amount });
                    }

                    {
                        signatureTransferDetails = new ISignatureTransfer.SignatureTransferDetails[](1);
                        signatureTransferDetails[0] = ISignatureTransfer.SignatureTransferDetails({
                            to: address(theCompact),
                            requestedAmount: params.amount
                        });
                    }

                    {
                        permitOnCall = ISignatureTransfer.PermitBatchTransferFrom({
                            permitted: tokenPermissionsOnCall,
                            nonce: params.nonce,
                            deadline: params.deadline
                        });
                    }
                }

                bytes32 witnessHash;
                {
                    witnessHash = keccak256(
                        abi.encode(
                            keccak256("CompactDeposit(bytes12 lockTag,address recipient)"), lockTag, params.recipient
                        )
                    );

                    vm.expectCall(
                        address(permit2),
                        abi.encodeWithSignature(
                            "permitWitnessTransferFrom(((address,uint256)[],uint256,uint256),(address,uint256)[],address,bytes32,string,bytes)",
                            permitOnCall,
                            signatureTransferDetails,
                            swapper,
                            witnessHash,
                            "CompactDeposit witness)CompactDeposit(bytes12 lockTag,address recipient)TokenPermissions(address token,uint256 amount)",
                            signature
                        )
                    );
                }
            }

            // Make deposit
            {
                DepositDetails memory details =
                    DepositDetails({ nonce: params.nonce, deadline: params.deadline, lockTag: lockTag });

                ids = theCompact.batchDepositViaPermit2{ value: params.amount }(
                    swapper, tokenPermissions, details, params.recipient, signature
                );
                vm.snapshotGasLastCall("depositBatchViaPermit2NativeAndERC20");

                assertEq(ids.length, 2);
            }
        }

        // Verify lock details for ETH (native token)
        {
            LockDetails memory expectedDetails;
            expectedDetails.token = address(0);
            expectedDetails.allocator = allocator;
            expectedDetails.resetPeriod = params.resetPeriod;
            expectedDetails.scope = params.scope;
            expectedDetails.lockTag = lockTag;

            _verifyLockDetails(ids[0], params, expectedDetails, allocatorId);
        }

        // Verify id for ERC20 token
        {
            assertEq(
                ids[1],
                (uint256(params.scope) << 255) | (uint256(params.resetPeriod) << 252) | (uint256(allocatorId) << 160)
                    | uint256(uint160(address(token)))
            );
        }

        // Verify balances and token URIs
        {
            assertEq(token.balanceOf(address(theCompact)), params.amount);
            assertEq(address(theCompact).balance, params.amount);
            assertEq(theCompact.balanceOf(params.recipient, ids[0]), params.amount);
            assertEq(theCompact.balanceOf(params.recipient, ids[1]), params.amount);
            assert(bytes(theCompact.tokenURI(ids[0])).length > 0);
        }
    }
}
