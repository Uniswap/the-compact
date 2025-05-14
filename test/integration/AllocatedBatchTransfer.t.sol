// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";

import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { Component, ComponentsById } from "../../src/types/Components.sol";
import { AllocatedTransfer } from "../../src/types/Claims.sol";
import { AllocatedBatchTransfer } from "../../src/types/BatchClaims.sol";

import { QualifiedAllocator } from "../../src/examples/allocator/QualifiedAllocator.sol";

import { Setup } from "./Setup.sol";

import { TestParams } from "./TestHelperStructs.sol";

contract AllocatedBatchTransferTest is Setup {
    function test_BatchTransfer() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Amount information
        uint256 amountOne = 1e18;
        uint256 amountTwo = 6e17;
        uint256 amountThree = 4e17;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x2222222222222222222222222222222222222222;

        // Register allocator and make deposits
        uint256 idOne;
        uint256 idTwo;
        {
            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            idOne = _makeDeposit(swapper, address(token), amountOne, lockTag);
            idTwo = _makeDeposit(swapper, amountTwo + amountThree, lockTag);

            assertEq(theCompact.balanceOf(swapper, idOne), amountOne);
            assertEq(theCompact.balanceOf(swapper, idTwo), amountTwo + amountThree);
        }

        // Create idsAndAmounts array
        uint256[2][] memory idsAndAmounts;
        {
            idsAndAmounts = new uint256[2][](2);
            idsAndAmounts[0] = [idOne, amountOne];
            idsAndAmounts[1] = [idTwo, amountTwo + amountThree];
        }

        // Create digest and allocator signature
        bytes memory allocatorData;
        {
            bytes32 digest;
            {
                bytes32 batchCompactHash = keccak256(
                    abi.encode(
                        keccak256(
                            "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts)"
                        ),
                        swapper,
                        swapper,
                        params.nonce,
                        params.deadline,
                        keccak256(abi.encodePacked(idsAndAmounts))
                    )
                );

                digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), batchCompactHash);
            }

            bytes32 r;
            bytes32 vs;
            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            allocatorData = abi.encodePacked(r, vs);
        }

        // Prepare transfers
        AllocatedBatchTransfer memory transfer;
        ComponentsById[] memory transfers = new ComponentsById[](2);
        {
            Component[] memory portionsOne;

            uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(bytes32(idOne)), recipientOne), (uint256));

            portionsOne = new Component[](1);
            portionsOne[0] = Component({ claimant: claimantOne, amount: amountOne });

            transfers[0] = ComponentsById({ id: idOne, portions: portionsOne });
        }

        {
            Component[] memory portionsTwo;
            uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(bytes32(idTwo)), recipientOne), (uint256));
            uint256 claimantThree = abi.decode(abi.encodePacked(bytes12(bytes32(idTwo)), recipientTwo), (uint256));

            portionsTwo = new Component[](2);
            portionsTwo[0] = Component({ claimant: claimantTwo, amount: amountTwo });
            portionsTwo[1] = Component({ claimant: claimantThree, amount: amountThree });

            transfers[1] = ComponentsById({ id: idTwo, portions: portionsTwo });
        }

        {
            // Create batch transfer
            transfer = AllocatedBatchTransfer({
                nonce: params.nonce,
                expires: params.deadline,
                allocatorData: allocatorData,
                transfers: transfers
            });
        }

        // Execute transfer
        {
            vm.prank(swapper);
            bool status = theCompact.allocatedBatchTransfer(transfer);
            vm.snapshotGasLastCall("BatchTransfer");
            assert(status);
        }

        // Verify balances
        assertEq(token.balanceOf(recipientOne), 0);
        assertEq(token.balanceOf(recipientTwo), 0);
        assertEq(theCompact.balanceOf(swapper, idOne), 0);
        assertEq(theCompact.balanceOf(swapper, idTwo), 0);
        assertEq(theCompact.balanceOf(recipientOne, idOne), amountOne);
        assertEq(theCompact.balanceOf(recipientOne, idTwo), amountTwo);
        assertEq(theCompact.balanceOf(recipientTwo, idTwo), amountThree);
    }

    function test_batchWithdrawal() public {
        // Setup test parameters
        TestParams memory params;
        params.resetPeriod = ResetPeriod.TenMinutes;
        params.scope = Scope.Multichain;
        params.nonce = 0;
        params.deadline = block.timestamp + 1000;

        // Amount information
        uint256 amountOne = 1e18;
        uint256 amountTwo = 6e17;
        uint256 amountThree = 4e17;

        // Recipient information
        address recipientOne = 0x1111111111111111111111111111111111111111;
        address recipientTwo = 0x2222222222222222222222222222222222222222;

        // Register allocator and make deposits
        uint256 idOne;
        uint256 idTwo;
        {
            uint96 allocatorId;
            bytes12 lockTag;
            (allocatorId, lockTag) = _registerAllocator(allocator);

            idOne = _makeDeposit(swapper, address(token), amountOne, lockTag);
            idTwo = _makeDeposit(swapper, amountTwo + amountThree, lockTag);

            assertEq(theCompact.balanceOf(swapper, idOne), amountOne);
            assertEq(theCompact.balanceOf(swapper, idTwo), amountTwo + amountThree);
        }

        // Create idsAndAmounts array
        uint256[2][] memory idsAndAmounts;
        {
            idsAndAmounts = new uint256[2][](2);
            idsAndAmounts[0] = [idOne, amountOne];
            idsAndAmounts[1] = [idTwo, amountTwo + amountThree];
        }

        // Create digest and allocator signature
        bytes memory allocatorData;
        {
            bytes32 digest;
            {
                bytes32 batchCompactHash = keccak256(
                    abi.encode(
                        keccak256(
                            "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts)"
                        ),
                        swapper,
                        swapper,
                        params.nonce,
                        params.deadline,
                        keccak256(abi.encodePacked(idsAndAmounts))
                    )
                );

                digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), batchCompactHash);
            }

            bytes32 r;
            bytes32 vs;
            (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
            allocatorData = abi.encodePacked(r, vs);
        }

        // Prepare transfers
        AllocatedBatchTransfer memory transfer;
        ComponentsById[] memory transfers = new ComponentsById[](2);
        {
            // First transfer
            {
                Component[] memory portionsOne;
                uint256 claimantOne = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));

                portionsOne = new Component[](1);
                portionsOne[0] = Component({ claimant: claimantOne, amount: amountOne });

                transfers[0] = ComponentsById({ id: idOne, portions: portionsOne });
            }

            // Second transfer
            {
                Component[] memory portionsTwo;
                uint256 claimantTwo = abi.decode(abi.encodePacked(bytes12(0), recipientOne), (uint256));
                uint256 claimantThree = abi.decode(abi.encodePacked(bytes12(0), recipientTwo), (uint256));

                portionsTwo = new Component[](2);
                portionsTwo[0] = Component({ claimant: claimantTwo, amount: amountTwo });
                portionsTwo[1] = Component({ claimant: claimantThree, amount: amountThree });

                transfers[1] = ComponentsById({ id: idTwo, portions: portionsTwo });
            }

            // Create batch transfer
            {
                transfer = AllocatedBatchTransfer({
                    nonce: params.nonce,
                    expires: params.deadline,
                    allocatorData: allocatorData,
                    transfers: transfers
                });
            }
        }

        // Execute transfer
        {
            vm.prank(swapper);
            bool status = theCompact.allocatedBatchTransfer(transfer);
            vm.snapshotGasLastCall("batchWithdrawal");
            assert(status);
        }

        // Verify balances
        assertEq(token.balanceOf(recipientOne), amountOne);
        assertEq(token.balanceOf(recipientTwo), 0);
        assertEq(recipientOne.balance, amountTwo);
        assertEq(recipientTwo.balance, amountThree);
        assertEq(theCompact.balanceOf(swapper, idOne), 0);
        assertEq(theCompact.balanceOf(swapper, idTwo), 0);
        assertEq(theCompact.balanceOf(recipientOne, idOne), 0);
        assertEq(theCompact.balanceOf(recipientOne, idTwo), 0);
        assertEq(theCompact.balanceOf(recipientTwo, idTwo), 0);
    }
}
