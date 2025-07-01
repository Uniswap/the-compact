// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";

import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { IdLib } from "../../src/lib/IdLib.sol";
import { FeeOnTransferToken } from "../../src/test/FeeOnTransferToken.sol";
import { ReentrantToken } from "../../src/test/ReentrantToken.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

import { Setup } from "./Setup.sol";

contract DepositTest is Setup {
    function setUp() public override {
        super.setUp();
    }

    function test_depositETHBasic() public {
        address recipient = swapper;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, address(0));
        vm.snapshotGasLastCall("depositETHBasic");

        (
            address derivedToken,
            address derivedAllocator,
            ResetPeriod derivedResetPeriod,
            Scope derivedScope,
            bytes12 derivedLockTag
        ) = theCompact.getLockDetails(id);
        assertEq(derivedToken, address(0));
        assertEq(derivedAllocator, allocator);
        assertEq(uint256(derivedResetPeriod), uint256(resetPeriod));
        assertEq(uint256(derivedScope), uint256(scope));
        assertEq(
            id,
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(0)))
        );
        assertEq(
            derivedLockTag,
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)))
        );

        assertEq(address(theCompact).balance, amount);
        assertEq(theCompact.balanceOf(recipient, id), amount);
        assert(bytes(theCompact.tokenURI(id)).length > 0);
    }

    function test_depositETHAndURI() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositNative{ value: amount }(lockTag, recipient);
        vm.snapshotGasLastCall("depositETHAndURI");

        (
            address derivedToken,
            address derivedAllocator,
            ResetPeriod derivedResetPeriod,
            Scope derivedScope,
            bytes12 derivedLockTag
        ) = theCompact.getLockDetails(id);
        assertEq(derivedToken, address(0));
        assertEq(derivedAllocator, allocator);
        assertEq(uint256(derivedResetPeriod), uint256(resetPeriod));
        assertEq(uint256(derivedScope), uint256(scope));
        assertEq(
            id,
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(0)))
        );
        assertEq(
            derivedLockTag,
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)))
        );

        assertEq(address(theCompact).balance, amount);
        assertEq(theCompact.balanceOf(recipient, id), amount);
        assert(bytes(theCompact.tokenURI(id)).length > 0);
    }

    function test_depositERC20Basic() public {
        address recipient = swapper;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositERC20(address(token), lockTag, amount, swapper);
        vm.snapshotGasLastCall("depositERC20Basic");

        (
            address derivedToken,
            address derivedAllocator,
            ResetPeriod derivedResetPeriod,
            Scope derivedScope,
            bytes12 derivedLockTag
        ) = theCompact.getLockDetails(id);
        assertEq(derivedToken, address(token));
        assertEq(derivedAllocator, allocator);
        assertEq(uint256(derivedResetPeriod), uint256(resetPeriod));
        assertEq(uint256(derivedScope), uint256(scope));
        assertEq(
            id,
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(token)))
        );
        assertEq(
            derivedLockTag,
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)))
        );

        assertEq(token.balanceOf(address(theCompact)), amount);
        assertEq(theCompact.balanceOf(recipient, id), amount);
        assert(bytes(theCompact.tokenURI(id)).length > 0);
    }

    function test_depositERC20AndURI() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        uint256 id = theCompact.depositERC20(address(token), lockTag, amount, recipient);
        vm.snapshotGasLastCall("depositERC20AndURI");

        (
            address derivedToken,
            address derivedAllocator,
            ResetPeriod derivedResetPeriod,
            Scope derivedScope,
            bytes12 derivedLockTag
        ) = theCompact.getLockDetails(id);
        assertEq(derivedToken, address(token));
        assertEq(derivedAllocator, allocator);
        assertEq(uint256(derivedResetPeriod), uint256(resetPeriod));
        assertEq(uint256(derivedScope), uint256(scope));
        assertEq(
            id,
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(token)))
        );
        assertEq(
            derivedLockTag,
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)))
        );

        assertEq(token.balanceOf(address(theCompact)), amount);
        assertEq(theCompact.balanceOf(recipient, id), amount);
        assert(bytes(theCompact.tokenURI(id)).length > 0);
    }

    function test_depositBatchSingleNativeToken() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        uint256 id = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(0)))
        );

        {
            uint256[2][] memory idsAndAmounts = new uint256[2][](1);
            idsAndAmounts[0] = [id, amount];

            vm.prank(swapper);
            bool ok = theCompact.batchDeposit{ value: amount }(idsAndAmounts, recipient);
            vm.snapshotGasLastCall("depositBatchSingleNative");
            assert(ok);
        }

        (
            address derivedToken,
            address derivedAllocator,
            ResetPeriod derivedResetPeriod,
            Scope derivedScope,
            bytes12 lockTag
        ) = theCompact.getLockDetails(id);
        assertEq(derivedToken, address(0));
        assertEq(derivedAllocator, allocator);
        assertEq(uint256(derivedResetPeriod), uint256(resetPeriod));
        assertEq(uint256(derivedScope), uint256(scope));

        assertEq(
            id,
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(0)))
        );
        assertEq(
            lockTag,
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)))
        );

        assertEq(address(theCompact).balance, amount);
        assertEq(theCompact.balanceOf(recipient, id), amount);
        assert(bytes(theCompact.tokenURI(id)).length > 0);
    }

    function test_depositBatchSingleERC20() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        uint256 id = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(token)))
        );

        {
            uint256[2][] memory idsAndAmounts = new uint256[2][](1);
            idsAndAmounts[0] = [id, amount];

            vm.prank(swapper);
            bool ok = theCompact.batchDeposit(idsAndAmounts, recipient);
            vm.snapshotGasLastCall("depositBatchSingleERC20");
            assert(ok);
        }

        (
            address derivedToken,
            address derivedAllocator,
            ResetPeriod derivedResetPeriod,
            Scope derivedScope,
            bytes12 lockTag
        ) = theCompact.getLockDetails(id);
        assertEq(derivedToken, address(token));
        assertEq(derivedAllocator, allocator);
        assertEq(uint256(derivedResetPeriod), uint256(resetPeriod));
        assertEq(uint256(derivedScope), uint256(scope));

        assertEq(
            id,
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(token)))
        );
        assertEq(
            lockTag,
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)))
        );

        assertEq(token.balanceOf(address(theCompact)), amount);
        assertEq(theCompact.balanceOf(recipient, id), amount);
        assert(bytes(theCompact.tokenURI(id)).length > 0);
    }

    function test_depositBatchDifferentAllocators() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");
        vm.prank(alwaysOKAllocator);
        uint96 anotherAllocatorId = theCompact.__registerAllocator(alwaysOKAllocator, "");

        uint256 nativeId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(0)))
        );

        uint256 tokenId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(anotherAllocatorId) << 160)
                | uint256(uint160(address(token)))
        );

        {
            uint256[2][] memory idsAndAmounts = new uint256[2][](2);
            idsAndAmounts[0] = [nativeId, amount];
            idsAndAmounts[1] = [tokenId, amount];

            vm.prank(swapper);
            bool ok = theCompact.batchDeposit{ value: amount }(idsAndAmounts, recipient);
            vm.snapshotGasLastCall("depositBatchNativeAndERC20");
            assert(ok);
        }

        {
            // Check Native Token
            (address derivedNativeToken, address derivedNativeAllocator,,, bytes12 derivedNativeLockTag) =
                theCompact.getLockDetails(nativeId);
            assertEq(derivedNativeToken, address(0));
            assertEq(derivedNativeAllocator, allocator);

            assertEq(
                nativeId,
                (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                    | uint256(uint160(address(0)))
            );
            assertEq(
                derivedNativeLockTag,
                bytes12(
                    bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160))
                )
            );

            assertEq(address(theCompact).balance, amount);
            assertEq(theCompact.balanceOf(recipient, nativeId), amount);
            assert(bytes(theCompact.tokenURI(nativeId)).length > 0);
        }
        {
            // Check ERC20 Token
            (address derivedToken, address derivedAllocator,,, bytes12 derivedLockTag) =
                theCompact.getLockDetails(tokenId);
            assertEq(derivedToken, address(token));
            assertEq(derivedAllocator, alwaysOKAllocator);

            assertEq(
                tokenId,
                (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(anotherAllocatorId) << 160)
                    | uint256(uint160(address(token)))
            );
            assertEq(
                derivedLockTag,
                bytes12(
                    bytes32(
                        (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(anotherAllocatorId) << 160)
                    )
                )
            );

            assertEq(token.balanceOf(address(theCompact)), amount);
            assertEq(theCompact.balanceOf(recipient, tokenId), amount);
            assert(bytes(theCompact.tokenURI(tokenId)).length > 0);
        }
    }

    function test_depositBatchNativeTokenAndERC20() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        uint256 nativeId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(0)))
        );

        uint256 tokenId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(token)))
        );

        {
            uint256[2][] memory idsAndAmounts = new uint256[2][](2);
            idsAndAmounts[0] = [nativeId, amount];
            idsAndAmounts[1] = [tokenId, amount];

            vm.prank(swapper);
            bool ok = theCompact.batchDeposit{ value: amount }(idsAndAmounts, recipient);
            vm.snapshotGasLastCall("depositBatchNativeAndERC20");
            assert(ok);
        }

        {
            // Check Native Token
            (
                address derivedNativeToken,
                address derivedNativeAllocator,
                ResetPeriod derivedNativeResetPeriod,
                Scope derivedNativeScope,
                bytes12 derivedNativeLockTag
            ) = theCompact.getLockDetails(nativeId);
            assertEq(derivedNativeToken, address(0));
            assertEq(derivedNativeAllocator, allocator);
            assertEq(uint256(derivedNativeResetPeriod), uint256(resetPeriod));
            assertEq(uint256(derivedNativeScope), uint256(scope));

            assertEq(
                nativeId,
                (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                    | uint256(uint160(address(0)))
            );
            assertEq(
                derivedNativeLockTag,
                bytes12(
                    bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160))
                )
            );

            assertEq(address(theCompact).balance, amount);
            assertEq(theCompact.balanceOf(recipient, nativeId), amount);
            assert(bytes(theCompact.tokenURI(nativeId)).length > 0);
        }
        {
            // Check ERC20 Token
            (
                address derivedToken,
                address derivedAllocator,
                ResetPeriod derivedResetPeriod,
                Scope derivedScope,
                bytes12 derivedLockTag
            ) = theCompact.getLockDetails(tokenId);
            assertEq(derivedToken, address(token));
            assertEq(derivedAllocator, allocator);
            assertEq(uint256(derivedResetPeriod), uint256(resetPeriod));
            assertEq(uint256(derivedScope), uint256(scope));

            assertEq(
                tokenId,
                (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                    | uint256(uint160(address(token)))
            );
            assertEq(
                derivedLockTag,
                bytes12(
                    bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160))
                )
            );

            assertEq(token.balanceOf(address(theCompact)), amount);
            assertEq(theCompact.balanceOf(recipient, tokenId), amount);
            assert(bytes(theCompact.tokenURI(tokenId)).length > 0);
        }
    }

    function test_revert_depositEthBasicZeroValue() public {
        address recipient = swapper;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidDepositBalanceChange.selector), address(theCompact));
        theCompact.depositNative{ value: 0 }(lockTag, recipient);
    }

    function test_revert_depositERC20ZeroValue() public {
        address recipient = swapper;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidDepositBalanceChange.selector), address(theCompact));
        theCompact.depositERC20(address(token), lockTag, 0, recipient);
    }

    function test_revert_InvalidDepositBalanceChange(uint8 fee_, uint8 failingAmount_, uint256 successfulAmount_)
        public
    {
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        fee_ = uint8(bound(fee_, 2, type(uint8).max)); // fee must be at least 2, so failingAmount can be at least 1
        failingAmount_ = uint8(bound(failingAmount_, 1, fee_ - 1)); // always one smaller then fee
        successfulAmount_ = bound(successfulAmount_, uint256(fee_) + 1, type(uint256).max - fee_); // Must be at least fee + 1, otherwise the balance change on theCompact is 0

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        FeeOnTransferToken fotToken = new FeeOnTransferToken("Test", "TEST", 18, fee_);
        uint256 id = uint256(bytes32(lockTag)) | uint256(uint160(address(fotToken)));

        fotToken.mint(address(theCompact), fee_);
        fotToken.mint(swapper, failingAmount_);

        vm.prank(swapper);
        fotToken.approve(address(theCompact), type(uint256).max);

        assertEq(fotToken.balanceOf(address(theCompact)), fee_);
        assertEq(fotToken.balanceOf(swapper), failingAmount_);

        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidDepositBalanceChange.selector), address(theCompact));
        theCompact.depositERC20(address(fotToken), lockTag, failingAmount_, swapper);

        // Check balances of ERC20
        assertEq(fotToken.balanceOf(address(theCompact)), fee_);
        assertEq(fotToken.balanceOf(swapper), failingAmount_);
        // Check balances of ERC6909
        assertEq(theCompact.balanceOf(address(theCompact), id), 0);
        assertEq(theCompact.balanceOf(swapper, id), 0);

        // FOT token works if the fee is smaller or equal to the deposited amount
        fotToken.mint(swapper, successfulAmount_ - failingAmount_);
        vm.prank(swapper);
        uint256 realId = theCompact.depositERC20(address(fotToken), lockTag, successfulAmount_, swapper);
        assertEq(realId, id, "id mismatch");

        // Check balances of ERC20
        assertEq(fotToken.balanceOf(address(theCompact)), successfulAmount_); // fee gets deducted from previous balance
        assertEq(fotToken.balanceOf(swapper), 0);
        // Check balances of ERC6909
        assertEq(theCompact.balanceOf(swapper, id), successfulAmount_ - fee_);
    }

    function test_revert_BlockingReentrantTokenCall(uint256 amount) public {
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        ReentrantToken reentrantToken = new ReentrantToken("Test", "TEST", 18, address(theCompact), bytes(""));
        uint256 id = uint256(bytes32(lockTag)) | uint256(uint160(address(reentrantToken)));
        reentrantToken.setReentrantData(
            abi.encodeWithSelector(ITheCompact.depositERC20.selector, address(reentrantToken), lockTag, amount, swapper)
        );

        reentrantToken.mint(swapper, type(uint256).max);

        vm.prank(swapper);
        reentrantToken.approve(address(theCompact), type(uint256).max);

        assertEq(reentrantToken.balanceOf(address(theCompact)), 0);
        assertEq(reentrantToken.balanceOf(swapper), type(uint256).max);

        vm.prank(swapper);
        // The reentrant call will fail with "ReentrantCall", then the transferFrom will revert with "TransferFromFailed"
        vm.expectRevert(abi.encodeWithSelector(SafeTransferLib.TransferFromFailed.selector), address(theCompact));
        theCompact.depositERC20(address(reentrantToken), lockTag, amount, swapper);

        // Check balances of ERC20
        assertEq(reentrantToken.balanceOf(address(theCompact)), 0);
        assertEq(reentrantToken.balanceOf(swapper), type(uint256).max);
        // Check balances of ERC6909
        assertEq(theCompact.balanceOf(swapper, id), 0);
    }

    function test_revert_Batch_ArrayEmpty() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        uint256 amount = 1e18;

        vm.prank(allocator);
        theCompact.__registerAllocator(allocator, "");

        {
            uint256[2][] memory idsAndAmounts = new uint256[2][](0);

            vm.prank(swapper);
            vm.expectRevert(
                abi.encodeWithSelector(ITheCompact.InvalidBatchDepositStructure.selector), address(theCompact)
            );
            theCompact.batchDeposit{ value: amount }(idsAndAmounts, recipient);
        }

        {
            assertEq(token.balanceOf(address(theCompact)), 0);
            assertEq(address(theCompact).balance, 0);
        }
    }

    function test_revert_Batch_NativeTokenValueZero() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        uint256 nativeId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(0)))
        );

        uint256 tokenId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(token)))
        );

        {
            uint256[2][] memory idsAndAmounts = new uint256[2][](2);
            idsAndAmounts[0] = [nativeId, amount];
            idsAndAmounts[1] = [tokenId, amount];

            vm.prank(swapper);
            vm.expectRevert(
                abi.encodeWithSelector(ITheCompact.InvalidBatchDepositStructure.selector), address(theCompact)
            );
            theCompact.batchDeposit{ value: 0 }(idsAndAmounts, recipient);
        }

        {
            assertEq(token.balanceOf(address(theCompact)), 0);
            assertEq(address(theCompact).balance, 0);
        }
    }

    function test_revert_Batch_NonNativeValueNotZero() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        uint256 tokenId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(token)))
        );

        uint256 anotherTokenId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(anotherToken)))
        );

        {
            uint256[2][] memory idsAndAmounts = new uint256[2][](2);
            idsAndAmounts[0] = [tokenId, amount];
            idsAndAmounts[1] = [anotherTokenId, amount];

            vm.prank(swapper);
            vm.expectRevert(
                abi.encodeWithSelector(ITheCompact.InvalidBatchDepositStructure.selector), address(theCompact)
            );
            theCompact.batchDeposit{ value: amount }(idsAndAmounts, recipient);
        }

        {
            assertEq(token.balanceOf(address(theCompact)), 0);
            assertEq(address(theCompact).balance, 0);
        }
    }

    function test_revert_Batch_NativeTokenNonMatchingValue() public {
        address recipient = 0x1111111111111111111111111111111111111111;
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        uint256 nativeId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(0)))
        );

        uint256 tokenId = (
            (uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)
                | uint256(uint160(address(token)))
        );

        {
            uint256[2][] memory idsAndAmounts = new uint256[2][](2);
            idsAndAmounts[0] = [nativeId, amount];
            idsAndAmounts[1] = [tokenId, amount];

            vm.prank(swapper);
            vm.expectRevert(
                abi.encodeWithSelector(ITheCompact.InvalidBatchDepositStructure.selector), address(theCompact)
            );
            theCompact.batchDeposit{ value: amount + 1 }(idsAndAmounts, recipient);
        }

        {
            assertEq(token.balanceOf(address(theCompact)), 0);
            assertEq(address(theCompact).balance, 0);
        }
    }

    function test_revert_NoAllocatorRegistered() public {
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        uint96 allocatorId = uint96(uint160(allocator) >> (64 + 4) /* 1 byte for scope + 3 bytes for reset period */ ); // unregistered allocator

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(IdLib.NoAllocatorRegistered.selector, allocatorId), address(theCompact));
        theCompact.depositNative{ value: amount }(lockTag, address(0));
    }

    function test_revert_depositOverflow() public {
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 5e17;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        uint256 id = _makeDeposit(swapper, address(token), amount, lockTag);

        bytes8 _ERC6909_MASTER_SLOT_SEED = 0xedcaa89a82293940;
        bytes32 slot = keccak256(abi.encodePacked(id, swapper, bytes4(""), _ERC6909_MASTER_SLOT_SEED));

        // Check the current value at the slot
        uint256 valueAtSlot = uint256(vm.load(address(theCompact), slot));
        assertEq(valueAtSlot, amount);

        // Set the slot value to uint256.max
        vm.store(address(theCompact), slot, bytes32(type(uint256).max));

        vm.startPrank(swapper);
        token.approve(address(theCompact), amount);
        vm.expectRevert(abi.encodeWithSignature("BalanceOverflow()"), address(theCompact));
        theCompact.depositERC20(address(token), lockTag, amount, swapper);
        vm.stopPrank();
    }

    function test_revert_depositERC20ZeroAddress() public {
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;

        vm.prank(allocator);
        uint96 allocatorId = theCompact.__registerAllocator(allocator, "");

        bytes12 lockTag =
            bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));

        vm.prank(swapper);
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidToken.selector, address(0)), address(theCompact));
        theCompact.depositERC20(address(0), lockTag, amount, swapper);
    }
}
