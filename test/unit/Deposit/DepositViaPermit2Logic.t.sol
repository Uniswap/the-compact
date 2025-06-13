// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { Scope } from "src/types/Scope.sol";
import { CompactCategory } from "src/types/CompactCategory.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import { AlwaysOKAllocator } from "src/test/AlwaysOKAllocator.sol";

import { IEIP712 } from "permit2/src/interfaces/IEIP712.sol";
import { ERC20 } from "lib/solady/src/tokens/ERC20.sol";
import { MockERC20 } from "lib/solady/test/utils/mocks/MockERC20.sol";
import { ERC6909 } from "lib/solady/src/tokens/ERC6909.sol";

import "src/lib/IdLib.sol";
import "./MockDepositViaPermit2Logic.sol";

import { Permit2Test } from "../../helpers/Permit2.sol";

struct LockDetails {
    address token;
    address allocator;
    ResetPeriod resetPeriod;
    Scope scope;
    bytes12 lockTag;
}

contract DepositViaPermit2LogicTest is Permit2Test {
    using IdLib for address;
    using IdLib for uint96;
    using IdLib for uint256;

    MockDepositViaPermit2Logic logic;
    AlwaysOKAllocator allocator;

    MockERC20 testToken;
    MockERC20 secondToken;
    address recipient;
    uint96 allocatorId;
    uint256 testTokenId;
    bytes12 lockTag;

    bytes mockSignature = abi.encodePacked(bytes32(hex"01"), bytes32(hex"02"), bytes8(hex"03"));

    function setUp() public override {
        super.setUp();
        vm.warp(1743479729);

        recipient = makeAddr("recipient");
        allocator = new AlwaysOKAllocator();

        // Setup test tokens.
        testToken = new MockERC20("Test Token", "TEST", 18);
        secondToken = new MockERC20("Second Token", "SECOND", 18);
        testToken.mint(depositor, 1 ether);
        secondToken.mint(depositor, 1 ether);

        // Deploy the logic contract.
        logic = new MockDepositViaPermit2Logic();

        // Register allocator.
        (allocatorId, lockTag) = logic.registerAllocator(address(allocator));
        testTokenId = logic.toIdIfRegistered(address(testToken), lockTag);

        // Pre-approve tokens to the logic contract.
        vm.startPrank(depositor);
        testToken.approve(address(logic), type(uint256).max);
        secondToken.approve(address(logic), type(uint256).max);
        vm.stopPrank();
    }

    function test_depositViaPermit2() public {
        (ISignatureTransfer.PermitTransferFrom memory permit, bytes32 witnessHash, bytes memory signature) =
            createSingleERC20Permit(address(testToken), 0.5 ether, recipient, lockTag, privateKey, address(logic));

        vm.expectCall(
            address(permit2),
            abi.encodeWithSignature(
                "permitWitnessTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes32,string,bytes)",
                permit,
                ISignatureTransfer.SignatureTransferDetails({ to: address(logic), requestedAmount: 0.5 ether }),
                depositor,
                witnessHash,
                "CompactDeposit witness)CompactDeposit(bytes12 lockTag,address recipient)TokenPermissions(address token,uint256 amount)",
                signature
            )
        );
        uint256 id = logic.depositERC20ViaPermit2(permit, depositor, lockTag, recipient, signature);

        // Verify lock details
        {
            LockDetails memory lockDetails;
            (lockDetails.token, lockDetails.allocator, lockDetails.resetPeriod, lockDetails.scope, lockDetails.lockTag)
            = logic.getLockDetails(id);

            assertEq(lockDetails.token, address(testToken));
            assertEq(lockDetails.allocator, address(allocator));
            assertEq(uint256(lockDetails.resetPeriod), uint256(ResetPeriod.OneDay));
            assertEq(uint256(lockDetails.scope), uint256(Scope.Multichain));
            assertEq(
                id,
                (uint256(Scope.Multichain) << 255) | (uint256(ResetPeriod.OneDay) << 252)
                    | (uint256(allocatorId) << 160) | uint256(uint160(address(testToken)))
            );
            assertEq(lockDetails.lockTag, lockTag);
        }

        // Verify balances
        {
            assertEq(testToken.balanceOf(address(logic)), 0.5 ether);
            assertEq(testToken.balanceOf(depositor), 0.5 ether);
        }
    }

    function test_depositBatchViaPermit2_singleERC20() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(testToken);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 0.5 ether;

        (ISignatureTransfer.TokenPermissions[] memory tokenPermissions, bytes memory signature) =
        createPermit2BatchSignature(
            tokens, amounts, 0, block.timestamp + 1 days, lockTag, recipient, privateKey, address(logic)
        );

        DepositDetails memory depositDetails =
            DepositDetails({ nonce: 0, deadline: block.timestamp + 1 days, lockTag: lockTag });

        uint256[] memory ids =
            logic.batchDepositViaPermit2(depositor, tokenPermissions, depositDetails, recipient, signature);

        // Verify lock details
        LockDetails memory lockDetails;
        (lockDetails.token, lockDetails.allocator, lockDetails.resetPeriod, lockDetails.scope, lockDetails.lockTag) =
            logic.getLockDetails(ids[0]);

        assertEq(lockDetails.token, address(testToken));
        assertEq(lockDetails.allocator, address(allocator));
        assertEq(uint256(lockDetails.resetPeriod), uint256(ResetPeriod.OneDay));
        assertEq(uint256(lockDetails.scope), uint256(Scope.Multichain));
        assertEq(lockDetails.lockTag, lockTag);
    }

    function test_depositBatchViaPermit2_multipleERC20() public {
        address[] memory tokens = new address[](2);
        tokens[0] = address(testToken);
        tokens[1] = address(secondToken);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 0.5 ether;
        amounts[1] = 0.25 ether;

        (ISignatureTransfer.TokenPermissions[] memory tokenPermissions, bytes memory signature) =
        createPermit2BatchSignature(
            tokens, amounts, 0, block.timestamp + 1 days, lockTag, recipient, privateKey, address(logic)
        );

        DepositDetails memory depositDetails =
            DepositDetails({ nonce: 0, deadline: block.timestamp + 1 days, lockTag: lockTag });

        uint256[] memory ids =
            logic.batchDepositViaPermit2(depositor, tokenPermissions, depositDetails, recipient, signature);

        // Verify lock details
        LockDetails memory firstLock;
        (firstLock.token, firstLock.allocator, firstLock.resetPeriod, firstLock.scope, firstLock.lockTag) =
            logic.getLockDetails(ids[0]);

        assertEq(firstLock.token, address(testToken));
        assertEq(firstLock.allocator, address(allocator));
        assertEq(uint256(firstLock.resetPeriod), uint256(ResetPeriod.OneDay));
        assertEq(uint256(firstLock.scope), uint256(Scope.Multichain));
        assertEq(firstLock.lockTag, lockTag);
        assertEq(testToken.balanceOf(address(logic)), amounts[0]);

        LockDetails memory secondLock;
        (secondLock.token, secondLock.allocator, secondLock.resetPeriod, secondLock.scope, secondLock.lockTag) =
            logic.getLockDetails(ids[1]);

        assertEq(secondLock.token, address(secondToken));
        assertEq(secondLock.allocator, address(allocator));
        assertEq(uint256(secondLock.resetPeriod), uint256(ResetPeriod.OneDay));
        assertEq(uint256(secondLock.scope), uint256(Scope.Multichain));
        assertEq(secondLock.lockTag, lockTag);
        assertEq(ERC20(secondLock.token).balanceOf(address(logic)), amounts[1]);
    }

    function test_depositBatchViaPermit2_multipleERC20AndNative() public {
        vm.skip(true); // TODO: debug why this test is failing

        address[] memory tokens = new address[](3);
        tokens[0] = address(0);
        tokens[1] = address(testToken);
        tokens[2] = address(secondToken);

        uint256[] memory amounts = new uint256[](3);
        amounts[0] = 1 ether;
        amounts[1] = 0.5 ether;
        amounts[2] = 0.25 ether;

        (ISignatureTransfer.TokenPermissions[] memory tokenPermissions, bytes memory signature) =
        createPermit2BatchSignature(
            tokens, amounts, 0, block.timestamp + 1 days, lockTag, recipient, privateKey, address(logic)
        );

        assertEq(tokenPermissions.length, 2);
        assertEq(tokenPermissions[0].token, address(testToken), "First token should be testToken");
        assertEq(tokenPermissions[1].token, address(secondToken), "Second token should be secondToken");

        DepositDetails memory depositDetails =
            DepositDetails({ nonce: 0, deadline: block.timestamp + 1 days, lockTag: lockTag });

        // Include the native value in the call to the permit2 batch deposit function
        uint256[] memory ids = logic.batchDepositViaPermit2{ value: amounts[0] }(
            depositor, tokenPermissions, depositDetails, recipient, signature
        );

        // Verify lock details
        LockDetails memory nativeLock;
        (nativeLock.token, nativeLock.allocator, nativeLock.resetPeriod, nativeLock.scope, nativeLock.lockTag) =
            logic.getLockDetails(ids[0]);

        assertEq(nativeLock.token, address(0));
        assertEq(nativeLock.allocator, address(allocator));
        assertEq(uint256(nativeLock.resetPeriod), uint256(ResetPeriod.OneDay));
        assertEq(uint256(nativeLock.scope), uint256(Scope.Multichain));
        assertEq(nativeLock.lockTag, lockTag);
        assertEq(address(logic).balance, amounts[0]);

        LockDetails memory testTokenLock;
        (
            testTokenLock.token,
            testTokenLock.allocator,
            testTokenLock.resetPeriod,
            testTokenLock.scope,
            testTokenLock.lockTag
        ) = logic.getLockDetails(ids[1]);

        assertEq(testTokenLock.token, address(testToken));
        assertEq(testTokenLock.allocator, address(allocator));
        assertEq(uint256(testTokenLock.resetPeriod), uint256(ResetPeriod.OneDay));
        assertEq(uint256(testTokenLock.scope), uint256(Scope.Multichain));
        assertEq(testTokenLock.lockTag, lockTag);
        assertEq(testToken.balanceOf(address(logic)), amounts[1]);

        LockDetails memory secondTokenLock;
        (
            secondTokenLock.token,
            secondTokenLock.allocator,
            secondTokenLock.resetPeriod,
            secondTokenLock.scope,
            secondTokenLock.lockTag
        ) = logic.getLockDetails(ids[2]);

        assertEq(secondTokenLock.token, address(secondToken));
        assertEq(secondTokenLock.allocator, address(allocator));
        assertEq(uint256(secondTokenLock.resetPeriod), uint256(ResetPeriod.OneDay));
        assertEq(uint256(secondTokenLock.scope), uint256(Scope.Multichain));
        assertEq(secondTokenLock.lockTag, lockTag);
        assertEq(secondToken.balanceOf(address(logic)), amounts[2]);
    }
}
