// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { UtilityLib } from "../../src/utility/UtilityLib.sol";
import { TheCompact } from "../../src/TheCompact.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";

import { Setup } from "../integration/Setup.sol";
import { HelperConstants } from "../helpers/HelperConstants.sol";
import { Claim } from "../../src/types/Claims.sol";
import { Component } from "../../src/types/Components.sol";

contract UtilityLibTest is Setup {
    uint256 private id;

    function setUp() public override {
        super.setUp();
    }

    function test_checkTheCompactDeployments() public view {
        assertEq(address(theCompact), UtilityLib.THE_COMPACT);
    }

    function test_checkCheckTstoreAvailable_success() public view {
        bool available = UtilityLib.checkTstoreAvailable();
        assertTrue(available);
    }

    function test_checkCheckTstoreAvailable_failure() public {
        // Deploy a contract that immediately reverts to simulate TSTORE not being available
        bytes memory revertCode = hex"5f5ffd"; // PUSH0 PUSH0 REVERT
        vm.etch(UtilityLib.TSTORE_TEST_CONTRACT, revertCode);
        bool available = UtilityLib.checkTstoreAvailable();
        assertFalse(available);
    }
}

contract UtilityLibTest_Transient is Setup {
    bytes12 lockTag;
    uint256 private idEth;
    uint256 private idERC20;
    CheckBalanceDuringTransfer public checkBalanceDuringTransfer;

    function setUp() public override {
        super.setUp();

        (, lockTag) = _registerAllocator(alwaysOKAllocator);
        idEth = theCompact.depositNative{ value: 1e18 }(lockTag, address(this));

        // Deploy malicious ERC20 token
        checkBalanceDuringTransfer = new CheckBalanceDuringTransfer(false);
        // Set approval
        checkBalanceDuringTransfer.approve(address(theCompact), 1e18);
        // Deposit malicious ERC20 token
        idERC20 = theCompact.depositERC20(address(checkBalanceDuringTransfer), lockTag, 1e18, address(this));
        checkBalanceDuringTransfer.setId(idERC20);
    }

    function test_checkTheCompactAddress() public view {
        assertEq(address(theCompact), UtilityLib.THE_COMPACT);
    }

    function test_makeSureTransientStorageIsUsed() public {
        vm.expectRevert(abi.encodeWithSignature("TStoreAlreadyActivated()"));
        TheCompact(UtilityLib.THE_COMPACT).__activateTstore();
    }

    function test_checkSettledBalanceOf_transient() public view {
        uint256 balance = UtilityLib.settledBalanceOf(address(this), idEth);
        assertEq(balance, 1e18);
    }

    function test_checkSettledBalanceOf_transient_reentrant() public {
        uint256 balance = UtilityLib.settledBalanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 0);

        // Check successful withdrawal without reentrancy
        Component memory component =
            Component({ claimant: uint256(bytes32(abi.encodePacked(bytes12(0), address(this)))), amount: 1e18 });
        Component[] memory claimants = new Component[](1);
        claimants[0] = component;
        Claim memory claim = Claim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: address(this),
            nonce: 0,
            expires: type(uint32).max,
            witness: bytes32(0),
            witnessTypestring: "",
            id: idERC20,
            allocatedAmount: 1e18,
            claimants: claimants
        });
        theCompact.claim(claim);

        balance = UtilityLib.settledBalanceOf(address(this), idERC20);
        assertEq(balance, 0);
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 0);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 1e18);

        checkBalanceDuringTransfer.approve(address(theCompact), 1e18);

        // Activate reentrancy balance to check the deposit revert
        checkBalanceDuringTransfer.setAfterTokenTransferActive(true);
        vm.expectRevert(abi.encodeWithSignature("TransferFromFailed()"));
        theCompact.depositERC20(address(checkBalanceDuringTransfer), lockTag, 1e18, address(this));
        // Deactivate reentrancy balance to deposit correctly
        checkBalanceDuringTransfer.setAfterTokenTransferActive(false);

        // Deposit again
        theCompact.depositERC20(address(checkBalanceDuringTransfer), lockTag, 1e18, address(this));
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 0);

        // Activate reentrancy balance
        checkBalanceDuringTransfer.setAfterTokenTransferActive(true);

        // Try to claim again - should fail due to an invalid balance check in the _afterTokenTransfer hook
        claim.nonce++;
        // The claim transaction will NOT FAIL, even if the claim transfer actually failed. Instead it will release the tokens, which will trigger a release (no balance change)
        theCompact.claim(claim);

        // While the claim only silently failed the balance should still NOT have been affected
        balance = UtilityLib.settledBalanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 0);
    }
}

contract UtilityLibTest_NonTransient is Setup {
    bytes12 lockTag;
    uint256 private idEth;
    uint256 private idERC20;
    CheckBalanceDuringTransfer public checkBalanceDuringTransfer;

    function setUp() public override {
        super.setUp();

        // manipulate the code of the TSTORE_TEST_CONTRACT to be the code of theCompact_deployedBytecode_noTransientStorage
        bytes memory deployedCode = HelperConstants.theCompact_deployedBytecode_noTransientStorage;
        vm.etch(UtilityLib.THE_COMPACT, deployedCode);

        (, lockTag) = _registerAllocator(alwaysOKAllocator);
        idEth = theCompact.depositNative{ value: 1e18 }(lockTag, address(this));

        // Deploy malicious ERC20 token
        checkBalanceDuringTransfer = new CheckBalanceDuringTransfer(true);
        // Set approval
        checkBalanceDuringTransfer.approve(address(theCompact), 1e18);
        // Deposit malicious ERC20 token
        idERC20 = theCompact.depositERC20(address(checkBalanceDuringTransfer), lockTag, 1e18, address(this));
        checkBalanceDuringTransfer.setId(idERC20);
    }

    function test_checkTheCompactAddress() public view {
        assertEq(address(theCompact), UtilityLib.THE_COMPACT);
    }

    function test_makeSureTransientStorageIsNotUsed() public {
        TheCompact(UtilityLib.THE_COMPACT).__activateTstore();
    }

    function test_checkSettledBalanceOf_nonTransient() public view {
        uint256 balance = UtilityLib.settledBalanceOf_nonTransient(address(this), idEth);
        assertEq(balance, 1e18);
    }

    function test_checkSettledBalanceOf_nonTransient_reentrant() public {
        uint256 balance = UtilityLib.settledBalanceOf_nonTransient(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 0);

        // Check successful withdrawal without reentrancy
        Component memory component =
            Component({ claimant: uint256(bytes32(abi.encodePacked(bytes12(0), address(this)))), amount: 1e18 });
        Component[] memory claimants = new Component[](1);
        claimants[0] = component;
        Claim memory claim = Claim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: address(this),
            nonce: 0,
            expires: type(uint32).max,
            witness: bytes32(0),
            witnessTypestring: "",
            id: idERC20,
            allocatedAmount: 1e18,
            claimants: claimants
        });
        theCompact.claim(claim);

        balance = UtilityLib.settledBalanceOf_nonTransient(address(this), idERC20);
        assertEq(balance, 0);
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 0);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 1e18);

        checkBalanceDuringTransfer.approve(address(theCompact), 1e18);

        // Activate reentrancy balance to check the deposit revert
        checkBalanceDuringTransfer.setAfterTokenTransferActive(true);
        vm.expectRevert(abi.encodeWithSignature("TransferFromFailed()"));
        theCompact.depositERC20(address(checkBalanceDuringTransfer), lockTag, 1e18, address(this));
        // Deactivate reentrancy balance to deposit correctly
        checkBalanceDuringTransfer.setAfterTokenTransferActive(false);

        // Deposit again
        theCompact.depositERC20(address(checkBalanceDuringTransfer), lockTag, 1e18, address(this));
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 0);

        // Activate reentrancy balance
        checkBalanceDuringTransfer.setAfterTokenTransferActive(true);

        // Try to claim again - should fail due to an invalid balance check in the _afterTokenTransfer hook
        claim.nonce++;
        // The claim transaction will NOT FAIL, even if the claim transfer actually failed. Instead it will release the tokens, which will trigger a release (no balance change)
        theCompact.claim(claim);

        // While the claim only silently failed the balance should still NOT have been affected
        balance = UtilityLib.settledBalanceOf_nonTransient(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 0);
    }
}

// --- Mock Contracts ---

contract CheckBalanceDuringTransfer is ERC20 {
    bool private immutable _NON_TRANSIENT;

    uint256 private id;
    bool public afterTokenTransferActive;

    constructor(bool nonTransient_) {
        _NON_TRANSIENT = nonTransient_;
        _mint(msg.sender, 1e18);
    }

    function _afterTokenTransfer(address from, address, uint256) internal view override {
        if (afterTokenTransferActive) {
            if (_NON_TRANSIENT) {
                UtilityLib.settledBalanceOf_nonTransient(from, id);
            } else {
                UtilityLib.settledBalanceOf(from, id);
            }
        }
    }

    /// @dev Returns the name of the token.
    function name() public pure override returns (string memory) {
        return "CheckBalanceDuringTransfer";
    }

    /// @dev Returns the symbol of the token.
    function symbol() public pure override returns (string memory) {
        return "CBDT";
    }

    /// @dev Returns the decimals places of the token.
    function decimals() public pure override returns (uint8) {
        return 18;
    }

    function setId(uint256 id_) public {
        id = id_;
    }

    function setAfterTokenTransferActive(bool active) public {
        afterTokenTransferActive = active;
    }
}
