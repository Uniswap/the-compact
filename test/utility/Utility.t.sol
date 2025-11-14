// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Utility } from "../../src/utility/Utility.sol";
import { TheCompact } from "../../src/TheCompact.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";

import { Setup } from "../integration/Setup.sol";
import { HelperConstants } from "../helpers/HelperConstants.sol";
import { Claim } from "../../src/types/Claims.sol";
import { Component } from "../../src/types/Components.sol";

// ============= Test Harness =============

contract UtilityTestHarness is Utility {
    function THE_COMPACT_ADDRESS() external pure returns (address) {
        return THE_COMPACT;
    }

    function TSTORE_TEST_CONTRACT_ADDRESS() external pure returns (address) {
        return TSTORE_TEST_CONTRACT;
    }

    function exposed_checkTstoreAvailable() external view returns (bool) {
        return checkTstoreAvailable();
    }

    function exposed_settledBalanceOf(address owner, uint256 id) external view returns (uint256) {
        return settledBalanceOf(owner, id);
    }

    function tstoreInitialSupport() external view returns (bool) {
        return TSTORE_INITIAL_SUPPORT;
    }
}

// ============= Test Contracts =============

contract UtilityTest is Setup {
    UtilityTestHarness public utilityHarness;
    uint256 private id;

    function setUp() public override {
        super.setUp();

        // Deploy harness AFTER environment is ready
        utilityHarness = new UtilityTestHarness();

        if (vm.envOr("COVERAGE", false)) {
            // Deploy the compact on the correct address for coverage
            vm.etch(utilityHarness.THE_COMPACT_ADDRESS(), address(theCompact).code);
            theCompact = TheCompact(utilityHarness.THE_COMPACT_ADDRESS());
        }
    }

    function test_checkTheCompactAddress() public view {
        assertEq(address(theCompact), utilityHarness.THE_COMPACT_ADDRESS());
    }

    function test_checkCheckTstoreAvailable_success() public view {
        if (!vm.envOr("COVERAGE", false)) {
            bool available = utilityHarness.exposed_checkTstoreAvailable();
            assertTrue(available);
        }
    }

    function test_checkCheckTstoreAvailable_failure() public {
        // Deploy a contract that immediately reverts to simulate TSTORE not being available
        bytes memory revertCode = hex"5f5ffd"; // PUSH0 PUSH0 REVERT
        vm.etch(utilityHarness.TSTORE_TEST_CONTRACT_ADDRESS(), revertCode);
        bool available = utilityHarness.exposed_checkTstoreAvailable();
        assertFalse(available);
    }
}

contract UtilityTest_Transient is Setup {
    UtilityTestHarness public utilityHarness;
    bytes12 lockTag;
    uint256 private idEth;
    uint256 private idERC20;
    CheckBalanceDuringTransfer public checkBalanceDuringTransfer;

    function setUp() public override {
        super.setUp();

        // Deploy harness AFTER environment is ready (tstore available)
        utilityHarness = new UtilityTestHarness();

        if (vm.envOr("COVERAGE", false)) {
            // Deploy the compact on the correct address for coverage
            vm.etch(utilityHarness.THE_COMPACT_ADDRESS(), address(theCompact).code);
            theCompact = TheCompact(utilityHarness.THE_COMPACT_ADDRESS());
        }

        (, lockTag) = _registerAllocator(alwaysOKAllocator);
        idEth = theCompact.depositNative{ value: 1e18 }(lockTag, address(this));

        // Deploy malicious ERC20 token with harness
        checkBalanceDuringTransfer = new CheckBalanceDuringTransfer(utilityHarness);
        // Set approval
        checkBalanceDuringTransfer.approve(address(theCompact), 1e18);
        // Deposit malicious ERC20 token
        idERC20 = theCompact.depositERC20(address(checkBalanceDuringTransfer), lockTag, 1e18, address(this));
        checkBalanceDuringTransfer.setId(idERC20);
    }

    function test_makeSureTransientStorageIsUsed() public {
        vm.expectRevert(abi.encodeWithSignature("TStoreAlreadyActivated()"));
        theCompact.__activateTstore();
    }

    function test_checkSettledBalanceOf_transient() public view {
        uint256 balance = utilityHarness.exposed_settledBalanceOf(address(this), idEth);
        assertEq(balance, 1e18);
    }

    function test_checkSettledBalanceOf_transient_reentrant() public {
        uint256 balance = utilityHarness.exposed_settledBalanceOf(address(this), idERC20);
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

        balance = utilityHarness.exposed_settledBalanceOf(address(this), idERC20);
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
        balance = utilityHarness.exposed_settledBalanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 0);
    }
}

contract UtilityTest_NonTransient is Setup {
    UtilityTestHarness public utilityHarness;
    bytes12 lockTag;
    uint256 private idEth;
    uint256 private idERC20;
    CheckBalanceDuringTransfer public checkBalanceDuringTransfer;

    function setUp() public override {
        super.setUp();

        if (vm.envOr("COVERAGE", false)) {
            // Deploy the compact on the correct address for coverage
            vm.etch(address(0x00000000000000171ede64904551eeDF3C6C9788), address(theCompact).code);
            theCompact = TheCompact(address(0x00000000000000171ede64904551eeDF3C6C9788));
        }

        // CRITICAL: Make TSTORE_TEST_CONTRACT revert to simulate tstore unavailable BEFORE deploying harness
        bytes memory revertCode = hex"5f5ffd"; // PUSH0 PUSH0 REVERT
        vm.etch(address(0x627c1071d6A691688938Bb856659768398262690), revertCode);

        // Deploy harness AFTER environment manipulation (tstore unavailable)
        utilityHarness = new UtilityTestHarness();

        // Also etch the no-tstore bytecode to TheCompact for the actual tests
        bytes memory deployedCode = HelperConstants.theCompact_deployedBytecode_noTransientStorage;
        vm.etch(address(0x00000000000000171ede64904551eeDF3C6C9788), deployedCode);

        (, lockTag) = _registerAllocator(alwaysOKAllocator);
        idEth = theCompact.depositNative{ value: 1e18 }(lockTag, address(this));

        // Deploy malicious ERC20 token with harness
        checkBalanceDuringTransfer = new CheckBalanceDuringTransfer(utilityHarness);
        // Set approval
        checkBalanceDuringTransfer.approve(address(theCompact), 1e18);
        // Deposit malicious ERC20 token
        idERC20 = theCompact.depositERC20(address(checkBalanceDuringTransfer), lockTag, 1e18, address(this));
        checkBalanceDuringTransfer.setId(idERC20);
    }

    function test_checkTheCompactAddress() public view {
        assertEq(address(theCompact), utilityHarness.THE_COMPACT_ADDRESS());
    }

    function test_makeSureTransientStorageIsNotUsed() public {
        theCompact.__activateTstore();
    }

    function test_checkSettledBalanceOf_nonTransient() public view {
        uint256 balance = utilityHarness.exposed_settledBalanceOf(address(this), idEth);
        assertEq(balance, 1e18);
    }

    function test_checkSettledBalanceOf_nonTransient_reentrant() public {
        uint256 balance = utilityHarness.exposed_settledBalanceOf(address(this), idERC20);
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

        balance = utilityHarness.exposed_settledBalanceOf(address(this), idERC20);
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
        balance = utilityHarness.exposed_settledBalanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = theCompact.balanceOf(address(this), idERC20);
        assertEq(balance, 1e18);
        balance = checkBalanceDuringTransfer.balanceOf(address(this));
        assertEq(balance, 0);
    }
}

// ============= Mock Contracts =============

contract CheckBalanceDuringTransfer is ERC20 {
    UtilityTestHarness private immutable _HARNESS;

    uint256 private id;
    bool public afterTokenTransferActive;

    constructor(UtilityTestHarness harness_) {
        _HARNESS = harness_;
        _mint(msg.sender, 1e18);
    }

    function _afterTokenTransfer(address from, address, uint256) internal view override {
        if (afterTokenTransferActive) {
            _HARNESS.exposed_settledBalanceOf(from, id);
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
