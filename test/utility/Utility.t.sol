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

        if (vm.envOr("COVERAGE", false)) {
            // Deploy the compact on the correct address for coverage
            vm.etch(address(0x00000000000000171ede64904551eeDF3C6C9788), address(theCompact).code);
            theCompact = TheCompact(address(0x00000000000000171ede64904551eeDF3C6C9788));
            // TSTORE_TEST_CONTRACT
            vm.etch(address(0x627c1071d6A691688938Bb856659768398262690), hex"3d5c");
        }

        // Deploy harness AFTER environment is ready
        utilityHarness = new UtilityTestHarness();
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

        if (vm.envOr("COVERAGE", false)) {
            // Deploy the compact on the correct address for coverage
            vm.etch(address(0x00000000000000171ede64904551eeDF3C6C9788), address(theCompact).code);
            theCompact = TheCompact(address(0x00000000000000171ede64904551eeDF3C6C9788));
            // TSTORE_TEST_CONTRACT
            vm.etch(address(0x627c1071d6A691688938Bb856659768398262690), hex"3d5c");
        }

        // Deploy harness AFTER environment is ready (tstore available)
        utilityHarness = new UtilityTestHarness();

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

    /// @notice Test that when Utility successfully activates tstore on TheCompact,
    ///         TSTORE_INITIAL_SUPPORT is false (activation pending next block)
    function test_constructor_setsFalse_whenSuccessfullyActivatesTstore() public {
        // Confirm _tstoreSupportActiveAt is 0 before deployment
        bytes32 activeAtBefore = theCompact.extsload(bytes32(uint256(0)));
        assertEq(uint256(activeAtBefore), 0, "_tstoreSupportActiveAt should be 0 before activation");

        // Re-enable tstore on the chain
        vm.etch(address(0x627c1071d6A691688938Bb856659768398262690), hex"3d5c");

        // Deploy a new Utility - it should successfully call __activateTstore()
        // because TheCompact has _tstoreInitialSupport = false and _tstoreSupportActiveAt = 0
        UtilityTestHarness newHarness = new UtilityTestHarness();

        // TSTORE_INITIAL_SUPPORT should be false because activation is pending (next block)
        assertFalse(
            newHarness.tstoreInitialSupport(), "TSTORE_INITIAL_SUPPORT should be false after successful activation"
        );

        // Confirm _tstoreSupportActiveAt is now block.number + 1
        bytes32 activeAtAfter = theCompact.extsload(bytes32(uint256(0)));
        assertEq(uint256(activeAtAfter), block.number + 1, "_tstoreSupportActiveAt should be block.number + 1");
    }

    /// @notice Test that settledBalanceOf uses extsload when _tstoreSupportActiveAt = 0
    ///         This is the default state when tstore was never activated
    function test_settledBalanceOf_usesExtsload_whenActivationIsZero() public {
        // Ensure _tstoreSupportActiveAt is 0
        vm.store(address(theCompact), bytes32(uint256(0)), bytes32(uint256(0)));

        // Set persistent storage reentrancy slot to value > 1 to trigger revert if read
        bytes32 reentrancySlot = bytes32(uint256(0x929eee149b4bd21268));
        vm.store(address(theCompact), reentrancySlot, bytes32(uint256(2)));

        // settledBalanceOf should read from persistent storage (extsload) and revert
        vm.expectRevert(abi.encodeWithSignature("BalanceNotSettled()"));
        utilityHarness.exposed_settledBalanceOf(address(this), idEth);
    }

    /// @notice Test that settledBalanceOf uses extsload when _tstoreSupportActiveAt > block.number
    ///         This happens when tstore activation is pending (takes effect next block)
    function test_settledBalanceOf_usesExtsload_whenActivationPending() public {
        // Set _tstoreSupportActiveAt to a future block
        vm.store(address(theCompact), bytes32(uint256(0)), bytes32(block.number + 1));

        // Set persistent storage reentrancy slot to value > 1 to trigger revert if read
        bytes32 reentrancySlot = bytes32(uint256(0x929eee149b4bd21268));
        vm.store(address(theCompact), reentrancySlot, bytes32(uint256(2)));

        // settledBalanceOf should read from persistent storage (extsload) and revert
        vm.expectRevert(abi.encodeWithSignature("BalanceNotSettled()"));
        utilityHarness.exposed_settledBalanceOf(address(this), idEth);
    }

    /// @notice Test that settledBalanceOf uses exttload when _tstoreSupportActiveAt <= block.number
    ///         This happens when tstore has been activated and is now active
    function test_settledBalanceOf_usesExttload_whenTstoreActive() public {
        // Set _tstoreSupportActiveAt to current block (active now)
        vm.store(address(theCompact), bytes32(uint256(0)), bytes32(block.number));

        // Set persistent storage reentrancy slot to value > 1
        // If extsload is used, this would cause a revert
        bytes32 reentrancySlot = bytes32(uint256(0x929eee149b4bd21268));
        vm.store(address(theCompact), reentrancySlot, bytes32(uint256(2)));

        // settledBalanceOf should read from transient storage (exttload), which is 0
        // So it should NOT revert and return the balance
        uint256 balance = utilityHarness.exposed_settledBalanceOf(address(this), idEth);
        assertEq(balance, 1e18, "Should return correct balance when reading from transient storage");
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

// ============= Constructor Activation Tests =============

contract UtilityTest_ConstructorActivation is Setup {
    function setUp() public override {
        super.setUp();

        if (vm.envOr("COVERAGE", false)) {
            // Deploy the compact on the correct address for coverage
            vm.etch(address(0x00000000000000171ede64904551eeDF3C6C9788), address(theCompact).code);
            theCompact = TheCompact(address(0x00000000000000171ede64904551eeDF3C6C9788));
            // TSTORE_TEST_CONTRACT
            vm.etch(address(0x627c1071d6A691688938Bb856659768398262690), hex"3d5c");
        }
    }

    /// @notice Test that when Utility is deployed after TheCompact has already activated tstore,
    ///         TSTORE_INITIAL_SUPPORT is true (the default Setup scenario)
    function test_constructor_setsTrue_whenTstoreAlreadyActiveFromSetup() public {
        // In the Setup, TheCompact is deployed with tstore support and it's already activated.
        // When Utility constructor tries __activateTstore(), it reverts with TStoreAlreadyActivated.
        // The constructor then reads _tstoreSupportActiveAt which is <= block.number,
        // so TSTORE_INITIAL_SUPPORT remains true.
        UtilityTestHarness harness = new UtilityTestHarness();

        // TSTORE_INITIAL_SUPPORT should be true because tstore is already active
        assertTrue(
            harness.tstoreInitialSupport(), "TSTORE_INITIAL_SUPPORT should be true when tstore is already active"
        );
    }

    /// @notice Test that when tstore is available but activation is pending (future block),
    ///         TSTORE_INITIAL_SUPPORT is false because _tstoreSupportActiveAt > block.number
    function test_constructor_setsFalse_whenActivationPending() public {
        // Set _tstoreSupportActiveAt to a future block to simulate pending activation
        uint256 futureBlock = block.number + 1;
        vm.store(address(theCompact), bytes32(uint256(0)), bytes32(futureBlock));

        // Deploy Utility - it should try to activate tstore, get TStoreAlreadyActivated,
        // then read _tstoreSupportActiveAt which is in the future, so TSTORE_INITIAL_SUPPORT = false
        UtilityTestHarness harness = new UtilityTestHarness();

        // TSTORE_INITIAL_SUPPORT should be false because activation is pending
        assertFalse(
            harness.tstoreInitialSupport(), "TSTORE_INITIAL_SUPPORT should be false when tstore activation is pending"
        );
    }

    /// @notice Test that when tstore is available and already activated (in a previous block),
    ///         TSTORE_INITIAL_SUPPORT is true because _tstoreSupportActiveAt <= block.number
    function test_constructor_setsTrue_whenAlreadyActivatedPreviousBlock() public {
        // Set _tstoreSupportActiveAt to a block in the past
        uint256 pastBlock = block.number - 1;
        vm.store(address(theCompact), bytes32(uint256(0)), bytes32(pastBlock));

        // Deploy Utility - it should try to activate tstore, get TStoreAlreadyActivated,
        // then read _tstoreSupportActiveAt which is in the past, so TSTORE_INITIAL_SUPPORT stays true
        UtilityTestHarness harness = new UtilityTestHarness();

        // TSTORE_INITIAL_SUPPORT should be true because tstore is already active
        assertTrue(
            harness.tstoreInitialSupport(), "TSTORE_INITIAL_SUPPORT should be true when tstore is already active"
        );
    }

    /// @notice Test that when tstore is available and already activated at exactly block.number,
    ///         TSTORE_INITIAL_SUPPORT is true because _tstoreSupportActiveAt <= block.number
    function test_constructor_setsTrue_whenActivatedAtCurrentBlock() public {
        // Set _tstoreSupportActiveAt to exactly the current block
        vm.store(address(theCompact), bytes32(uint256(0)), bytes32(block.number));

        // Deploy Utility
        UtilityTestHarness harness = new UtilityTestHarness();

        // TSTORE_INITIAL_SUPPORT should be true because _tstoreSupportActiveAt <= block.number
        assertTrue(
            harness.tstoreInitialSupport(),
            "TSTORE_INITIAL_SUPPORT should be true when tstore activated at current block"
        );
    }

    /// @notice Test that when tstore is NOT available on the chain,
    ///         TSTORE_INITIAL_SUPPORT is false and no activation is attempted
    function test_constructor_noActivation_whenTstoreUnavailable() public {
        // Make TSTORE_TEST_CONTRACT revert to simulate tstore unavailable
        bytes memory revertCode = hex"5f5ffd"; // PUSH0 PUSH0 REVERT
        vm.etch(address(0x627c1071d6A691688938Bb856659768398262690), revertCode);

        // Deploy Utility - checkTstoreAvailable() returns false, so the activation
        // logic is skipped entirely and TSTORE_INITIAL_SUPPORT stays false
        UtilityTestHarness harness = new UtilityTestHarness();

        // TSTORE_INITIAL_SUPPORT should be false because tstore is not available
        assertFalse(harness.tstoreInitialSupport(), "TSTORE_INITIAL_SUPPORT should be false when tstore unavailable");

        // Confirm _tstoreSupportActiveAt is 0 because no activation was attempted
        bytes32 activeAtAfter = theCompact.extsload(bytes32(uint256(0)));
        assertEq(uint256(activeAtAfter), 0, "_tstoreSupportActiveAt should be 0");
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
