// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test, console } from "forge-std/Test.sol";
import { Tstorish } from "../../src/lib/Tstorish.sol";
import { TstorishMock } from "../../src/test/TstorishMock.sol";

contract TstorishTest is Test {
    Tstorish public tstorish;
    TstorishMock public tstorishMock;

    function setUp() public {
        tstorish = new Tstorish();
        tstorishMock = new TstorishMock();
    }

    function test_revert_tloadTestContractDeploymentFailed() public {
        uint8 nonce = uint8(vm.getNonce(address(this)));
        address tstorishExpected = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(this), bytes1(nonce)))))
        );

        address tloadTestContractExpected = address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(tstorishExpected), bytes1(0x01)))
                )
            )
        );

        vm.etch(tloadTestContractExpected, hex"5f5ffd"); // push0 push0 revert

        vm.expectRevert(abi.encodeWithSelector(Tstorish.TloadTestContractDeploymentFailed.selector));
        new Tstorish();
    }

    function test_revert_tstoreAlreadyActivated() public {
        uint8 nonce = 1;
        address deployer = address(0x1111111111111111111111111111111111111111);

        vm.setNonce(deployer, nonce);
        vm.prank(deployer);
        Tstorish tstorishContract = new Tstorish();

        // Manipulate the tloadTestContract to revert so tstore is not supported
        address tloadTestContractExpected = address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(tstorishContract), bytes1(0x01)))
                )
            )
        );

        vm.etch(tloadTestContractExpected, hex"5f5ffd"); // push0 push0 revert

        vm.expectRevert(abi.encodeWithSelector(Tstorish.TStoreAlreadyActivated.selector));
        tstorishContract.__activateTstore();
    }

    function test_revert_TStoreNotSupported() public {
        TstorishMock tstorishContract = new TstorishMock();

        vm.expectRevert(abi.encodeWithSelector(Tstorish.TStoreNotSupported.selector));
        tstorishContract.__activateTstore();
    }

    function test_tstoreMockActivation() public {
        // mock contract starts in an "tstore disabled" state
        TstorishMock tstorishContract = new TstorishMock();

        // first set the mock value via sstore
        tstorishContract.setMockValue();

        // ensure it's found correctly and set the expected storage
        assertTrue(tstorishContract.checkMockValue());
        assertTrue(tstorishContract.checkSstoreSlot());
        assertFalse(tstorishContract.checkTstoreSlot());

        // "enable" tstore on the mock and activate it on tstorish
        tstorishContract.activateMockTstore();
        tstorishContract.__activateTstore();

        // sstore value is still correctly returned by tstorish this block
        assertTrue(tstorishContract.checkMockValue());

        // after 1 block it now doesn't find it anymore
        vm.roll(block.number + 1);
        assertFalse(tstorishContract.checkMockValue());

        tstorishContract.clearSstoreSlot();
        assertFalse(tstorishContract.checkSstoreSlot());
        assertFalse(tstorishContract.checkTstoreSlot());

        // now test setting a value using tstore
        tstorishContract.setMockValue();

        // ensure it's found correctly and set the expected storage
        assertTrue(tstorishContract.checkMockValue());
        assertFalse(tstorishContract.checkSstoreSlot());
        assertTrue(tstorishContract.checkTstoreSlot());
    }
}
