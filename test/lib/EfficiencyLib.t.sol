// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";
import { EfficiencyLib } from "src/lib/EfficiencyLib.sol";
import { Scope } from "src/types/Scope.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";

contract EfficiencyLibTest is Test {
    using EfficiencyLib for *;

    function testUsingCallerIfNull_NonNull() public view {
        address testAddress = address(0xdeadbeef);
        assertEq(testAddress.usingCallerIfNull(), testAddress, "Should return original address if non-null");
    }

    function testUsingCallerIfNull_Null() public view {
        assertEq(address(0).usingCallerIfNull(), msg.sender, "Should return caller address if null");
    }

    function testFuzzUsingCallerIfNull(address testAddress) public view {
        vm.assume(testAddress != address(0));
        assertEq(testAddress.usingCallerIfNull(), testAddress, "Fuzz test for usingCallerIfNull failed");
    }

    function testBoolAnd() public pure {
        assertTrue(true.and(true), "true && true should be true");
        assertFalse(true.and(false), "true && false should be false");
        assertFalse(false.and(true), "false && true should be false");
        assertFalse(false.and(false), "false && false should be false");
    }

    function testBoolOr() public pure {
        assertTrue(true.or(true), "true || true should be true");
        assertTrue(true.or(false), "true || false should be true");
        assertTrue(false.or(true), "false || true should be true");
        assertFalse(false.or(false), "false || false should be false");
    }

    function testAsBool() public pure {
        assertTrue(uint256(1).asBool(), "1 should be true");
        assertFalse(uint256(0).asBool(), "0 should be false");
    }

    function testFuzzAsBool(uint256 val) public pure {
        bool expected = val != 0;
        assertEq(val.asBool(), expected, "Fuzz test for asBool failed");
    }

    function testAsBytes12() public pure {
        uint256 val = type(uint240).max;
        bytes12 expected = bytes12(bytes32(val));
        assertEq(val.asBytes12(), expected, "Should convert uint256 to bytes12");

        uint256 highVal = (uint256(1234567890) << 160) | val;
        bytes12 truncated = bytes12(bytes32(highVal));
        assertEq(highVal.asBytes12(), truncated, "Should truncate upper bits for bytes12");
    }

    function testFuzzAsBytes12(uint256 val) public pure {
        bytes12 expected = bytes12(bytes32(val));
        assertEq(val.asBytes12(), expected, "Fuzz test for asBytes12 failed");
    }

    function testAsSanitizedAddress() public pure {
        uint256 val = uint256(uint160(address(0x123)));
        address expected = address(uint160(val));
        assertEq(val.asSanitizedAddress(), expected, "Should convert uint256 to address");

        // Test with upper bits set (should be sanitized)
        uint256 highVal = (uint256(1234567890) << 160) | val;
        assertEq(highVal.asSanitizedAddress(), expected, "Should sanitize upper bits for address");
    }

    function testFuzzAsSanitizedAddress(uint256 val) public pure {
        address expected = address(uint160(val));
        assertEq(val.asSanitizedAddress(), expected, "Fuzz test for asSanitizedAddress failed");
    }

    function testIsNullAddress() public view {
        assertTrue(address(0).isNullAddress(), "address(0) should be null");
        assertFalse(address(1).isNullAddress(), "address(1) should not be null");
        assertFalse(address(this).isNullAddress(), "address(this) should not be null");
    }

    function testFuzzIsNullAddress(address testAddress) public pure {
        bool expected = testAddress == address(0);
        assertEq(testAddress.isNullAddress(), expected, "Fuzz test for isNullAddress failed");
    }

    function testAsUint256() public pure {
        assertTrue(1 == bool(true).asUint256(), "bool(true) -> 1");
        assertTrue(0 == bool(false).asUint256(), "bool(false) -> 0");

        // uint8 u8Val = 42;
        // assertEq(u8Val.asUint256(), 42, "uint8 -> uint256");

        uint96 u96Val = 96000;
        assertEq(u96Val.asUint256(), 96000, "uint96 -> uint256");

        bytes12 b12Val = 0x1234567890abcdef12345678;
        assertEq(b12Val.asUint256(), uint256(bytes32(b12Val)), "bytes12 -> uint256");

        assertEq(Scope.Multichain.asUint256(), uint256(Scope.Multichain), "Scope -> uint256");
        assertEq(Scope.ChainSpecific.asUint256(), uint256(Scope.ChainSpecific), "Scope -> uint256");

        address addrVal = address(0xcafe);
        assertEq(addrVal.asUint256(), uint256(uint160(addrVal)), "address -> uint256");

        assertEq(ResetPeriod.OneSecond.asUint256(), uint256(ResetPeriod.OneSecond), "ResetPeriod -> uint256");
    }

    function testAsResetPeriod() public pure {
        uint256 periodVal = uint256(ResetPeriod.OneDay);
        assertEq(uint8(periodVal.asResetPeriod()), uint8(ResetPeriod.OneDay), "uint256 -> ResetPeriod");
    }

    function testFuzzAsResetPeriod(uint8 periodVal) public pure {
        vm.assume(periodVal < 8);
        ResetPeriod actualEnum = periodVal.asResetPeriod();
        assertEq(uint8(actualEnum), uint8(periodVal), "Fuzz test for asResetPeriod (uint8 value) failed");
    }
}
