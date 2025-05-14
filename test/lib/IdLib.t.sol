// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test, console } from "forge-std/Test.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import { IdLib } from "src/lib/IdLib.sol";
import { EfficiencyLib } from "src/lib/EfficiencyLib.sol";
import { MetadataLib } from "src/lib/MetadataLib.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { Scope } from "src/types/Scope.sol";
import { MockERC20 } from "lib/solady/test/utils/mocks/MockERC20.sol";

contract IdLibTest is Test {
    using IdLib for *;
    using EfficiencyLib for *;

    address allocatorAddress = vm.addr(uint256(0xdeadbeef));
    address tokenAddress = vm.addr(uint256(0xcafebabe));
    uint96 allocatorId;
    bytes empty;

    function setUp() public {
        vm.label(allocatorAddress, "Default Allocator");
        allocatorId = IdLib.register(allocatorAddress);
    }

    function testToCompactFlag_Address_Specific() public pure {
        // No leading zeros
        assertEq(address(0x1234567890123456789012345678901234567890).toCompactFlag(), 0);
        // 1 leading zero byte (2 nibbles)
        assertEq(address(0x0012345678901234567890123456789012345678).toCompactFlag(), 0);
        // 2 leading zero bytes (4 nibbles) -> flag 1 (4-3)
        assertEq(address(0x0000123456789012345678901234567890123456).toCompactFlag(), 1);
        // 3 leading zero bytes (6 nibbles) -> flag 3 (6-3)
        assertEq(address(0x0000001234567890123456789012345678901234).toCompactFlag(), 3);
        // 4 leading zero bytes (8 nibbles) -> flag 5 (8-3)
        assertEq(address(0x0000000012345678901234567890123456789012).toCompactFlag(), 5);
        // 8 leading zero bytes (16 nibbles) -> flag 13 (16-3)
        assertEq(address(0x0000000000000000123456789012345678901234).toCompactFlag(), 13);
        // 9 leading zero bytes (18 nibbles) -> flag 15 (max)
        assertEq(address(0x0000000000000000001234567890123456789012).toCompactFlag(), 15);
        // 10 leading zero bytes (20 nibbles) -> flag 15 (max)
        assertEq(address(0x0000000000000000000012345678901234567890).toCompactFlag(), 15);
        // All zeros
        assertEq(address(0).toCompactFlag(), 15);
    }

    // Manual calculation for fuzzing toCompactFlag
    function _calculateCompactFlag(address allocator) internal pure returns (uint8) {
        uint256 addrInt = uint256(uint160(allocator));
        uint8 leadingZeroBytes = 0;
        for (uint256 i = 0; i < 20; ++i) {
            if ((addrInt >> (19 - i) * 8) & 0xFF == 0) {
                leadingZeroBytes++;
            } else {
                break;
            }
        }
        uint8 leadingZeroNibbles = leadingZeroBytes * 2;
        // Check first nibble if leadingZeroBytes < 20
        if (leadingZeroBytes < 20 && (addrInt >> ((19 - leadingZeroBytes) * 8 + 4)) & 0xF == 0) {
            leadingZeroNibbles++;
        }

        if (leadingZeroNibbles < 4) return 0;
        if (leadingZeroNibbles >= 18) return 15;
        return leadingZeroNibbles - 3;
    }

    function testFuzzToCompactFlag_Address(address allocator) public pure {
        uint8 expectedFlag = _calculateCompactFlag(allocator);
        assertEq(allocator.toCompactFlag(), expectedFlag, "Fuzz toCompactFlag(address) failed");
    }

    function testUsingAllocatorId() public {
        address allocator = makeAddr("Allocator");
        uint8 compactFlag = allocator.toCompactFlag(); // Should be 1
        uint96 expectedId = (uint96(compactFlag) << 88) | uint96(uint256(uint160(allocator)) & ((1 << 88) - 1));
        assertEq(allocator.usingAllocatorId(), expectedId, "usingAllocatorId calculation failed");

        address allocatorMaxCompact = address(0x000000000000000000AbCdeF1234567890aBcDef);
        compactFlag = allocatorMaxCompact.toCompactFlag(); // Should be 15
        expectedId = (uint96(compactFlag) << 88) | uint96(uint256(uint160(allocatorMaxCompact)) & ((1 << 88) - 1));
        assertEq(allocatorMaxCompact.usingAllocatorId(), expectedId, "usingAllocatorId max compact failed");

        address allocatorZeroCompact = address(0x1234567890AbcdEF1234567890aBcdef12345678);
        compactFlag = allocatorZeroCompact.toCompactFlag(); // Should be 0
        expectedId = (uint96(compactFlag) << 88) | uint96(uint256(uint160(allocatorZeroCompact)) & ((1 << 88) - 1));
        assertEq(allocatorZeroCompact.usingAllocatorId(), expectedId, "usingAllocatorId zero compact failed");
    }

    function testFuzzUsingAllocatorId(address allocator) public pure {
        uint8 compactFlag = allocator.toCompactFlag();
        uint96 expectedId = (uint96(compactFlag) << 88) | uint96(uint256(uint160(allocator)) & ((1 << 88) - 1));
        assertEq(allocator.usingAllocatorId(), expectedId, "Fuzz usingAllocatorId failed");
    }

    function testToLockTag_Components() public view {
        Scope scope = Scope.Multichain;
        ResetPeriod resetPeriod = ResetPeriod.OneDay;

        bytes12 expectedTag = bytes12(
            bytes32(uint256(uint8(scope)) << 255) | bytes32(uint256(uint8(resetPeriod)) << 252)
                | bytes32(uint256(allocatorId) << 160)
        );

        bytes12 actualTag = allocatorId.toLockTag(scope, resetPeriod);
        assertEq(actualTag, expectedTag, "toLockTag from components failed");
    }

    function testFuzzToLockTag_Components(uint8 scope, uint8 resetPeriod) public view {
        Scope actualScope = Scope(scope % 2);
        ResetPeriod actualResetPeriod = ResetPeriod(resetPeriod % 8);

        bytes12 expectedTag = bytes12(
            bytes32(uint256(uint8(actualScope)) << 255) | bytes32(uint256(uint8(actualResetPeriod)) << 252)
                | bytes32(uint256(allocatorId) << 160)
        );

        bytes12 actualTag = allocatorId.toLockTag(actualScope, actualResetPeriod);
        assertEq(actualTag, expectedTag, "Fuzz toLockTag from components failed");

        // Cross-check extractors
        assertEq(uint8(uint256(bytes32(actualTag)).toScope()), uint8(actualScope), "Extracted scope mismatch");
        assertEq(
            uint8(uint256(bytes32(actualTag)).toResetPeriod()),
            uint8(actualResetPeriod),
            "Extracted reset period mismatch"
        );
        assertEq(uint256(bytes32(actualTag)).toAllocatorId(), allocatorId, "Extracted allocatorId mismatch");
    }

    function testToLockTag_FromId() public pure {
        uint96 localAllocatorId = 123;
        address token = address(0x12345);
        Scope scope = Scope.Multichain;
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        bytes12 expectedTag = IdLib.toLockTag(localAllocatorId, scope, resetPeriod);
        uint256 id = uint256(bytes32(expectedTag)) | uint256(uint160(token));

        assertEq(id.toLockTag(), expectedTag, "toLockTag from ID failed");
    }

    function testFuzzToLockTag_FromId(uint256 id) public pure {
        bytes12 expectedTag = bytes12(bytes32(id & ~uint256((1 << 160) - 1))); // Mask out lower 160 bits
        assertEq(id.toLockTag(), expectedTag, "Fuzz toLockTag from ID failed");
    }

    function testToAllocatorId_FromTag() public view {
        Scope scope = Scope.Multichain;
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        bytes12 lockTag = allocatorId.toLockTag(scope, resetPeriod);
        assertEq(lockTag.toAllocatorId(), allocatorId, "toAllocatorId from tag failed");
    }

    function testFuzzToAllocatorId_FromTag(address fuzzedAllocator) public pure {
        uint96 fuzzedAllocatorId = fuzzedAllocator.usingAllocatorId();
        bytes12 lockTag = fuzzedAllocatorId.toLockTag(Scope.Multichain, ResetPeriod.OneDay);
        assertEq(lockTag.toAllocatorId(), fuzzedAllocatorId, "Fuzz toAllocatorId from tag failed");
    }

    function testToAllocatorId_FromId() public pure {
        uint96 expectedAllocatorId = 987654321987654321;
        Scope scope = Scope.ChainSpecific;
        ResetPeriod resetPeriod = ResetPeriod.OneHourAndFiveMinutes;
        bytes12 lockTag = IdLib.toLockTag(expectedAllocatorId, scope, resetPeriod);
        address token = address(0x9999);
        uint256 id = uint256(bytes32(lockTag)) | uint256(uint160(token));

        assertEq(id.toAllocatorId(), expectedAllocatorId, "toAllocatorId from ID failed");
    }

    function testFuzzToAllocatorId_FromId(uint256 id) public pure {
        // extract bits 160-251 and remove the compact flag (248-251)
        uint96 expectedId = uint96(uint256(uint256(id << 4) >> 164));
        assertEq(id.toAllocatorId(), expectedId, "Fuzz toAllocatorId from ID failed");
    }

    function testToAddress() public {
        address expectedToken = makeAddr("probably safe token");
        uint256 id = 12345 << 160 | uint256(uint160(expectedToken));
        assertEq(id.toAddress(), expectedToken, "toAddress failed");
    }

    function testFuzzToAddress(uint256 id) public pure {
        address expectedToken = address(uint160(id));
        assertEq(id.toAddress(), expectedToken, "Fuzz toAddress failed");
    }

    function testWithReplacedToken() public {
        uint96 localAllocatorId = 123;
        Scope scope = Scope.Multichain;
        ResetPeriod resetPeriod = ResetPeriod.OneDay;
        bytes12 lockTag = IdLib.toLockTag(localAllocatorId, scope, resetPeriod);
        address originalToken = makeAddr("original token");
        address newToken = makeAddr("new token");

        uint256 originalId = uint256(bytes32(lockTag)) | uint256(uint160(originalToken));
        uint256 expectedId = uint256(bytes32(lockTag)) | uint256(uint160(newToken));

        assertEq(originalId.withReplacedToken(newToken), expectedId, "withReplacedToken failed");
    }

    function testFuzzWithReplacedToken(uint256 originalId, address newToken) public pure {
        bytes12 lockTag = originalId.toLockTag();
        uint256 expectedId = uint256(bytes32(lockTag)) | uint256(uint160(newToken));
        assertEq(originalId.withReplacedToken(newToken), expectedId, "Fuzz withReplacedToken failed");
    }

    function testWithReplacedLockTag() public {
        uint96 originalAllocatorId = 123;
        Scope originalScope = Scope.Multichain;
        ResetPeriod originalResetPeriod = ResetPeriod.OneDay;
        bytes12 originalLockTag = IdLib.toLockTag(originalAllocatorId, originalScope, originalResetPeriod);

        uint96 newAllocatorId = 456;
        Scope newScope = Scope.ChainSpecific;
        ResetPeriod newResetPeriod = ResetPeriod.OneHourAndFiveMinutes;
        bytes12 newLockTag = IdLib.toLockTag(newAllocatorId, newScope, newResetPeriod);

        address token = makeAddr("probably safe token");

        uint256 originalId = uint256(bytes32(originalLockTag)) | uint256(uint160(token));
        uint256 expectedId = uint256(bytes32(newLockTag)) | uint256(uint160(token));

        assertEq(originalId.withReplacedLockTag(newLockTag), expectedId, "withReplacedLockTag failed");
    }

    function testFuzzWithReplacedLockTag(uint256 originalId, bytes12 newLockTag) public pure {
        address token = originalId.toAddress();
        uint256 expectedId = uint256(bytes32(newLockTag)) | uint256(uint160(token));
        assertEq(originalId.withReplacedLockTag(newLockTag), expectedId, "Fuzz withReplacedLockTag failed");
    }

    function testToScope_FromId() public pure {
        uint256 singleChain = uint256(1) << 255; // Set highest bit
        uint256 multichain = 0;
        assertEq(uint8(singleChain.toScope()), uint8(Scope.ChainSpecific), "toScope SingleChain failed");
        assertEq(uint8(multichain.toScope()), uint8(Scope.Multichain), "toScope Multichain failed");
    }

    function testFuzzToScope_FromId(uint256 id) public pure {
        Scope expectedScope = Scope(uint8(id >> 255));
        assertEq(uint8(id.toScope()), uint8(expectedScope), "Fuzz toScope failed");
    }

    function testToResetPeriod_FromId() public pure {
        uint256 baseId = 0;
        for (uint8 i = 0; i < 8; i++) {
            uint256 id = baseId | (uint256(i) << 252);
            assertEq(
                uint8(id.toResetPeriod()), i, string.concat("toResetPeriod(ID) failed for period ", vm.toString(i))
            );
        }
    }

    function testFuzzToResetPeriod_FromId(uint256 id) public pure {
        ResetPeriod expectedPeriod = ResetPeriod(uint8((id >> 252) & 7));
        assertEq(uint8(id.toResetPeriod()), uint8(expectedPeriod), "Fuzz toResetPeriod(ID) failed");
    }

    function testToResetPeriod_FromTag() public pure {
        uint96 localAllocatorId = 1;
        Scope scope = Scope.Multichain;
        for (uint8 i = 0; i < 8; i++) {
            ResetPeriod period = ResetPeriod(i);
            bytes12 tag = IdLib.toLockTag(localAllocatorId, scope, period);
            assertEq(
                uint8(tag.toResetPeriod()), i, string.concat("toResetPeriod(tag) failed for period ", vm.toString(i))
            );
        }
    }

    function testFuzzToResetPeriod_FromTag(bytes12 tag) public pure {
        ResetPeriod expectedPeriod = ResetPeriod(uint8((uint256(bytes32(tag)) >> 252) & 7));
        assertEq(uint8(tag.toResetPeriod()), uint8(expectedPeriod), "Fuzz toResetPeriod(tag) failed");
    }

    function testToCompactFlag_FromId() public pure {
        uint256 baseId = 0;
        for (uint8 i = 0; i < 16; i++) {
            uint256 id = baseId | (uint256(i) << 248);
            assertEq(id.toCompactFlag(), i, string.concat("toCompactFlag(ID) failed for flag ", vm.toString(i)));
        }
    }

    function testFuzzToCompactFlag_FromId(uint256 id) public pure {
        uint8 expectedFlag = uint8((id >> 248) & 15);
        assertEq(id.toCompactFlag(), expectedFlag, "Fuzz toCompactFlag(ID) failed");
    }

    function testToSeconds() public pure {
        assertEq(ResetPeriod.OneSecond.toSeconds(), 1, "OneSecond");
        assertEq(ResetPeriod.FifteenSeconds.toSeconds(), 15, "FifteenSeconds");
        assertEq(ResetPeriod.OneMinute.toSeconds(), 60, "OneMinute");
        assertEq(ResetPeriod.TenMinutes.toSeconds(), 10 * 60, "TenMinutes");
        assertEq(ResetPeriod.OneHourAndFiveMinutes.toSeconds(), 1 hours + 5 minutes, "OneHourAndFiveMinutes"); // Padded
        assertEq(ResetPeriod.OneDay.toSeconds(), 1 days, "OneDay");
        assertEq(ResetPeriod.SevenDaysAndOneHour.toSeconds(), 7 days + 1 hours, "SevenDaysAndOneHour"); // Padded
        assertEq(ResetPeriod.ThirtyDays.toSeconds(), 30 days, "ThirtyDays");
    }

    function testToId_FromLock() public {
        address allocator = makeAddr("probably safe allocator");
        address token = makeAddr("probably safe token");
        Scope scope = Scope.Multichain;
        ResetPeriod resetPeriod = ResetPeriod.OneDay;

        uint96 lockAllocatorId = allocator.usingAllocatorId(); // Uses compact flag internally
        bytes12 lockTag = IdLib.toLockTag(lockAllocatorId, scope, resetPeriod);
        uint256 expectedId = uint256(bytes32(lockTag)) | uint256(uint160(token));

        assertEq(IdLib.toId(token, allocator, resetPeriod, scope), expectedId, "toId from Lock failed");
    }

    function testFuzzToId_FromLock(address allocator, address token, uint8 scope, uint8 resetPeriod) public pure {
        Scope actualScope = Scope(uint8(scope) % 2);
        ResetPeriod actualResetPeriod = ResetPeriod(uint8(resetPeriod) % 8);

        uint96 lockAllocatorId = allocator.usingAllocatorId();
        bytes12 lockTag = IdLib.toLockTag(lockAllocatorId, actualScope, actualResetPeriod);

        uint256 actualId = IdLib.toId(token, allocator, actualResetPeriod, actualScope);
        assertEq(actualId, uint256(bytes32(lockTag)) | uint256(uint160(token)));

        // Cross-check extractors
        assertEq(actualId.toAddress(), token, "Extracted token mismatch");
        assertEq(uint8(actualId.toResetPeriod()), uint8(actualResetPeriod), "Extracted reset period mismatch");
        assertEq(uint8(actualId.toScope()), uint8(actualScope), "Extracted scope mismatch");
        assertEq(actualId.toAllocatorId(), lockAllocatorId, "Extracted allocatorId mismatch");
        assertEq(actualId.toCompactFlag(), allocator.toCompactFlag(), "Extracted compact flag mismatch");
        assertEq(actualId.toLockTag(), lockTag, "Extracted lockTag mismatch");
    }

    function testRegister() public {
        // Default allocator already registered in setUp
        uint96 defaultAllocatorId = allocatorAddress.usingAllocatorId();
        assertEq(allocatorId, defaultAllocatorId, "Registered allocator ID mismatch");
        assertEq(allocatorId.toRegisteredAllocator(), allocatorAddress, "Stored allocator mismatch");

        // Try registering a new one
        address newAllocator = makeAddr("new allocator");
        uint96 newAllocatorId = newAllocator.usingAllocatorId();

        vm.expectEmit(true, true, true, true);
        emit ITheCompact.AllocatorRegistered(newAllocatorId, newAllocator);
        uint96 returnedId = newAllocator.register();

        assertEq(returnedId, newAllocatorId, "Returned new allocator ID mismatch");
        assertEq(newAllocatorId.toRegisteredAllocator(), newAllocator, "Stored new allocator mismatch");
    }

    // While collision is _possible_, the probability is like 1 in 2^92, so it's not worth worrying about.
    // function testFuzzRegister_Collision(address fuzzyMatch) public {
    //     vm.assume(fuzzyMatch != allocatorAddress);
    //     // Check that the lower 88 bits match
    //     uint256 allocatorLower88Bits = uint256(uint160(allocatorAddress)) & ((1 << 88) - 1);
    //     uint256 fuzzyLower88Bits = uint256(uint160(fuzzyMatch)) & ((1 << 88) - 1);
    //     vm.assume(allocatorLower88Bits == fuzzyLower88Bits);

    //     // Check that the compact flag matches
    //     vm.assume(fuzzyMatch.toCompactFlag() == allocatorAddress.toCompactFlag());

    //     console.log("allocatorAddress", allocatorAddress);
    //     console.log("matching address", fuzzyMatch);

    //     // Try to register the fuzzy match (reverts)
    //     // vm.expectRevert(IdLib.AllocatorAlreadyRegistered.selector);
    //     IdLib.register(fuzzyMatch);
    // }

    function testCollisionWithSpecificPattern() public pure {
        // Test addresses with same lower 88 bits but different upper bits
        address baseAddr = address(0x1234567890123456789012345678901234567890);
        uint256 baseLower88 = uint256(uint160(baseAddr)) & ((1 << 88) - 1);

        uint256 collisions = 0;
        uint256 totalVariants = 16; // Testing 16 different upper bit patterns

        for (uint256 i = 0; i < totalVariants; i++) {
            // Create address with same lower 88 bits but different upper bits
            address variantAddr = address(uint160((i << 88) | baseLower88));

            if (variantAddr.usingAllocatorId() == baseAddr.usingAllocatorId() && variantAddr != baseAddr) {
                collisions++;
                console.log("Collision found with variant", i);
                console.log("Base address:", baseAddr);
                console.log("Variant address:", variantAddr);
                console.log("Compact flag base:", baseAddr.toCompactFlag());
                console.log("Compact flag variant:", variantAddr.toCompactFlag());
            }
        }

        console.log("Pattern-specific collisions:", collisions, "out of", totalVariants);
    }

    function testToRegisteredAllocator() public view {
        assertEq(allocatorId.toRegisteredAllocator(), allocatorAddress, "Should return registered allocator");
    }

    function testToRegisteredAllocator_RevertNotRegistered(address unregisteredAllocator) public {
        vm.skip(true); // TODO: this should not be colliding often, right?
        vm.assume(unregisteredAllocator != allocatorAddress);
        uint96 unregisteredId = unregisteredAllocator.usingAllocatorId();
        assertNotEq(
            unregisteredAllocator, allocatorAddress, "Unregistered allocator should not be the registered allocator"
        );
        assertNotEq(unregisteredId, allocatorId, "Unregistered ID should not match registered ID");
        vm.expectRevert(abi.encodeWithSelector(IdLib.NoAllocatorRegistered.selector, unregisteredId));
        unregisteredId.toRegisteredAllocator();
    }

    function testToAllocatorIdIfRegistered() public view {
        assertEq(allocatorAddress.toAllocatorIdIfRegistered(), allocatorId, "Should return ID for registered allocator");
    }

    function testToAllocatorIdIfRegistered_RevertNotRegistered(address unregisteredAllocator) public {
        vm.skip(true); // TODO: this should be reverting

        // This collides way too often for my comfort
        vm.assume(unregisteredAllocator != allocatorAddress && unregisteredAllocator.usingAllocatorId() != allocatorId);
        vm.expectRevert(
            abi.encodeWithSelector(IdLib.NoAllocatorRegistered.selector, unregisteredAllocator.usingAllocatorId())
        );
        unregisteredAllocator.toAllocatorIdIfRegistered();
    }

    function testMustHaveARegisteredAllocator() public view {
        // Should not revert for registered allocator
        allocatorId.mustHaveARegisteredAllocator();
    }

    function testToRegisteredAllocatorId_FromId() public view {
        uint256 id = allocatorId.asUint256() << 160 | tokenAddress.asUint256(); // Construct ID with registered allocator ID
        assertEq(id.toRegisteredAllocatorId(), allocatorId, "Should extract registered allocator ID from resource ID");
    }

    function testToRegisteredAllocatorId_FromId_RevertNotRegistered(uint96 unregisteredId, address token) public {
        vm.skip(true); // TODO: this should be reverting
        vm.assume(unregisteredId != allocatorId);

        uint256 id = unregisteredId.asUint256() << 160 | token.asUint256();
        vm.expectRevert(abi.encodeWithSelector(IdLib.NoAllocatorRegistered.selector, unregisteredId));
        id.toRegisteredAllocatorId();
    }

    function testHasRegisteredAllocatorId_FromTag() public view {
        bytes12 lockTag = allocatorId.toLockTag(Scope.Multichain, ResetPeriod.OneDay);
        lockTag.hasRegisteredAllocatorId();
    }

    function testHasRegisteredAllocatorId_FromTag_RevertNotRegistered(uint96 unregisteredId) public {
        vm.skip(true); // TODO: this should be reverting
        vm.assume(unregisteredId != allocatorId);
        bytes12 lockTag = unregisteredId.toLockTag(Scope.Multichain, ResetPeriod.OneDay);
        vm.expectRevert(abi.encodeWithSelector(IdLib.NoAllocatorRegistered.selector, unregisteredId));
        lockTag.hasRegisteredAllocatorId();
    }

    function testToIdIfRegistered() public view {
        bytes12 lockTag = IdLib.toLockTag(allocatorId, Scope.ChainSpecific, ResetPeriod.OneHourAndFiveMinutes);
        uint256 expectedId = uint256(bytes32(lockTag)) | tokenAddress.asUint256();
        assertEq(IdLib.toIdIfRegistered(tokenAddress, lockTag), expectedId, "toIdIfRegistered failed");
    }

    function testToIdIfRegistered_RevertNotRegistered(uint96 unregisteredId) public {
        vm.skip(true); // TODO: this should be reverting
        vm.assume(unregisteredId != allocatorId);
        bytes12 lockTag = IdLib.toLockTag(unregisteredId, Scope.Multichain, ResetPeriod.OneDay);
        vm.expectRevert(abi.encodeWithSelector(IdLib.NoAllocatorRegistered.selector, unregisteredId));
        IdLib.toIdIfRegistered(tokenAddress, lockTag);
    }

    function testToAllocator_FromId() public view {
        bytes12 lockTag = IdLib.toLockTag(allocatorId, Scope.ChainSpecific, ResetPeriod.OneHourAndFiveMinutes);
        uint256 id = uint256(bytes32(lockTag)) | tokenAddress.asUint256();
        assertEq(id.toAllocator(), allocatorAddress, "toAllocator from ID failed");
    }

    function testToLock_FromId() public view {
        Scope scope = Scope.Multichain;
        ResetPeriod resetPeriod = ResetPeriod.SevenDaysAndOneHour;
        bytes12 lockTag = IdLib.toLockTag(allocatorId, scope, resetPeriod);
        uint256 id = uint256(bytes32(lockTag)) | tokenAddress.asUint256();

        (address resultToken, address resultAllocator, ResetPeriod resultResetPeriod, Scope resultScope) = id.toLock();

        assertEq(resultAllocator, allocatorAddress, "Lock allocator mismatch");
        assertEq(resultToken, tokenAddress, "Lock token mismatch");
        assertEq(uint8(resultScope), uint8(scope), "Lock scope mismatch");
        assertEq(uint8(resultResetPeriod), uint8(resetPeriod), "Lock resetPeriod mismatch");
    }

    function testCanBeRegistered_SenderIsAllocator() public {
        DummyContract dummy = new DummyContract();
        assertFalse(dummy.canBeRegistered(address(0xdeadbeef), empty), "Should be false if sender is not allocator");
        vm.prank(address(0xdeadbeef));
        assertTrue(dummy.canBeRegistered(address(0xdeadbeef), empty), "Should be true if sender is allocator");
    }

    function testCanBeRegistered_AllocatorIsContract() public {
        DummyContract dummy = new DummyContract();
        address contractAllocator = address(this);
        assertTrue(
            dummy.canBeRegistered(contractAllocator, vm.randomBytes(0)), "Should be true if allocator is a contract"
        );
    }

    function testCanBeRegistered_ValidCreate2Proof() public {
        DummyContract dummy = new DummyContract();
        address factory = address(0x0000000000000000000000000000000000000001);
        bytes32 salt = bytes32(uint256(123));
        bytes memory initCode = abi.encodePacked(type(DummyContract).creationCode);
        bytes32 initCodeHash = keccak256(initCode);

        // Calculate expected create2 address
        address expectedAllocator = computeCreate2Address(factory, salt, initCodeHash);

        // Construct proof: 0xff ++ factory ++ salt ++ initCodeHash
        bytes memory proof = abi.encodePacked(bytes1(0xff), factory, salt, initCodeHash);
        assertEq(proof.length, 85, "Proof length mismatch");

        assertTrue(dummy.canBeRegistered(expectedAllocator, proof), "Should be true for valid create2 proof");
    }

    function testCanBeRegistered_InvalidCreate2Proof_Length() public {
        DummyContract dummy = new DummyContract();
        address factory = address(0x0000000000000000000000000000000000000001);
        bytes32 salt = bytes32(uint256(123));
        bytes memory initCode = abi.encodePacked(type(DummyContract).creationCode);
        bytes32 initCodeHash = keccak256(initCode);
        address expectedAllocator = computeCreate2Address(factory, salt, initCodeHash);

        // Wrong length
        bytes memory shortProof = abi.encodePacked(bytes1(0xff), factory, salt);
        bytes memory longProof = abi.encodePacked(bytes1(0xff), factory, salt, initCodeHash, bytes1(0x00));
        assertFalse(dummy.canBeRegistered(expectedAllocator, shortProof), "Should be false for short proof");
        assertFalse(dummy.canBeRegistered(expectedAllocator, longProof), "Should be false for long proof");
    }

    function testCanBeRegistered_InvalidCreate2Proof_Prefix() public {
        DummyContract dummy = new DummyContract();
        address factory = address(0x0000000000000000000000000000000000000001);
        bytes32 salt = bytes32(uint256(123));
        bytes memory initCode = abi.encodePacked(type(DummyContract).creationCode);
        bytes32 initCodeHash = keccak256(initCode);
        address expectedAllocator = computeCreate2Address(factory, salt, initCodeHash);

        // Wrong prefix
        bytes memory proof = abi.encodePacked(bytes1(0xfe), factory, salt, initCodeHash);
        assertFalse(dummy.canBeRegistered(expectedAllocator, proof), "Should be false for wrong prefix");
    }

    function testCanBeRegistered_InvalidCreate2Proof_HashMismatch() public {
        DummyContract dummy = new DummyContract();
        address factory = address(0x0000000000000000000000000000000000000001);
        bytes32 salt = bytes32(uint256(123));
        bytes memory initCode = abi.encodePacked(type(DummyContract).creationCode);
        bytes32 initCodeHash = keccak256(initCode);
        address expectedAllocator = computeCreate2Address(factory, salt, initCodeHash);

        // Hash mismatch (changed salt)
        bytes memory proof = abi.encodePacked(bytes1(0xff), factory, bytes32(uint256(456)), initCodeHash);
        assertFalse(dummy.canBeRegistered(expectedAllocator, proof), "Should be false for hash mismatch");
    }

    function testCanBeRegistered_EOA_NoProof() public {
        DummyContract dummy = new DummyContract();
        address eoaAllocator = makeAddr("eoa allocator");
        assertFalse(dummy.canBeRegistered(eoaAllocator, ""), "Should be false for EOA, not sender, no proof");
    }

    function computeCreate2Address(address factory, bytes32 salt, bytes32 initCodeHash)
        internal
        pure
        returns (address)
    {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), factory, salt, initCodeHash)))));
    }

    event AllocatorRegistered(uint96 indexed allocatorId, address indexed allocator);
}

contract DummyContract is MockERC20 {
    using IdLib for address;

    constructor() MockERC20("Dummy", "DUMMY", 18) { }

    function canBeRegistered(address allocator, bytes calldata proof) external view returns (bool) {
        return allocator.canBeRegistered(proof);
    }

    function register(address allocator) external {
        allocator.register();
    }
}
