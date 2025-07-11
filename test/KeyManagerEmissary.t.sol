// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";
import { P256VerifierEtcher } from "./helpers/P256VerifierEtcher.sol";
import { KeyManagerEmissary } from "../src/examples/emissary/KeyManagerEmissary.sol";
import { KeyLib, Key, KeyType } from "../src/examples/emissary/KeyLib.sol";
import { ResetPeriod } from "../src/types/ResetPeriod.sol";
import { IEmissary } from "../src/interfaces/IEmissary.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";
import { Base64 } from "solady/utils/Base64.sol";
import { P256 } from "solady/utils/P256.sol";

contract KeyManagerEmissaryTest is Test, P256VerifierEtcher {
    using KeyLib for Key;

    KeyManagerEmissary public emissary;

    // Test accounts
    address public sponsor1 = makeAddr("sponsor1");
    address public sponsor2 = makeAddr("sponsor2");
    address public sponsor3 = makeAddr("sponsor3");

    // Valid P256 test keys (copied from rfc6979)
    bytes32 constant P256_X_VALID = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6;
    bytes32 constant P256_Y_VALID = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299;
    bytes32 constant P256_X_ALT = 0x1CCBE91C075FC7F4F033BFADD73D5130D2A2C1F1F3C7E5E75CE0CB9E7B1E1B4E;
    bytes32 constant P256_Y_ALT = 0x59C3E75C3CF84E6D6E7E3F7B3E5A5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E;

    // WebAuthn P256 test keys (same curve, different format)
    uint256 constant WEBAUTHN_X_VALID = uint256(P256_X_VALID);
    uint256 constant WEBAUTHN_Y_VALID = uint256(P256_Y_VALID);
    uint256 constant WEBAUTHN_X_ALT = uint256(P256_X_ALT);
    uint256 constant WEBAUTHN_Y_ALT = uint256(P256_Y_ALT);

    function setUp() public {
        emissary = new KeyManagerEmissary();
    }

    // ============ Key Registration Tests ============

    function test_registerKey_Secp256k1Key() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);
        bytes32 keyHash = key.hash();

        vm.prank(sponsor1);
        vm.expectEmit(true, true, false, true);
        emit KeyManagerEmissary.KeyRegistered(sponsor1, keyHash, KeyType.Secp256k1, ResetPeriod.OneDay);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);
        vm.snapshotGasLastCall("registerKey_Secp256k1Key");

        // Verify registration
        assertTrue(emissary.isKeyRegistered(sponsor1, keyHash));
        assertEq(emissary.getKeyCount(sponsor1), 1);

        // Verify key details
        Key memory retrievedKey = emissary.getKey(sponsor1, keyHash);
        assertEq(uint8(retrievedKey.keyType), uint8(KeyType.Secp256k1));
        assertEq(uint8(retrievedKey.resetPeriod), uint8(ResetPeriod.OneDay));
        assertEq(retrievedKey.removalTimestamp, 0);
        assertEq(retrievedKey.publicKey, abi.encode(signer));
    }

    function test_registerKey_P256Key() public {
        Key memory key = KeyLib.fromP256(P256_X_VALID, P256_Y_VALID, ResetPeriod.TenMinutes);
        bytes32 keyHash = key.hash();

        vm.prank(sponsor1);
        vm.expectEmit(true, true, false, true);
        emit KeyManagerEmissary.KeyRegistered(sponsor1, keyHash, KeyType.P256, ResetPeriod.TenMinutes);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);
        vm.snapshotGasLastCall("registerKey_P256Key");

        // Verify registration
        assertTrue(emissary.isKeyRegistered(sponsor1, keyHash));

        // Verify key details
        Key memory retrievedKey = emissary.getKey(sponsor1, keyHash);
        assertEq(uint8(retrievedKey.keyType), uint8(KeyType.P256));
        assertEq(uint8(retrievedKey.resetPeriod), uint8(ResetPeriod.TenMinutes));
        assertEq(retrievedKey.removalTimestamp, 0);
        assertEq(retrievedKey.publicKey, abi.encode(P256_X_VALID, P256_Y_VALID));
    }

    function test_registerKey_WebAuthnP256Key() public {
        Key memory key = KeyLib.fromWebAuthnP256(WEBAUTHN_X_VALID, WEBAUTHN_Y_VALID, ResetPeriod.OneHourAndFiveMinutes);
        bytes32 keyHash = key.hash();

        vm.prank(sponsor1);
        vm.expectEmit(true, true, false, true);
        emit KeyManagerEmissary.KeyRegistered(
            sponsor1, keyHash, KeyType.WebAuthnP256, ResetPeriod.OneHourAndFiveMinutes
        );
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);
        vm.snapshotGasLastCall("registerKey_WebAuthnP256Key");

        // Verify registration
        assertTrue(emissary.isKeyRegistered(sponsor1, keyHash));

        // Verify key details
        Key memory retrievedKey = emissary.getKey(sponsor1, keyHash);
        assertEq(uint8(retrievedKey.keyType), uint8(KeyType.WebAuthnP256));
        assertEq(uint8(retrievedKey.resetPeriod), uint8(ResetPeriod.OneHourAndFiveMinutes));
        assertEq(retrievedKey.removalTimestamp, 0);
        assertEq(retrievedKey.publicKey, abi.encode(WEBAUTHN_X_VALID, WEBAUTHN_Y_VALID));
    }

    function test_registerKey_MultipleKeys() public {
        address signer = makeAddr("alice");
        Key memory key1 = KeyLib.fromAddress(signer, ResetPeriod.OneDay);
        Key memory key2 = KeyLib.fromP256(P256_X_VALID, P256_Y_VALID, ResetPeriod.TenMinutes);
        Key memory key3 = KeyLib.fromWebAuthnP256(WEBAUTHN_X_VALID, WEBAUTHN_Y_VALID, ResetPeriod.OneHourAndFiveMinutes);

        vm.startPrank(sponsor1);
        emissary.registerKey(key1.keyType, key1.publicKey, key1.resetPeriod);
        emissary.registerKey(key2.keyType, key2.publicKey, key2.resetPeriod);
        emissary.registerKey(key3.keyType, key3.publicKey, key3.resetPeriod);
        vm.stopPrank();

        // Verify all keys are registered
        assertEq(emissary.getKeyCount(sponsor1), 3);
        assertTrue(emissary.isKeyRegistered(sponsor1, key1.hash()));
        assertTrue(emissary.isKeyRegistered(sponsor1, key2.hash()));
        assertTrue(emissary.isKeyRegistered(sponsor1, key3.hash()));

        // Verify key hashes array
        bytes32[] memory keyHashes = emissary.getKeyHashes(sponsor1);
        assertEq(keyHashes.length, 3);
        assertEq(keyHashes[0], key1.hash());
        assertEq(keyHashes[1], key2.hash());
        assertEq(keyHashes[2], key3.hash());
    }

    function test_revert_registerKey_DuplicateKey() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);

        vm.startPrank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Try to register the same key again
        vm.expectRevert(abi.encodeWithSelector(KeyManagerEmissary.KeyAlreadyRegistered.selector, sponsor1, key.hash()));
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);
        vm.stopPrank();
    }

    function test_revert_registerKey_InvalidKey() public {
        // Create an invalid key with zero address
        Key memory invalidKey = Key({
            keyType: KeyType.Secp256k1,
            resetPeriod: ResetPeriod.OneDay,
            removalTimestamp: 0,
            publicKey: abi.encode(address(0))
        });

        vm.prank(sponsor1);
        vm.expectRevert(abi.encodeWithSelector(KeyManagerEmissary.InvalidKey.selector, invalidKey.hash()));
        emissary.registerKey(invalidKey.keyType, invalidKey.publicKey, invalidKey.resetPeriod);
    }

    // ============ Key Removal Tests ============

    function test_scheduleKeyRemoval() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.TenMinutes);
        bytes32 keyHash = key.hash();

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        uint256 expectedRemovalTime = block.timestamp + 600; // 10 minutes

        vm.prank(sponsor1);
        vm.expectEmit(true, true, false, true);
        emit KeyManagerEmissary.KeyRemovalScheduled(sponsor1, keyHash, expectedRemovalTime);
        uint256 actualRemovalTime = emissary.scheduleKeyRemoval(keyHash);
        vm.snapshotGasLastCall("scheduleKeyRemoval");

        assertEq(actualRemovalTime, expectedRemovalTime);

        // Verify removal status
        (bool isScheduled, uint256 removableAt) = emissary.getKeyRemovalStatus(sponsor1, keyHash);
        assertTrue(isScheduled);
        assertEq(removableAt, expectedRemovalTime);

        // Verify cannot remove yet
        assertFalse(emissary.canRemoveKey(sponsor1, keyHash));
    }

    function test_scheduleKeyRemoval_DifferentResetPeriods() public {
        address signer1 = makeAddr("alice");
        address signer2 = makeAddr("bob");
        Key memory key1 = KeyLib.fromAddress(signer1, ResetPeriod.OneSecond);
        Key memory key2 = KeyLib.fromAddress(signer2, ResetPeriod.ThirtyDays);

        vm.startPrank(sponsor1);
        emissary.registerKey(key1.keyType, key1.publicKey, key1.resetPeriod);
        emissary.registerKey(key2.keyType, key2.publicKey, key2.resetPeriod);

        uint256 startTime = block.timestamp;
        uint256 removal1 = emissary.scheduleKeyRemoval(key1.hash());
        uint256 removal2 = emissary.scheduleKeyRemoval(key2.hash());
        vm.stopPrank();

        assertEq(removal1, startTime + 1);
        assertEq(removal2, startTime + 30 days);
    }

    function test_revert_scheduleKeyRemoval_NonExistentKey() public {
        bytes32 fakeKeyHash = bytes32(uint256(0x123));

        vm.prank(sponsor1);
        vm.expectRevert(abi.encodeWithSelector(KeyManagerEmissary.KeyNotRegistered.selector, sponsor1, fakeKeyHash));
        emissary.scheduleKeyRemoval(fakeKeyHash);
    }

    function test_scheduleKeyRemoval_Reschedule() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.TenMinutes);
        bytes32 keyHash = key.hash();

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Schedule removal first time
        vm.prank(sponsor1);
        emissary.scheduleKeyRemoval(keyHash);

        // Fast forward time
        vm.warp(block.timestamp + 300); // 5 minutes later

        // Reschedule removal
        vm.prank(sponsor1);
        uint256 secondRemoval = emissary.scheduleKeyRemoval(keyHash);

        // Should be scheduled for 10 minutes from new time (block.timestamp + 300 + 600)
        assertEq(secondRemoval, block.timestamp + 600);

        (bool isScheduled, uint256 removableAt) = emissary.getKeyRemovalStatus(sponsor1, keyHash);
        assertTrue(isScheduled);
        assertEq(removableAt, secondRemoval);
    }

    function test_removeKey_AfterTimelock() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.TenMinutes);
        bytes32 keyHash = key.hash();

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        vm.prank(sponsor1);
        uint256 removableAt = emissary.scheduleKeyRemoval(keyHash);

        // Fast forward past timelock
        vm.warp(removableAt + 1);

        // Should be able to remove now
        assertTrue(emissary.canRemoveKey(sponsor1, keyHash));

        vm.prank(sponsor1);
        vm.expectEmit(true, true, false, false);
        emit KeyManagerEmissary.KeyRemoved(sponsor1, keyHash);
        emissary.removeKey(keyHash);
        vm.snapshotGasLastCall("removeKey");

        // Verify key is removed
        assertFalse(emissary.isKeyRegistered(sponsor1, keyHash));
        assertEq(emissary.getKeyCount(sponsor1), 0);
    }

    function test_revert_removeKey_BeforeTimelock() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.TenMinutes);
        bytes32 keyHash = key.hash();

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        vm.prank(sponsor1);
        uint256 removableAt = emissary.scheduleKeyRemoval(keyHash);

        // Try to remove before timelock expires
        vm.prank(sponsor1);
        vm.expectRevert(abi.encodeWithSelector(KeyManagerEmissary.KeyRemovalUnavailable.selector, removableAt));
        emissary.removeKey(keyHash);
    }

    function test_revert_removeKey_WithoutScheduling() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.TenMinutes);
        bytes32 keyHash = key.hash();

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Try to remove without scheduling
        vm.prank(sponsor1);
        vm.expectRevert(abi.encodeWithSelector(KeyManagerEmissary.KeyRemovalUnavailable.selector, 0));
        emissary.removeKey(keyHash);
    }

    function test_revert_removeKey_NonExistentKey() public {
        bytes32 fakeKeyHash = bytes32(uint256(0x123));

        vm.prank(sponsor1);
        vm.expectRevert(abi.encodeWithSelector(KeyManagerEmissary.KeyRemovalUnavailable.selector, 0));
        emissary.removeKey(fakeKeyHash);
    }

    function test_removeKey_FromMiddleOfArray() public {
        address signer = makeAddr("alice");
        Key memory key1 = KeyLib.fromAddress(signer, ResetPeriod.OneSecond);
        Key memory key2 = KeyLib.fromP256(P256_X_VALID, P256_Y_VALID, ResetPeriod.OneSecond);
        Key memory key3 = KeyLib.fromWebAuthnP256(WEBAUTHN_X_VALID, WEBAUTHN_Y_VALID, ResetPeriod.OneSecond);

        vm.startPrank(sponsor1);
        emissary.registerKey(key1.keyType, key1.publicKey, key1.resetPeriod);
        emissary.registerKey(key2.keyType, key2.publicKey, key2.resetPeriod);
        emissary.registerKey(key3.keyType, key3.publicKey, key3.resetPeriod);

        // Schedule removal for middle key
        emissary.scheduleKeyRemoval(key2.hash());

        // Fast forward time
        vm.warp(block.timestamp + 2);

        // Remove middle key
        emissary.removeKey(key2.hash());
        vm.snapshotGasLastCall("removeKey_FromMiddleOfArray");
        vm.stopPrank();

        // Verify array is properly managed
        assertEq(emissary.getKeyCount(sponsor1), 2);
        bytes32[] memory keyHashes = emissary.getKeyHashes(sponsor1);
        assertEq(keyHashes.length, 2);

        // Should still have key1 and key3
        assertTrue(emissary.isKeyRegistered(sponsor1, key1.hash()));
        assertTrue(emissary.isKeyRegistered(sponsor1, key3.hash()));

        // key2 should have been removed
        assertFalse(emissary.isKeyRegistered(sponsor1, key2.hash()));
    }

    function test_removeKey_MultipleKeys() public {
        // Test removal from different positions in array
        Key memory key1 = KeyLib.fromAddress(makeAddr("alice"), ResetPeriod.OneSecond);
        Key memory key2 = KeyLib.fromAddress(makeAddr("bob"), ResetPeriod.OneSecond);
        Key memory key3 = KeyLib.fromAddress(makeAddr("charlie"), ResetPeriod.OneSecond);
        Key memory key4 = KeyLib.fromP256(P256_X_VALID, P256_Y_VALID, ResetPeriod.OneSecond);
        Key memory key5 = KeyLib.fromWebAuthnP256(WEBAUTHN_X_VALID, WEBAUTHN_Y_VALID, ResetPeriod.OneSecond);

        // Register all keys
        vm.startPrank(sponsor1);
        emissary.registerKey(key1.keyType, key1.publicKey, key1.resetPeriod);
        emissary.registerKey(key2.keyType, key2.publicKey, key2.resetPeriod);
        emissary.registerKey(key3.keyType, key3.publicKey, key3.resetPeriod);
        emissary.registerKey(key4.keyType, key4.publicKey, key4.resetPeriod);
        emissary.registerKey(key5.keyType, key5.publicKey, key5.resetPeriod);

        // Schedule all for removal
        emissary.scheduleKeyRemoval(key1.hash());
        emissary.scheduleKeyRemoval(key2.hash());
        emissary.scheduleKeyRemoval(key3.hash());
        emissary.scheduleKeyRemoval(key4.hash());
        emissary.scheduleKeyRemoval(key5.hash());
        vm.stopPrank();

        // Fast forward time
        vm.warp(block.timestamp + 2);

        // Remove keys in non-sequential order: 3rd, 1st, 5th, 2nd, 4th
        vm.startPrank(sponsor1);

        // Remove key3 (middle)
        emissary.removeKey(key3.hash());
        assertEq(emissary.getKeyCount(sponsor1), 4);
        assertFalse(emissary.isKeyRegistered(sponsor1, key3.hash()));

        // Remove key1 (now first)
        emissary.removeKey(key1.hash());
        assertEq(emissary.getKeyCount(sponsor1), 3);
        assertFalse(emissary.isKeyRegistered(sponsor1, key1.hash()));

        // Remove key5 (now last)
        emissary.removeKey(key5.hash());
        assertEq(emissary.getKeyCount(sponsor1), 2);
        assertFalse(emissary.isKeyRegistered(sponsor1, key5.hash()));

        // Remove key2
        emissary.removeKey(key2.hash());
        assertEq(emissary.getKeyCount(sponsor1), 1);
        assertFalse(emissary.isKeyRegistered(sponsor1, key2.hash()));

        // Remove key4 (last remaining)
        emissary.removeKey(key4.hash());
        assertEq(emissary.getKeyCount(sponsor1), 0);
        assertFalse(emissary.isKeyRegistered(sponsor1, key4.hash()));

        vm.stopPrank();

        // Verify array is empty
        bytes32[] memory finalHashes = emissary.getKeyHashes(sponsor1);
        assertEq(finalHashes.length, 0);
    }

    // ============ Signature Verification Tests ============

    function test_verifyClaim_Secp256k1Signature() public {
        // Create a key for the signer
        (address signer, uint256 privateKey) = makeAddrAndKey("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create a test digest and signature
        bytes32 digest = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create a compatible lock tag (same or shorter reset period)
        // Lock tag format: scope (1 bit) + reset period (3 bits) + allocator ID (92 bits)
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Verify signature
        bytes4 result = emissary.verifyClaim(
            sponsor1,
            digest,
            bytes32(0), // claimHash not used
            signature,
            lockTag
        );
        vm.snapshotGasLastCall("verifyClaim_Secp256k1Signature");

        assertEq(result, IEmissary.verifyClaim.selector);
    }

    function test_revert_verifyClaim_IncompatibleResetPeriod() public {
        // Create a key with OneDay reset period
        (address signer, uint256 privateKey) = makeAddrAndKey("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create a test digest and signature
        bytes32 digest = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create an incompatible lock tag (longer reset period than key)
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.ThirtyDays)) << 92);

        // Should fail verification due to incompatible reset period
        vm.expectRevert(KeyManagerEmissary.SignatureVerificationFailed.selector);
        emissary.verifyClaim(
            sponsor1,
            digest,
            bytes32(0), // claimHash not used
            signature,
            lockTag
        );
    }

    function test_verifyClaim_MultipleKeys() public {
        // Register multiple keys
        (address signer1, uint256 privateKey1) = makeAddrAndKey("alice");
        (address signer2, uint256 privateKey2) = makeAddrAndKey("bob");
        Key memory key1 = KeyLib.fromAddress(signer1, ResetPeriod.OneDay);
        Key memory key2 = KeyLib.fromAddress(signer2, ResetPeriod.TenMinutes);

        vm.startPrank(sponsor1);
        emissary.registerKey(key1.keyType, key1.publicKey, key1.resetPeriod);
        emissary.registerKey(key2.keyType, key2.publicKey, key2.resetPeriod);
        vm.stopPrank();

        // Create signature with signer2
        bytes32 digest = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey2, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Use compatible lock tag
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.TenMinutes)) << 92);

        // Should find the correct key and verify
        bytes4 result = emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        vm.snapshotGasLastCall("verifyClaim_MultipleKeys");

        assertEq(result, IEmissary.verifyClaim.selector);
    }

    function test_revert_verifyClaim_NoRegisteredKeys() public {
        bytes32 digest = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xdeadbeef, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        vm.expectRevert(KeyManagerEmissary.SignatureVerificationFailed.selector);
        emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
    }

    function test_revert_verifyClaim_InvalidSignature() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        bytes32 digest = keccak256("test message");
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        vm.expectRevert(KeyManagerEmissary.SignatureVerificationFailed.selector);
        emissary.verifyClaim(sponsor1, digest, bytes32(0), invalidSignature, lockTag);
    }

    // ============ P256 Signature Verification Tests ============

    function test_verifyClaim_P256Signature() public {
        // Set up P256 verifier (required for P256)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Generate a real P256 private key and derive the public key
        uint256 privateKey = _bound(uint256(keccak256("test_p256_key")), 1, P256.N - 1);
        (uint256 x, uint256 y) = vm.publicKeyP256(privateKey);

        // Register P256 key with the derived public key
        Key memory key = KeyLib.fromP256(bytes32(x), bytes32(y), ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create a test digest
        bytes32 digest = keccak256("test message for P256");

        // Generate a real P256 signature
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, digest);
        s = P256.normalized(s);

        bytes memory signature = abi.encodePacked(r, s);
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);
        bytes4 result = emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        vm.snapshotGasLastCall("verifyClaim_P256Signature");

        assertEq(result, IEmissary.verifyClaim.selector);
    }

    function test_verifyClaim_P256Signature_WithResetPeriodCheck() public {
        // Set up P256 verifier (required for P256)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Generate a real P256 private key and derive the public key
        uint256 privateKey = _bound(uint256(keccak256("test_p256_key_reset")), 1, P256.N - 1);
        (uint256 x, uint256 y) = vm.publicKeyP256(privateKey);

        // Register P256 key with TenMinutes reset period
        Key memory key = KeyLib.fromP256(bytes32(x), bytes32(y), ResetPeriod.TenMinutes);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        bytes32 digest = keccak256("test message");

        // Generate a real P256 signature
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, digest);
        s = P256.normalized(s);
        bytes memory signature = abi.encodePacked(r, s);

        // Test with compatible lock tag (OneMinute) - should succeed
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneMinute)) << 92);
        bytes4 result = emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        assertEq(result, IEmissary.verifyClaim.selector);

        // Test with incompatible lock tag (longer than key's reset period) - should fail
        bytes12 incompatibleLockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);
        vm.expectRevert(KeyManagerEmissary.SignatureVerificationFailed.selector);
        emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, incompatibleLockTag);
    }

    function test_revert_verifyClaim_P256Signature_InvalidLength() public {
        // Set up P256 verifier (required for P256)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Register P256 key
        Key memory key = KeyLib.fromP256(P256_X_VALID, P256_Y_VALID, ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        bytes32 digest = keccak256("test message");
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Test with invalid signature length (should be 64 bytes)
        bytes memory invalidSignature = abi.encodePacked(bytes32(uint256(0x123)), bytes16(uint128(0x456))); // 48 bytes
        vm.expectRevert(KeyManagerEmissary.SignatureVerificationFailed.selector);
        emissary.verifyClaim(sponsor1, digest, bytes32(0), invalidSignature, lockTag);
    }

    function test_verifyClaim_MixedKeyTypes_P256AndSecp256k1() public {
        // Set up P256 verifier (required for P256)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Generate a real P256 private key and derive the public key
        uint256 p256PrivateKey = _bound(uint256(keccak256("test_p256_mixed")), 1, P256.N - 1);
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);
        Key memory p256Key = KeyLib.fromP256(bytes32(x), bytes32(y), ResetPeriod.OneDay);

        (address signer, uint256 privateKey) = makeAddrAndKey("alice");
        Key memory secp256k1Key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);

        vm.startPrank(sponsor1);
        emissary.registerKey(p256Key.keyType, p256Key.publicKey, p256Key.resetPeriod);
        emissary.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);
        vm.stopPrank();

        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Test P256 signature
        {
            bytes32 p256Digest = keccak256("test message for P256");
            (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, p256Digest);
            s = P256.normalized(s);
            bytes memory p256Signature = abi.encodePacked(r, s);
            bytes4 result = emissary.verifyClaim(sponsor1, p256Digest, bytes32(0), p256Signature, lockTag);
            assertEq(result, IEmissary.verifyClaim.selector);
        }

        // Test Secp256k1 signature
        {
            bytes32 secp256k1Digest = keccak256("test message for secp256k1");
            (uint8 v, bytes32 r2, bytes32 s2) = vm.sign(privateKey, secp256k1Digest);
            bytes memory secp256k1Signature = abi.encodePacked(r2, s2, v);
            bytes4 result = emissary.verifyClaim(sponsor1, secp256k1Digest, bytes32(0), secp256k1Signature, lockTag);
            assertEq(result, IEmissary.verifyClaim.selector);
        }
    }

    // ============ WebAuthn Signature Verification Tests ============

    function test_verifyClaim_WebAuthnSignature_Safari() public {
        // Set up P256 verifier (required for WebAuthn)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Use the same test data as Solady's WebAuthn tests
        uint256 x = 0x3f2be075ef57d6c8374ef412fe54fdd980050f70f4f3a00b5b1b32d2def7d28d;
        uint256 y = 0x57095a365acc2590ade3583fabfe8fbd64a9ed3ec07520da00636fb21f0176c1;
        bytes memory challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Register WebAuthn key
        Key memory key = KeyLib.fromWebAuthnP256(x, y, ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create WebAuthn auth data (Safari format)
        WebAuthn.WebAuthnAuth memory auth;
        auth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101";
        auth.clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64.encode(challenge, true, true),
                '","origin":"http://localhost:3005"}'
            )
        );
        auth.challengeIndex = 23;
        auth.typeIndex = 1;
        auth.r = 0x60946081650523acad13c8eff94996a409b1ed60e923c90f9e366aad619adffa;
        auth.s = 0x3216a237b73765d01b839e0832d73474bc7e63f4c86ef05fbbbfbeb34b35602b;

        // Encode signature
        bytes memory signature = abi.encode(auth);

        // For WebAuthn, the digest should be the challenge that was used to create the signature
        // The test data expects the challenge to be the 32-byte value that was encoded
        bytes32 digest = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Verify signature
        bytes4 result = emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        vm.snapshotGasLastCall("verifyClaim_WebAuthnSignature_Safari");
        assertEq(result, IEmissary.verifyClaim.selector);
    }

    function test_verifyClaim_WebAuthnSignature_Chrome() public {
        // Set up P256 verifier (required for WebAuthn)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Use the same test data as Solady's WebAuthn tests
        uint256 x = 0x3f2be075ef57d6c8374ef412fe54fdd980050f70f4f3a00b5b1b32d2def7d28d;
        uint256 y = 0x57095a365acc2590ade3583fabfe8fbd64a9ed3ec07520da00636fb21f0176c1;
        bytes memory challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Register WebAuthn key
        Key memory key = KeyLib.fromWebAuthnP256(x, y, ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create WebAuthn auth data (Chrome format)
        WebAuthn.WebAuthnAuth memory auth;
        auth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a";
        auth.clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64.encode(challenge, true, true),
                '","origin":"http://localhost:3005","crossOrigin":false}'
            )
        );
        auth.challengeIndex = 23;
        auth.typeIndex = 1;
        auth.r = 0x41c01ca5ecdfeb23ef70d6cc216fd491ac3aa3d40c480751f3618a3a9ef67b41;
        auth.s = 0x6595569abf76c2777e832a9252bae14efdb77febd0fa3b919aa16f6208469e86;

        // Encode signature
        bytes memory signature = abi.encode(auth);

        // For WebAuthn, the digest should be the challenge that was used to create the signature
        bytes32 digest = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Verify signature
        bytes4 result = emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        vm.snapshotGasLastCall("verifyClaim_WebAuthnSignature_Chrome");
        assertEq(result, IEmissary.verifyClaim.selector);
    }

    function test_verifyClaim_WebAuthnSignature_WithResetPeriodCheck() public {
        // Set up P256 verifier (required for WebAuthn)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Use the same test data as Solady's WebAuthn tests
        uint256 x = 0x3f2be075ef57d6c8374ef412fe54fdd980050f70f4f3a00b5b1b32d2def7d28d;
        uint256 y = 0x57095a365acc2590ade3583fabfe8fbd64a9ed3ec07520da00636fb21f0176c1;
        bytes memory challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Register WebAuthn key with TenMinutes reset period
        Key memory key = KeyLib.fromWebAuthnP256(x, y, ResetPeriod.TenMinutes);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create WebAuthn auth data (Safari format)
        WebAuthn.WebAuthnAuth memory auth;
        auth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101";
        auth.clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64.encode(challenge, true, true),
                '","origin":"http://localhost:3005"}'
            )
        );
        auth.challengeIndex = 23;
        auth.typeIndex = 1;
        auth.r = 0x60946081650523acad13c8eff94996a409b1ed60e923c90f9e366aad619adffa;
        auth.s = 0x3216a237b73765d01b839e0832d73474bc7e63f4c86ef05fbbbfbeb34b35602b;

        // Encode signature
        bytes memory signature = abi.encode(auth);

        // For WebAuthn, the digest should be the challenge that was used to create the signature
        bytes32 digest = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

        // Test with compatible lock tag (TenMinutes)
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.TenMinutes)) << 92);
        bytes4 result = emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        assertEq(result, IEmissary.verifyClaim.selector);

        // Test with incompatible lock tag (longer than key's reset period)
        bytes12 incompatibleLockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);
        vm.expectRevert(KeyManagerEmissary.SignatureVerificationFailed.selector);
        emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, incompatibleLockTag);
    }

    function test_revert_verifyClaim_WebAuthnSignature_InvalidSignature() public {
        // Set up P256 verifier (required for WebAuthn)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Register WebAuthn key
        uint256 x = 0x3f2be075ef57d6c8374ef412fe54fdd980050f70f4f3a00b5b1b32d2def7d28d;
        uint256 y = 0x57095a365acc2590ade3583fabfe8fbd64a9ed3ec07520da00636fb21f0176c1;
        Key memory key = KeyLib.fromWebAuthnP256(x, y, ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create invalid WebAuthn auth data (corrupted signature)
        WebAuthn.WebAuthnAuth memory auth;
        auth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101";
        auth.clientDataJSON = '{"type":"webauthn.get","challenge":"test","origin":"http://localhost:3005"}';
        auth.challengeIndex = 23;
        auth.typeIndex = 1;
        auth.r = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef; // Invalid
        auth.s = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321; // Invalid

        // Encode signature
        bytes memory signature = abi.encode(auth);

        bytes32 digest = keccak256("test message");
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Should fail verification
        vm.expectRevert(KeyManagerEmissary.SignatureVerificationFailed.selector);
        emissary.verifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
    }

    function test_verifyClaim_MixedKeyTypes_WebAuthnAndSecp256k1() public {
        // Set up P256 verifier (required for WebAuthn)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Register both WebAuthn and Secp256k1 keys for the same sponsor
        uint256 webauthnX = 0x3f2be075ef57d6c8374ef412fe54fdd980050f70f4f3a00b5b1b32d2def7d28d;
        uint256 webauthnY = 0x57095a365acc2590ade3583fabfe8fbd64a9ed3ec07520da00636fb21f0176c1;
        Key memory webauthnKey = KeyLib.fromWebAuthnP256(webauthnX, webauthnY, ResetPeriod.OneDay);

        (address signer, uint256 privateKey) = makeAddrAndKey("alice");
        Key memory secp256k1Key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);

        vm.startPrank(sponsor1);
        emissary.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);
        emissary.registerKey(webauthnKey.keyType, webauthnKey.publicKey, webauthnKey.resetPeriod);
        vm.stopPrank();

        // Test Secp256k1 signature first (should find it in the first iteration)
        bytes32 secp256k1Digest = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, secp256k1Digest);
        bytes memory secp256k1Signature = abi.encodePacked(r, s, v);
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        bytes4 result = emissary.verifyClaim(sponsor1, secp256k1Digest, bytes32(0), secp256k1Signature, lockTag);
        assertEq(result, IEmissary.verifyClaim.selector);

        // Test WebAuthn signature
        bytes memory challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
        WebAuthn.WebAuthnAuth memory auth;
        auth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101";
        auth.clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64.encode(challenge, true, true),
                '","origin":"http://localhost:3005"}'
            )
        );
        auth.challengeIndex = 23;
        auth.typeIndex = 1;
        auth.r = 0x60946081650523acad13c8eff94996a409b1ed60e923c90f9e366aad619adffa;
        auth.s = 0x3216a237b73765d01b839e0832d73474bc7e63f4c86ef05fbbbfbeb34b35602b;

        bytes memory webauthnSignature = abi.encode(auth);
        bytes32 webauthnDigest = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

        result = emissary.verifyClaim(sponsor1, webauthnDigest, bytes32(0), webauthnSignature, lockTag);
        assertEq(result, IEmissary.verifyClaim.selector);
    }

    function test_verifyClaim_WebAuthnSignature_CompactEncoding() public {
        // Set up P256 verifier (required for WebAuthn)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Register WebAuthn key
        uint256 x = 0x3f2be075ef57d6c8374ef412fe54fdd980050f70f4f3a00b5b1b32d2def7d28d;
        uint256 y = 0x57095a365acc2590ade3583fabfe8fbd64a9ed3ec07520da00636fb21f0176c1;
        Key memory key = KeyLib.fromWebAuthnP256(x, y, ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Use the same challenge format as Solady's tests
        bytes memory challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Create WebAuthn auth data with compact encoding
        WebAuthn.WebAuthnAuth memory auth;
        auth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101";
        auth.clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64.encode(challenge, true, true),
                '","origin":"http://localhost:3005"}'
            )
        );
        auth.challengeIndex = uint16(23);
        auth.typeIndex = uint16(1);
        auth.r = 0x60946081650523acad13c8eff94996a409b1ed60e923c90f9e366aad619adffa;
        auth.s = 0x3216a237b73765d01b839e0832d73474bc7e63f4c86ef05fbbbfbeb34b35602b;

        // Test both regular and compact encoding
        bytes memory regularSignature = abi.encode(auth);
        bytes memory compactSignature = WebAuthn.tryEncodeAuthCompact(auth);

        // Use the raw challenge bytes as the digest (this is what was actually signed)
        bytes32 digest = bytes32(challenge);
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        bool regularEncodingWorks;
        try emissary.verifyClaim(sponsor1, digest, bytes32(0), regularSignature, lockTag) {
            regularEncodingWorks = true;
        } catch {
            regularEncodingWorks = false;
        }

        bool compactEncodingWorks;
        try emissary.verifyClaim(sponsor1, digest, bytes32(0), compactSignature, lockTag) {
            compactEncodingWorks = true;
        } catch {
            compactEncodingWorks = false;
        }

        vm.snapshotGasLastCall("verifyClaim_WebAuthnSignature_CompactEncoding");

        assertTrue(regularEncodingWorks, "Regular encoding should work");
        assertTrue(compactEncodingWorks, "Compact encoding should work");
    }

    // ============ View Function Tests ============

    function test_getKeyResetPeriod() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.OneHourAndFiveMinutes);

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        ResetPeriod period = emissary.getKeyResetPeriod(sponsor1, key.hash());
        assertEq(uint8(period), uint8(ResetPeriod.OneHourAndFiveMinutes));
    }

    function test_revert_getKeyResetPeriod_NonExistentKey() public {
        bytes32 fakeKeyHash = bytes32(uint256(0x123));

        vm.expectRevert(abi.encodeWithSelector(KeyManagerEmissary.KeyNotRegistered.selector, sponsor1, fakeKeyHash));
        emissary.getKeyResetPeriod(sponsor1, fakeKeyHash);
    }

    function test_computeKeyHash() public {
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);
        bytes32 expectedHash = key.hash();
        bytes32 actualHash = emissary.computeKeyHash(key);
        assertEq(actualHash, expectedHash);
    }

    function test_validateKey() public {
        address signer = makeAddr("alice");
        Key memory validKey = KeyLib.fromAddress(signer, ResetPeriod.OneDay);
        assertTrue(emissary.validateKey(validKey));

        Key memory invalidKey = Key({
            keyType: KeyType.Secp256k1,
            resetPeriod: ResetPeriod.OneDay,
            removalTimestamp: 0,
            publicKey: abi.encode(address(0))
        });
        assertFalse(emissary.validateKey(invalidKey));
    }

    // ============ Edge Cases and Error Conditions ============

    function test_revert_getKeyRemovalStatus_NonExistentKey() public {
        bytes32 fakeKeyHash = bytes32(uint256(0x123));

        vm.expectRevert(abi.encodeWithSelector(KeyManagerEmissary.KeyNotRegistered.selector, sponsor1, fakeKeyHash));
        emissary.getKeyRemovalStatus(sponsor1, fakeKeyHash);
    }

    function test_canRemoveKey_NonExistentKey() public view {
        bytes32 fakeKeyHash = bytes32(uint256(0x123));
        assertFalse(emissary.canRemoveKey(sponsor1, fakeKeyHash));
    }

    function test_registerKey_MultipleSponsorsSeparateKeySpaces() public {
        address signer1 = makeAddr("alice");
        address signer2 = makeAddr("bob");
        Key memory key1 = KeyLib.fromAddress(signer1, ResetPeriod.OneDay);
        Key memory key2 = KeyLib.fromAddress(signer2, ResetPeriod.TenMinutes);

        // Register different keys for different sponsors
        vm.prank(sponsor1);
        emissary.registerKey(key1.keyType, key1.publicKey, key1.resetPeriod);

        vm.prank(sponsor2);
        emissary.registerKey(key2.keyType, key2.publicKey, key2.resetPeriod);

        // Verify segregation of keys between sponsors
        assertTrue(emissary.isKeyRegistered(sponsor1, key1.hash()));
        assertFalse(emissary.isKeyRegistered(sponsor1, key2.hash()));
        assertFalse(emissary.isKeyRegistered(sponsor2, key1.hash()));
        assertTrue(emissary.isKeyRegistered(sponsor2, key2.hash()));

        assertEq(emissary.getKeyCount(sponsor1), 1);
        assertEq(emissary.getKeyCount(sponsor2), 1);
    }

    function test_revert_scheduleKeyRemoval_TimestampOverflow() public {
        // Test with a very long reset period to check uint64 overflow handling
        address signer = makeAddr("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.ThirtyDays);

        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Warp to near uint64 max to test overflow
        vm.warp(type(uint64).max - 1000);

        vm.prank(sponsor1);

        uint256 removableAt = emissary.scheduleKeyRemoval(key.hash());
        assertTrue(removableAt > 0);
    }

    // ============ canVerifyClaim Function Tests ============

    function test_canVerifyClaim_Secp256k1Signature() public {
        // Register Secp256k1 key
        (address signer, uint256 privateKey) = makeAddrAndKey("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create a test digest and signature
        bytes32 digest = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Should return true for valid signature
        bool canVerify = emissary.canVerifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        assertTrue(canVerify);
    }

    function test_canVerifyClaim_P256Signature() public {
        // Set up P256 verifier (required for P256)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Generate a real P256 private key and derive the public key
        uint256 privateKey = _bound(uint256(keccak256("test_p256_key_canverify")), 1, P256.N - 1);
        (uint256 x, uint256 y) = vm.publicKeyP256(privateKey);

        // Register P256 key with the derived public key
        Key memory key = KeyLib.fromP256(bytes32(x), bytes32(y), ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create a test digest
        bytes32 digest = keccak256("test message for P256");

        // Generate a real P256 signature
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, digest);
        s = P256.normalized(s);

        bytes memory signature = abi.encodePacked(r, s);
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        bool canVerify = emissary.canVerifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        assertTrue(canVerify);
    }

    function test_canVerifyClaim_WebAuthnSignature() public {
        // Set up P256 verifier (required for WebAuthn)
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Use the same test data as Solady's WebAuthn tests
        uint256 x = 0x3f2be075ef57d6c8374ef412fe54fdd980050f70f4f3a00b5b1b32d2def7d28d;
        uint256 y = 0x57095a365acc2590ade3583fabfe8fbd64a9ed3ec07520da00636fb21f0176c1;
        bytes memory challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Register WebAuthn key
        Key memory key = KeyLib.fromWebAuthnP256(x, y, ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create WebAuthn auth data (Safari format)
        WebAuthn.WebAuthnAuth memory auth;
        auth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101";
        auth.clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64.encode(challenge, true, true),
                '","origin":"http://localhost:3005"}'
            )
        );
        auth.challengeIndex = 23;
        auth.typeIndex = 1;
        auth.r = 0x60946081650523acad13c8eff94996a409b1ed60e923c90f9e366aad619adffa;
        auth.s = 0x3216a237b73765d01b839e0832d73474bc7e63f4c86ef05fbbbfbeb34b35602b;

        // Encode signature
        bytes memory signature = abi.encode(auth);

        bytes32 digest = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Should return true for valid signature
        bool canVerify = emissary.canVerifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        assertTrue(canVerify);
    }

    function test_canVerifyClaim_WithResetPeriodCheck() public {
        // Register key with TenMinutes reset period
        (address signer, uint256 privateKey) = makeAddrAndKey("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.TenMinutes);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        bytes32 digest = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Test with compatible lock tag (lock's reset period is less than key's)
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneMinute)) << 92);
        bool canVerify = emissary.canVerifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        assertTrue(canVerify);

        // Test with incompatible lock tag (lock reset period is longer than key's)
        bytes12 incompatibleLockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);
        bool canVerifyIncompatible =
            emissary.canVerifyClaim(sponsor1, digest, bytes32(0), signature, incompatibleLockTag);
        assertFalse(canVerifyIncompatible);
    }

    function test_canVerifyClaim_MultipleKeys() public {
        // Register multiple keys
        (address signer1, uint256 privateKey1) = makeAddrAndKey("alice");
        (address signer2, uint256 privateKey2) = makeAddrAndKey("bob");
        Key memory key1 = KeyLib.fromAddress(signer1, ResetPeriod.OneDay);
        Key memory key2 = KeyLib.fromAddress(signer2, ResetPeriod.OneDay);

        vm.startPrank(sponsor1);
        emissary.registerKey(key1.keyType, key1.publicKey, key1.resetPeriod);
        emissary.registerKey(key2.keyType, key2.publicKey, key2.resetPeriod);
        vm.stopPrank();

        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Test signature from first key
        {
            bytes32 digest1 = keccak256("test message 1");
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey1, digest1);
            bytes memory signature1 = abi.encodePacked(r1, s1, v1);

            bool canVerify1 = emissary.canVerifyClaim(sponsor1, digest1, bytes32(0), signature1, lockTag);
            assertTrue(canVerify1);
        }

        // Test signature from second key
        {
            bytes32 digest2 = keccak256("test message 2");
            (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey2, digest2);
            bytes memory signature2 = abi.encodePacked(r2, s2, v2);

            bool canVerify2 = emissary.canVerifyClaim(sponsor1, digest2, bytes32(0), signature2, lockTag);
            assertTrue(canVerify2);
        }
    }

    function test_canVerifyClaim_MixedKeyTypes() public {
        // Set up P256 verifier
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Generate a real P256 private key and derive the public key
        uint256 p256PrivateKey = _bound(uint256(keccak256("test_p256_mixed_canverify")), 1, P256.N - 1);
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);
        Key memory p256Key = KeyLib.fromP256(bytes32(x), bytes32(y), ResetPeriod.OneDay);

        (address signer, uint256 privateKey) = makeAddrAndKey("alice");
        Key memory secp256k1Key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);

        vm.startPrank(sponsor1);
        emissary.registerKey(p256Key.keyType, p256Key.publicKey, p256Key.resetPeriod);
        emissary.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);
        vm.stopPrank();

        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Test P256 signature
        {
            bytes32 p256Digest = keccak256("test message for P256");
            (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, p256Digest);
            s = P256.normalized(s);
            bytes memory p256Signature = abi.encodePacked(r, s);

            bool canVerifyP256 = emissary.canVerifyClaim(sponsor1, p256Digest, bytes32(0), p256Signature, lockTag);
            assertTrue(canVerifyP256);
        }

        // Test Secp256k1 signature
        {
            bytes32 secp256k1Digest = keccak256("test message for secp256k1");
            (uint8 v, bytes32 r2, bytes32 s2) = vm.sign(privateKey, secp256k1Digest);
            bytes memory secp256k1Signature = abi.encodePacked(r2, s2, v);

            bool canVerifySecp256k1 =
                emissary.canVerifyClaim(sponsor1, secp256k1Digest, bytes32(0), secp256k1Signature, lockTag);
            assertTrue(canVerifySecp256k1);
        }
    }

    function test_canVerifyClaim_NoRegisteredKeys() public {
        bytes32 digest = keccak256("test message");
        bytes memory signature = abi.encodePacked(bytes32(vm.randomUint()), bytes32(vm.randomUint()), uint8(42)); // dummy signature
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);
        assertFalse(emissary.canVerifyClaim(sponsor1, digest, bytes32(0), signature, lockTag));
    }

    function test_canVerifyClaim_InvalidSignature() public {
        // Register key
        (address signer,) = makeAddrAndKey("alice");
        Key memory key = KeyLib.fromAddress(signer, ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        bytes32 digest = keccak256("test message");
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27)); // invalid signature
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Should return false for invalid signature
        bool canVerify = emissary.canVerifyClaim(sponsor1, digest, bytes32(0), invalidSignature, lockTag);
        assertFalse(canVerify);
    }

    function test_canVerifyClaim_P256Signature_InvalidLength() public {
        // Set up P256 verifier
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        // Generate a real P256 private key and derive the public key
        uint256 privateKey = _bound(uint256(keccak256("test_p256_invalid_length")), 1, P256.N - 1);
        (uint256 x, uint256 y) = vm.publicKeyP256(privateKey);

        Key memory key = KeyLib.fromP256(bytes32(x), bytes32(y), ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        bytes32 digest = keccak256("test message");
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Test with invalid signature length (should be 64 bytes for P256)
        bytes memory invalidSignature = abi.encodePacked(bytes32(uint256(0x123)), bytes16(uint128(0x456))); // 48 bytes
        bool canVerify = emissary.canVerifyClaim(sponsor1, digest, bytes32(0), invalidSignature, lockTag);
        assertFalse(canVerify);
    }

    function test_canVerifyClaim_WebAuthnSignature_InvalidSignature() public {
        // Set up P256 verifier
        _etchRIPPrecompile(true);
        _etchVerifier(true);

        uint256 x = 0x3f2be075ef57d6c8374ef412fe54fdd980050f70f4f3a00b5b1b32d2def7d28d;
        uint256 y = 0x57095a365acc2590ade3583fabfe8fbd64a9ed3ec07520da00636fb21f0176c1;

        Key memory key = KeyLib.fromWebAuthnP256(x, y, ResetPeriod.OneDay);
        vm.prank(sponsor1);
        emissary.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Create invalid WebAuthn auth data (corrupted signature)
        WebAuthn.WebAuthnAuth memory auth;
        auth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101";
        auth.clientDataJSON = '{"type":"webauthn.get","challenge":"invalid","origin":"http://localhost:3005"}';
        auth.challengeIndex = 23;
        auth.typeIndex = 1;
        auth.r = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef; // invalid
        auth.s = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321; // invalid

        bytes memory signature = abi.encode(auth);
        bytes32 digest = keccak256("test");
        bytes12 lockTag = bytes12(uint96(uint8(ResetPeriod.OneDay)) << 92);

        // Should return false for invalid WebAuthn signature
        bool canVerify = emissary.canVerifyClaim(sponsor1, digest, bytes32(0), signature, lockTag);
        assertFalse(canVerify);
    }
}
