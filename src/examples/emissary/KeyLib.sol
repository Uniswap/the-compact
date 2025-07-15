// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC1271 } from "permit2/src/interfaces/IERC1271.sol";
import { P256 } from "solady/utils/P256.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";

/// @notice The type of key supported by the emissary
enum KeyType {
    P256,
    WebAuthnP256,
    Secp256k1
}

/// @notice Represents a cryptographic key with its type, reset period, removal timestamp, and encoded public key
/// @param keyType The type of key. See the {KeyType} enum.
/// @param resetPeriod The reset period for timelock verification.
/// @param removalTimestamp The timestamp when key can be removed (0 means not scheduled for removal).
/// @param index The 1-based index of this key in the keyHashes array (0 means not registered).
/// @param publicKey The public key in encoded form.
struct Key {
    KeyType keyType;
    ResetPeriod resetPeriod;
    uint64 removalTimestamp;
    uint16 index;
    bytes publicKey;
}

/// @notice Library for key management and signature verification
/// @dev Adapted from Uniswap Calibur 7702 wallet implementation
library KeyLib {
    /**
     * @notice Hashes a key to create a unique identifier
     * @param key The key to hash
     * @return keyHash The keccak256 hash of the key
     */
    function hash(Key memory key) internal pure returns (bytes32 keyHash) {
        return keccak256(abi.encode(key.keyType, keccak256(key.publicKey)));
    }

    /**
     * @notice Verifies a signature from `key` over a `digest`
     * @dev Signatures from P256 are expected to be over the `sha256` hash of `digest`
     * @param key The key to verify against
     * @param digest The digest that was signed
     * @param signature The signature to verify
     * @return isValid True if the signature is valid
     */
    function verify(Key storage key, bytes32 digest, bytes calldata signature) internal view returns (bool isValid) {
        KeyType keyType;
        uint256 keyMaterialPtr;

        assembly {
            // Load the packed struct fields
            let keyData := sload(key.slot)
            keyType := and(keyData, 0xff)

            // The public key data is stored at keccak256(key.slot + 1)
            mstore(0x00, add(key.slot, 1))
            keyMaterialPtr := keccak256(0x00, 0x20)
        }

        if (keyType == KeyType.Secp256k1) {
            address expectedSigner;
            assembly {
                expectedSigner := sload(keyMaterialPtr)
            }

            // Try direct ECDSA recovery first
            if (signature.length == 64 || signature.length == 65) {
                address recovered = ECDSA.tryRecoverCalldata(digest, signature);
                if (recovered == expectedSigner) return true;
            }

            // Try EIP-1271 if the expected signer is a contract
            if (expectedSigner.code.length > 0) {
                try IERC1271(expectedSigner).isValidSignature(digest, signature) returns (bytes4 magicValue) {
                    return magicValue == IERC1271.isValidSignature.selector;
                } catch {
                    return false;
                }
            }

            return false;
        }

        bytes32 x;
        bytes32 y;
        assembly ("memory-safe") {
            x := sload(keyMaterialPtr)
            y := sload(add(keyMaterialPtr, 1))
        }

        if (keyType == KeyType.P256) {
            // Signature should be r || s (32 bytes * 2)
            if (signature.length != 64) {
                return false;
            }

            // Split signature into r and s values
            bytes32 r = bytes32(signature[0:32]);
            bytes32 s = bytes32(signature[32:64]);
            return P256.verifySignature(digest, r, s, x, y);
        }

        if (keyType == KeyType.WebAuthnP256) {
            // Try to decode the signature - first as regular ABI encoding, then as compact
            WebAuthn.WebAuthnAuth memory auth = WebAuthn.tryDecodeAuth(signature);

            // If regular decoding fails (clientDataJSON is empty), try compact decoding
            if (bytes(auth.clientDataJSON).length == 0) {
                auth = WebAuthn.tryDecodeAuthCompactCalldata(signature);

                // If compact decoding also fails (clientDataJSON is empty), fail
                if (bytes(auth.clientDataJSON).length == 0) {
                    return false;
                }
            }

            // WebAuthn verification with the digest as challenge (packed bytes)
            return WebAuthn.verify(abi.encodePacked(digest), false, auth, x, y);
        }

        return false;
    }

    /**
     * @notice Validates that a key is properly formatted
     * @param key The key to validate
     * @return isValid True if the key is valid
     */
    function isValidKey(Key memory key) internal pure returns (bool isValid) {
        if (key.keyType == KeyType.Secp256k1) {
            // For Secp256k1, publicKey should be an encoded address
            if (key.publicKey.length != 32) return false;
            address addr = abi.decode(key.publicKey, (address));
            return addr != address(0);
        } else if (key.keyType == KeyType.P256) {
            // For P256, publicKey should be encoded (x, y) coordinates
            if (key.publicKey.length != 64) return false;
            (bytes32 x, bytes32 y) = abi.decode(key.publicKey, (bytes32, bytes32));
            return x != bytes32(0) && y != bytes32(0);
        } else if (key.keyType == KeyType.WebAuthnP256) {
            // For WebAuthnP256, publicKey should be encoded (x, y) coordinates as uint256
            if (key.publicKey.length != 64) return false;
            (uint256 x, uint256 y) = abi.decode(key.publicKey, (uint256, uint256));
            return x != 0 && y != 0;
        }

        return false;
    }

    /**
     * @notice Turns a calling address into a key object for Secp256k1
     * @param caller The address to convert to a key
     * @param resetPeriod The reset period for the key
     * @return key The key object representing the caller
     */
    function fromAddress(address caller, ResetPeriod resetPeriod) internal pure returns (Key memory key) {
        key.keyType = KeyType.Secp256k1;
        key.resetPeriod = resetPeriod;
        key.publicKey = abi.encode(caller);
        return key;
    }

    /**
     * @notice Creates a P256 key from x,y coordinates
     * @param x The x coordinate of the P256 public key
     * @param y The y coordinate of the P256 public key
     * @param resetPeriod The reset period for the key
     * @return key The P256 key object
     */
    function fromP256(bytes32 x, bytes32 y, ResetPeriod resetPeriod) internal pure returns (Key memory key) {
        key.keyType = KeyType.P256;
        key.resetPeriod = resetPeriod;
        key.publicKey = abi.encode(x, y);
        return key;
    }

    /**
     * @notice Creates a WebAuthn P256 key from x,y coordinates
     * @param x The x coordinate of the WebAuthn P256 public key
     * @param y The y coordinate of the WebAuthn P256 public key
     * @param resetPeriod The reset period for the key
     * @return key The WebAuthn P256 key object
     */
    function fromWebAuthnP256(uint256 x, uint256 y, ResetPeriod resetPeriod) internal pure returns (Key memory key) {
        key.keyType = KeyType.WebAuthnP256;
        key.resetPeriod = resetPeriod;
        key.publicKey = abi.encode(x, y);
        return key;
    }
}
