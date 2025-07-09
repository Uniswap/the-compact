// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IEmissary } from "src/interfaces/IEmissary.sol";
import { KeyLib, Key, KeyType } from "./KeyLib.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { IdLib } from "src/lib/IdLib.sol";

/**
 * @title KeyManagerEmissary
 * @notice A flexible fallback signature verifier for compact sponsors
 * @dev Supports Secp256k1 and P256 (including WebAuthn) keys
 */
contract KeyManagerEmissary is IEmissary {
    using KeyLib for Key;
    using IdLib for ResetPeriod;
    using IdLib for bytes12;

    /// @notice Registry of authorized keys for each sponsor
    /// @dev sponsor => keyHash => Key
    mapping(address sponsor => mapping(bytes32 keyHash => Key key)) public keys;

    /// @notice List of key hashes for each sponsor (for enumeration)
    /// @dev sponsor => keyHash[]
    mapping(address sponsor => bytes32[] keyHashes) public keyHashes;

    /// @notice Index of a key hash in the keyHashes array (for efficient removal)
    /// @dev sponsor => keyHash => index (0 = not found)
    mapping(address sponsor => mapping(bytes32 keyHash => uint256 index)) public keyIndices;

    /// @notice Emitted when a key is registered
    /// @param sponsor The sponsor address
    /// @param keyHash The key hash
    /// @param keyType The key type
    /// @param resetPeriod The reset period for the key
    event KeyRegistered(address indexed sponsor, bytes32 indexed keyHash, KeyType keyType, ResetPeriod resetPeriod);

    /// @notice Emitted when a key is removed
    /// @param sponsor The sponsor address
    /// @param keyHash The key hash
    event KeyRemoved(address indexed sponsor, bytes32 indexed keyHash);

    /// @notice Emitted when a key removal is scheduled
    /// @param sponsor The sponsor address
    /// @param keyHash The key hash
    /// @param removableAt The timestamp when the key can be removed
    event KeyRemovalScheduled(address indexed sponsor, bytes32 indexed keyHash, uint256 removableAt);

    /// @notice Emitted when a key is already registered
    /// @param sponsor The sponsor address
    /// @param keyHash The key hash
    error KeyAlreadyRegistered(address sponsor, bytes32 keyHash);

    /// @notice Emitted when a key is not registered
    /// @param sponsor The sponsor address
    /// @param keyHash The key hash
    error KeyNotRegistered(address sponsor, bytes32 keyHash);

    /// @notice Emitted when a key is invalid
    /// @param keyHash The key hash
    error InvalidKey(bytes32 keyHash);

    /// @notice Emitted when a signature verification fails
    error SignatureVerificationFailed();

    /// @notice Emitted when key removal is attempted before timelock expires
    /// @param removableAt The timestamp when removal will be available
    error KeyRemovalUnavailable(uint256 removableAt);

    /**
     * @notice Registers a new key for the caller (sponsor)
     * @param keyType The type of key to register
     * @param publicKey The public key to register
     * @param resetPeriod The reset period for the key
     */
    function registerKey(KeyType keyType, bytes calldata publicKey, ResetPeriod resetPeriod)
        external
        returns (bytes32 keyHash)
    {
        Key memory key = Key({ keyType: keyType, publicKey: publicKey, resetPeriod: resetPeriod, removalTimestamp: 0 });
        keyHash = key.hash();
        require(key.isValidKey(), InvalidKey(keyHash));
        require(!_keyExists(msg.sender, keyHash), KeyAlreadyRegistered(msg.sender, keyHash));

        // Store the key
        keys[msg.sender][keyHash] = key;

        // Add to key hashes list
        keyHashes[msg.sender].push(keyHash);
        keyIndices[msg.sender][keyHash] = keyHashes[msg.sender].length; // 1-based index

        emit KeyRegistered(msg.sender, keyHash, key.keyType, key.resetPeriod);
    }

    /**
     * @notice Schedules a key removal for the caller (sponsor)
     * @param keyHash The hash of the key to schedule for removal
     * @return removableAt The timestamp when the key can be removed
     */
    function scheduleKeyRemoval(bytes32 keyHash) external returns (uint256 removableAt) {
        require(_keyExists(msg.sender, keyHash), KeyNotRegistered(msg.sender, keyHash));

        // Get the key and its reset period
        Key storage key = keys[msg.sender][keyHash];
        ResetPeriod resetPeriod = key.resetPeriod;

        unchecked {
            // Calculate when the key can be removed (current time + reset period)
            removableAt = block.timestamp + resetPeriod.toSeconds();
        }

        // Store the removal schedule directly in the key
        key.removalTimestamp = uint64(removableAt);

        emit KeyRemovalScheduled(msg.sender, keyHash, removableAt);
    }

    /**
     * @notice Removes a key for the caller (sponsor)
     * @param keyHash The hash of the key to remove
     */
    function removeKey(bytes32 keyHash) external {
        if (!_keyExists(msg.sender, keyHash)) {
            revert KeyNotRegistered(msg.sender, keyHash);
        }

        // Check if removal has been properly scheduled and timelock has expired
        Key storage key = keys[msg.sender][keyHash];
        uint64 removableAt = key.removalTimestamp;
        require(removableAt != 0 && removableAt < block.timestamp, KeyRemovalUnavailable(removableAt));

        // Remove from keys mapping (delete the entire struct)
        delete keys[msg.sender][keyHash];

        // Remove from key hashes list (swap with last element and pop)
        uint256 index = keyIndices[msg.sender][keyHash] - 1;
        bytes32[] storage sponsorKeyHashes = keyHashes[msg.sender];

        assembly ("memory-safe") {
            let arrSlot := sponsorKeyHashes.slot
            let arrLen := sload(arrSlot)

            if lt(index, sub(arrLen, 1)) {
                // Get the last element
                mstore(0x00, arrSlot)
                let lastIndex := sub(arrLen, 1)
                let lastElementSlot := add(keccak256(0x00, 0x20), lastIndex)
                let lastKeyHash := sload(lastElementSlot)

                // Move last element to the index position
                let targetSlot := add(keccak256(0x00, 0x20), index)
                sstore(targetSlot, lastKeyHash)

                // Update the moved element's index in keyIndices
                mstore(0x00, caller())
                mstore(0x20, keyIndices.slot)
                let sponsorIndicesSlot := keccak256(0x00, 0x40)

                mstore(0x00, lastKeyHash)
                mstore(0x20, sponsorIndicesSlot)
                let movedKeyIndexSlot := keccak256(0x00, 0x40)
                sstore(movedKeyIndexSlot, add(index, 1)) // Store 1-based index
            }

            // Decrease array length
            sstore(arrSlot, sub(arrLen, 1))
        }

        // Clean up related storage
        delete keyIndices[msg.sender][keyHash];

        emit KeyRemoved(msg.sender, keyHash);
    }

    /**
     * @notice Verifies a claim signature using the registered keys for the sponsor
     * @param sponsor The sponsor whose keys should be checked
     * @param digest The EIP-712 digest that was signed
     * @param (claimHash) The claim hash that was signed (unused in this implementation)
     * @param signature The signature bytes
     * @param lockTag The lock tag to check reset period compatibility
     * @return selector IEmissary.verifyClaim.selector if verification succeeds
     */
    function verifyClaim(
        address sponsor,
        bytes32 digest,
        bytes32, /* claimHash */
        bytes calldata signature,
        bytes12 lockTag
    ) external view returns (bytes4 selector) {
        if (canVerifyClaim(sponsor, digest, bytes32(0), signature, lockTag)) {
            return IEmissary.verifyClaim.selector;
        }

        revert SignatureVerificationFailed();
    }

    /**
     * @notice Checks if a signature can be verified for a given sponsor and lock tag using any of their registered keys
     * @param sponsor The sponsor address
     * @param digest The EIP-712 digest that was signed
     * @param (claimHash) The claim hash that was signed (unused in this implementation)
     * @param signature The signature bytes
     * @param lockTag The lock tag to check reset period compatibility
     * @return canVerify True if the signature can be verified
     */
    function canVerifyClaim(
        address sponsor,
        bytes32 digest,
        bytes32, /* claimHash */
        bytes calldata signature,
        bytes12 lockTag
    ) public view returns (bool canVerify) {
        // Get all key hashes for this sponsor
        bytes32[] storage sponsorKeyHashes = keyHashes[sponsor];

        // Try to verify the signature against each registered key
        for (uint256 i = 0; i < sponsorKeyHashes.length; i++) {
            Key storage key = keys[sponsor][sponsorKeyHashes[i]];

            // Check reset period compatibility
            ResetPeriod lockTagResetPeriod = lockTag.toResetPeriod();
            ResetPeriod keyResetPeriod = key.resetPeriod;

            // Skip this key if reset periods are incompatible
            if (uint8(lockTagResetPeriod) > uint8(keyResetPeriod)) {
                continue;
            }

            // Try to verify signature with this key
            bool isValid = key.verify(digest, signature);
            if (isValid) return true;
        }

        // No registered key can verify the signature
        return false;
    }

    /**
     * @notice Get details about a specific key
     * @param sponsor The sponsor address
     * @param keyHash The key hash
     * @return key The key details
     */
    function getKey(address sponsor, bytes32 keyHash) external view returns (Key memory key) {
        if (!_keyExists(sponsor, keyHash)) {
            revert KeyNotRegistered(sponsor, keyHash);
        }

        return keys[sponsor][keyHash];
    }

    /**
     * @notice Get all key hashes for a sponsor
     * @param sponsor The sponsor address
     * @return hashes Array of key hashes
     */
    function getKeyHashes(address sponsor) external view returns (bytes32[] memory hashes) {
        return keyHashes[sponsor];
    }

    /**
     * @notice Check if a key is registered for a sponsor
     * @param sponsor The sponsor address
     * @param keyHash The key hash
     * @return isRegistered True if key is registered
     */
    function isKeyRegistered(address sponsor, bytes32 keyHash) external view returns (bool isRegistered) {
        return _keyExists(sponsor, keyHash);
    }

    /**
     * @notice Get the count of keys for a sponsor
     * @param sponsor The sponsor address
     * @return count Number of registered keys
     */
    function getKeyCount(address sponsor) external view returns (uint256 count) {
        return keyHashes[sponsor].length;
    }

    /**
     * @notice Compute the hash of a key
     * @param key The key to hash
     * @return keyHash The hash of the key
     */
    function computeKeyHash(Key calldata key) external pure returns (bytes32 keyHash) {
        return key.hash();
    }

    /**
     * @notice Validate a key structure
     * @param key The key to validate
     * @return isValid True if the key is valid
     */
    function validateKey(Key calldata key) external pure returns (bool isValid) {
        return key.isValidKey();
    }

    /**
     * @notice Get the reset period for a specific key
     * @param sponsor The sponsor address
     * @param keyHash The key hash
     * @return resetPeriod The reset period for the key
     */
    function getKeyResetPeriod(address sponsor, bytes32 keyHash) external view returns (ResetPeriod resetPeriod) {
        if (!_keyExists(sponsor, keyHash)) {
            revert KeyNotRegistered(sponsor, keyHash);
        }

        return keys[sponsor][keyHash].resetPeriod;
    }

    /**
     * @notice Get the removal status for a specific key
     * @param sponsor The sponsor address
     * @param keyHash The key hash
     * @return isScheduled True if removal is scheduled
     * @return removableAt The timestamp when the key can be removed (0 if not scheduled)
     */
    function getKeyRemovalStatus(address sponsor, bytes32 keyHash)
        external
        view
        returns (bool isScheduled, uint256 removableAt)
    {
        if (!_keyExists(sponsor, keyHash)) {
            revert KeyNotRegistered(sponsor, keyHash);
        }

        uint64 schedule = keys[sponsor][keyHash].removalTimestamp;
        isScheduled = (schedule != 0);
        removableAt = uint256(schedule);
    }

    /**
     * @notice Check if a key can be removed immediately
     * @param sponsor The sponsor address
     * @param keyHash The key hash
     * @return canRemove True if the key can be removed now
     */
    function canRemoveKey(address sponsor, bytes32 keyHash) external view returns (bool canRemove) {
        if (!_keyExists(sponsor, keyHash)) {
            return false;
        }

        uint64 removableAt = keys[sponsor][keyHash].removalTimestamp;
        return (removableAt != 0 && block.timestamp >= removableAt);
    }

    /**
     * @notice Checks if a key exists for a sponsor
     * @param sponsor The sponsor address
     * @param keyHash The key hash
     * @return exists True if key exists
     */
    function _keyExists(address sponsor, bytes32 keyHash) internal view returns (bool exists) {
        // A key exists if it has a valid keyType (structs default to zero values when uninitialized)
        // Since KeyType enum starts at 0 (P256), we check if publicKey has content
        return keys[sponsor][keyHash].publicKey.length > 0;
    }
}
