// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title RegistrationLib
 * @notice Library contract implementing logic for registering compact claim hashes
 * and typehashes and querying for whether given claim hashes and typehashes have
 * been registered.
 */
library RegistrationLib {
    using RegistrationLib for address;

    // keccak256(bytes("CompactRegistered(address,bytes32,bytes32)")).
    uint256 private constant _COMPACT_REGISTERED_SIGNATURE =
        0x52dd3aeaf9d70bfcfdd63526e155ba1eea436e7851acf5c950299321c671b927;

    // Storage scope for active registrations:
    // slot: keccak256(_ACTIVE_REGISTRATIONS_SCOPE ++ sponsor ++ claimHash ++ typehash) => expires.
    uint256 private constant _ACTIVE_REGISTRATIONS_SCOPE = 0x68a30dd0;

    /**
     * @notice Internal function for registering a claim hash.
     * @param sponsor   The account registering the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     */
    function registerCompact(address sponsor, bytes32 claimHash, bytes32 typehash) internal {
        uint256 registrationSlot = sponsor.deriveRegistrationSlot(claimHash, typehash);
        assembly ("memory-safe") {
            // Store 1 (true) in active registration storage slot.
            sstore(registrationSlot, 1)

            // Emit the CompactRegistered event:
            //  - topic1: CompactRegistered event signature
            //  - topic2: sponsor address (sanitized)
            //  - data: [claimHash, typehash]
            mstore(0, claimHash)
            mstore(0x20, typehash)
            log2(0, 0x40, _COMPACT_REGISTERED_SIGNATURE, shr(0x60, shl(0x60, sponsor)))
        }
    }

    /**
     * @notice Internal function for registering multiple claim hashes in a single call.
     * @param claimHashesAndTypehashes Array of [claimHash, typehash] pairs for registration.
     * @return                         Whether all claim hashes were successfully registered.
     */
    function registerBatchAsCaller(bytes32[2][] calldata claimHashesAndTypehashes) internal returns (bool) {
        // Retrieve the total number of claim hashes and typehashes to register.
        uint256 totalClaimHashes = claimHashesAndTypehashes.length;

        // Iterate over each pair of claim hashes and typehashes.
        for (uint256 i = 0; i < totalClaimHashes; ++i) {
            // Retrieve the claim hash and typehash from calldata.
            bytes32[2] calldata claimHashAndTypehash = claimHashesAndTypehashes[i];

            // Register the compact as the caller.
            msg.sender.registerCompact(claimHashAndTypehash[0], claimHashAndTypehash[1]);
        }

        return true;
    }

    /**
     * @notice Internal view function for retrieving the timestamp of a registration.
     * @param sponsor   The account that registered the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @return registered Whether the compact has been registered.
     */
    function isRegistered(address sponsor, bytes32 claimHash, bytes32 typehash)
        internal
        view
        returns (bool registered)
    {
        uint256 registrationSlot = sponsor.deriveRegistrationSlot(claimHash, typehash);
        assembly ("memory-safe") {
            // Load registration storage slot to get registration status.
            registered := sload(registrationSlot)
        }
    }

    /**
     * @notice Internal function for consuming (clearing) a registration.
     * @param sponsor   The account that registered the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     */
    function consumeRegistrationIfRegistered(address sponsor, bytes32 claimHash, bytes32 typehash)
        internal
        returns (bool consumed)
    {
        uint256 registrationSlot = sponsor.deriveRegistrationSlot(claimHash, typehash);
        assembly ("memory-safe") {
            consumed := sload(registrationSlot)
            if consumed { sstore(registrationSlot, 0) }
        }
    }

    /**
     * @notice Internal function for deriving the registration storage slot for a given claim hash and typehash.
     * @param sponsor   The account that registered the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @return registrationSlot The storage slot for the registration.
     */
    function deriveRegistrationSlot(address sponsor, bytes32 claimHash, bytes32 typehash)
        internal
        pure
        returns (uint256 registrationSlot)
    {
        assembly ("memory-safe") {
            // Retrieve the current free memory pointer.
            let m := mload(0x40)

            // Pack data for deriving active registration storage slot.
            mstore(add(m, 0x14), sponsor)
            mstore(m, _ACTIVE_REGISTRATIONS_SCOPE)
            mstore(add(m, 0x34), claimHash)
            mstore(add(m, 0x54), typehash)

            // Derive active registration storage slot.
            registrationSlot := keccak256(add(m, 0x1c), 0x58)
        }
    }
}
