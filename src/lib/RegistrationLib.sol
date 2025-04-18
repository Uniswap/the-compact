// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResetPeriod } from "../types/ResetPeriod.sol";

import { EfficiencyLib } from "./EfficiencyLib.sol";
import { IdLib } from "./IdLib.sol";

/**
 * @title RegistrationLib
 * @notice Library contract implementing logic for registering compact claim hashes
 * and typehashes and querying for whether given claim hashes and typehashes have
 * been registered.
 */
library RegistrationLib {
    using RegistrationLib for address;
    using EfficiencyLib for uint256;
    using IdLib for ResetPeriod;

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
        assembly ("memory-safe") {
            // Retrieve the current free memory pointer.
            let m := mload(0x40)

            // Pack data for deriving active registration storage slot.
            mstore(add(m, 0x14), sponsor)
            mstore(m, _ACTIVE_REGISTRATIONS_SCOPE)
            mstore(add(m, 0x34), claimHash)
            mstore(add(m, 0x54), typehash)

            // Derive and load active registration storage slot to get current expiration.
            let cutoffSlot := keccak256(add(m, 0x1c), 0x58)

            // Store registration time in active registration storage slot.
            sstore(cutoffSlot, timestamp())

            // Emit the CompactRegistered event:
            //  - topic1: CompactRegistered event signature
            //  - topic2: sponsor address (sanitized)
            //  - data: [claimHash, typehash]
            log2(add(m, 0x34), 0x40, _COMPACT_REGISTERED_SIGNATURE, shr(0x60, shl(0x60, sponsor)))
        }
    }

    /**
     * @notice Internal function for registering multiple claim hashes in a single call. All
     * claim hashes will be registered using the shortest reset period on that compact as its
     * duration using the caller as the sponsor.
     * @param claimHashesAndTypehashes Array of [claimHash, typehash] pairs for registration.
     * @return                         Whether all claim hashes were successfully registered.
     */
    function registerBatchAsCaller(bytes32[2][] calldata claimHashesAndTypehashes) internal returns (bool) {
        unchecked {
            // Retrieve the total number of claim hashes and typehashes to register.
            uint256 totalClaimHashes = claimHashesAndTypehashes.length;

            // Iterate over each pair of claim hashes and typehashes.
            for (uint256 i = 0; i < totalClaimHashes; ++i) {
                // Retrieve the claim hash and typehash from calldata.
                bytes32[2] calldata claimHashAndTypehash = claimHashesAndTypehashes[i];

                // Register the compact as the caller.
                msg.sender.registerCompact(claimHashAndTypehash[0], claimHashAndTypehash[1]);
            }
        }

        return true;
    }

    /**
     * @notice Internal view function for retrieving the timestamp of a registration.
     * @param sponsor   The account that registered the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @return registrationTimestamp The timestamp at which the registration occurred.
     */
    function toRegistrationTimestamp(address sponsor, bytes32 claimHash, bytes32 typehash)
        internal
        view
        returns (uint256 registrationTimestamp)
    {
        assembly ("memory-safe") {
            // Retrieve the current free memory pointer.
            let m := mload(0x40)

            // Pack data for deriving active registration storage slot.
            mstore(add(m, 0x14), sponsor)
            mstore(m, _ACTIVE_REGISTRATIONS_SCOPE)
            mstore(add(m, 0x34), claimHash)
            mstore(add(m, 0x54), typehash)

            // Derive and load active registration storage slot to get registration timestamp.
            registrationTimestamp := sload(keccak256(add(m, 0x1c), 0x58))
        }
    }

    /**
     * @notice Internal view function for checking if a registration occurred.
     * @param sponsor   The account that registered the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @return          Whether the registration is inactive or has expired.
     */
    function hasNotBeenRegistered(address sponsor, bytes32 claimHash, bytes32 typehash) internal view returns (bool) {
        return sponsor.toRegistrationTimestamp(claimHash, typehash) == 0;
    }
}
