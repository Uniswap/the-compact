// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { RegistrationLib } from "./RegistrationLib.sol";

/**
 * @title RegistrationLogic
 * @notice Inherited contract implementing logic for registering compact claim hashes
 * and typehashes and querying for whether given claim hashes and typehashes have
 * been registered.
 */
contract RegistrationLogic {
    using RegistrationLib for address;
    using RegistrationLib for bytes32;
    using RegistrationLib for bytes32[2][];

    /**
     * @notice Internal function for registering a claim hash with a specific duration. The
     * claim hash and its associated typehash will remain valid until the specified duration
     * has elapsed. Reverts if the duration would result in an expiration earlier than an
     * existing registration or if it exceeds 30 days.
     * @param sponsor   The account registering the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @param duration  The duration for which the registration remains valid.
     */
    function _register(address sponsor, bytes32 claimHash, bytes32 typehash, uint256 duration) internal {
        sponsor.registerCompactWithSpecificDuration(claimHash, typehash, duration);
    }

    /**
     * @notice Internal function for registering a claim hash using the default duration
     * (10 minutes) and the caller as the sponsor.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     */
    function _registerWithDefaults(bytes32 claimHash, bytes32 typehash) internal {
        claimHash.registerAsCallerWithDefaultDuration(typehash);
    }

    /**
     * @notice Internal function for registering multiple claim hashes in a single call. All
     * claim hashes will be registered with the same duration using the caller as the sponsor.
     * @param claimHashesAndTypehashes Array of [claimHash, typehash] pairs for registration.
     * @param duration                 The duration for which the claim hashes remain valid.
     * @return                         Whether all claim hashes were successfully registered.
     */
    function _registerBatch(bytes32[2][] calldata claimHashesAndTypehashes, uint256 duration) internal returns (bool) {
        return claimHashesAndTypehashes.registerBatchAsCaller(duration);
    }

    /**
     * @notice Internal view function for retrieving the expiration timestamp of a
     * registration.
     * @param sponsor   The account that registered the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @return expires  The timestamp at which the registration expires.
     */
    function _getRegistrationStatus(address sponsor, bytes32 claimHash, bytes32 typehash) internal view returns (uint256 expires) {
        return sponsor.toRegistrationExpiration(claimHash, typehash);
    }
}
