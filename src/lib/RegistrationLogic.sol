// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { RegistrationLib } from "./RegistrationLib.sol";
import { HashLib } from "./HashLib.sol";
import { COMPACT_TYPEHASH, BATCH_COMPACT_TYPEHASH } from "../types/EIP712Types.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";

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

    //// Registration of specific claims ////

    /**
     * @notice Internal function to register a claim with witness by its components.
     * @dev Constructs and registers the compact that consists exactly of the provided
     * arguments.
     * @param sponsor     Account that the claim should be registered for.
     * @param tokenId     Identifier for the associated token & lock.
     * @param amount      Claim's associated number of tokens.
     * @param arbiter     Account verifying and initiating the settlement of the claim.
     * @param nonce       Allocator replay protection nonce.
     * @param expires     Timestamp when the claim expires. Not to be confused with the reset
     * time of the compact.
     * @param typehash    Typehash of the entire compact. Including the subtypes of the
     * witness
     * @param witness     EIP712 structured hash of witness.
     * @param resetPeriod Duration after which the resource locks can be reset once forced
     * withdrawals are initiated.
     */
    function _registerUsingClaimWithWitness(address sponsor, uint256 tokenId, uint256 amount, address arbiter, uint256 nonce, uint256 expires, bytes32 typehash, bytes32 witness, ResetPeriod resetPeriod)
        internal
        returns (bytes32 claimhash)
    {
        claimhash = HashLib.toFlatMessageHashWithWitness(sponsor, tokenId, amount, arbiter, nonce, expires, typehash, witness);
        sponsor.registerCompact(claimhash, typehash, resetPeriod);
    }

    /**
     * @notice Internal function to register a batch claim with witness by its components.
     * @dev Constructs and registers the compact that consists exactly of the provided
     * arguments.
     * @param sponsor       Account that the claim should be registered for.
     * @param idsAndAmounts Ids and amounts associated with the to be registered claim.
     * @param arbiter       Account verifying and initiating the settlement of the claim.
     * @param nonce         Nonce to register the claim at. The nonce is not checked to be
     * unspent
     * @param expires       Timestamp when the claim expires. Not to be confused with the
     * reset time of the compact.
     * @param typehash      Typehash of the entire compact. Including the subtypes of the
     * witness
     * @param witness       EIP712 structured hash of witness.
     * @param resetPeriod   Duration after which the resource locks can be reset once forced
     * withdrawals are initiated.
     */
    function _registerUsingBatchClaimWithWitness(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        ResetPeriod resetPeriod
    ) internal returns (bytes32 claimhash) {
        claimhash = HashLib.toFlatBatchClaimWithWitnessMessageHash(sponsor, idsAndAmounts, arbiter, nonce, expires, typehash, witness);
        sponsor.registerCompact(claimhash, typehash, resetPeriod);
    }
}
