// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { RegistrationLib } from "./RegistrationLib.sol";
import { HashLib } from "./HashLib.sol";
import { ValidityLib } from "./ValidityLib.sol";
import { DomainLib } from "./DomainLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";

import { ConstructorLogic } from "./ConstructorLogic.sol";

/**
 * @title RegistrationLogic
 * @notice Inherited contract implementing logic for registering compact claim hashes
 * and typehashes and querying for whether given claim hashes and typehashes have
 * been registered.
 */
contract RegistrationLogic is ConstructorLogic {
    using RegistrationLib for address;
    using RegistrationLib for bytes32[2][];
    using ValidityLib for bytes32;
    using DomainLib for uint256;
    using EfficiencyLib for address;

    /**
     * @notice Internal function for registering a claim hash. The claim hash and its
     * associated typehash will remain valid until the allocator consumes the nonce.
     * @param sponsor   The account registering the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     */
    function _register(address sponsor, bytes32 claimHash, bytes32 typehash) internal {
        sponsor.registerCompact(claimHash, typehash);
    }

    /**
     * @notice Internal function for registering multiple claim hashes in a single call. Each
     * claim hash and its associated typehash will remain valid until the allocator consumes the nonce.
     * @param claimHashesAndTypehashes Array of [claimHash, typehash] pairs for registration.
     * @return                         Whether all claim hashes were successfully registered.
     */
    function _registerBatch(bytes32[2][] calldata claimHashesAndTypehashes) internal returns (bool) {
        return claimHashesAndTypehashes.registerBatchAsCaller();
    }

    /**
     * @notice Internal function for registering a compact on behalf of a sponsor with their signature.
     * @param sponsor          The address of the sponsor for whom the compact is being registered.
     * @param typehash         The EIP-712 typehash associated with the registered compact.
     * @param sponsorSignature The signature from the sponsor authorizing the registration.
     * @return claimHash       The hash of the registered compact.
     */
    function _registerFor(address sponsor, bytes32 typehash, bytes calldata sponsorSignature)
        internal
        returns (bytes32 claimHash)
    {
        return _deriveClaimHashAndRegisterCompact(sponsor, typehash, 0x120, _domainSeparator(), sponsorSignature);
    }

    /**
     * @notice Internal function for registering a batch compact on behalf of a sponsor with their signature.
     * @param sponsor          The address of the sponsor for whom the compact is being registered.
     * @param typehash         The EIP-712 typehash associated with the registered compact.
     * @param sponsorSignature The signature from the sponsor authorizing the registration.
     * @return claimHash       The hash of the registered batch compact.
     */
    function _registerBatchFor(address sponsor, bytes32 typehash, bytes calldata sponsorSignature)
        internal
        returns (bytes32 claimHash)
    {
        return _deriveClaimHashAndRegisterCompact(sponsor, typehash, 0xe0, _domainSeparator(), sponsorSignature);
    }

    /**
     * @notice Internal function for registering a multichain compact on behalf of a sponsor with their signature.
     * Note that the multichain compact in question will need to be independently registered on each chain where
     * onchain registration is desired.
     * @param sponsor          The address of the sponsor for whom the compact is being registered.
     * @param typehash         The EIP-712 typehash associated with the registered compact.
     * @param notarizedChainId Chain ID of the domain used to sign the multichain compact.
     * @param sponsorSignature The signature from the sponsor authorizing the registration.
     * @return claimHash       The hash of the registered multichain compact.
     */
    function _registerMultichainFor(
        address sponsor,
        bytes32 typehash,
        uint256 notarizedChainId,
        bytes calldata sponsorSignature
    ) internal returns (bytes32 claimHash) {
        return _deriveClaimHashAndRegisterCompact(
            sponsor, typehash, 0xa0, notarizedChainId.toNotarizedDomainSeparator(), sponsorSignature
        );
    }

    /**
     * @notice Internal function for deriving a claim hash and registering it as a compact.
     * @param sponsor          The address of the sponsor for whom the compact is being registered.
     * @param typehash         The EIP-712 typehash associated with the registered compact.
     * @param preimageLength   The length of the preimage data used to derive the claim hash.
     * @param domainSeparator  The domain separator to use for signature verification.
     * @param sponsorSignature The signature from the sponsor authorizing the registration.
     * @return claimHash       The derived and registered claim hash.
     */
    function _deriveClaimHashAndRegisterCompact(
        address sponsor,
        bytes32 typehash,
        uint256 preimageLength,
        bytes32 domainSeparator,
        bytes calldata sponsorSignature
    ) internal returns (bytes32 claimHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Copy relevant arguments from calldata to prepare hash preimage.
            // Note that provided arguments may have dirty upper bits, which will
            // give a claim hash that cannot be derived during claim processing.
            calldatacopy(m, 0x04, preimageLength)

            // Derive the claim hash from the prepared preimage data.
            claimHash := keccak256(m, preimageLength)
        }

        // Ensure that the sponsor has verified the supplied claim hash.
        claimHash.hasValidSponsor(sponsor, sponsorSignature, domainSeparator);

        // Register the compact for the indicated sponsor.
        sponsor.registerCompact(claimHash, typehash);
    }

    /**
     * @notice Internal view function for retrieving the expiration timestamp of a
     * registration.
     * @param sponsor   The account that registered the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @return registered Whether the compact has been registered.
     */
    function _isRegistered(address sponsor, bytes32 claimHash, bytes32 typehash)
        internal
        view
        returns (bool registered)
    {
        registered = sponsor.isRegistered(claimHash, typehash);
    }

    //// Registration of specific compacts ////

    /**
     * @notice Internal function to register a compact by its components.
     * @dev Constructs and registers the compact that consists exactly of the provided
     * arguments.
     * @param sponsor    Account that the compact should be registered for.
     * @param tokenId    Identifier for the associated token & lock.
     * @param amount     Compact's associated number of tokens.
     * @param arbiter    Account able to initiate a claim against the registered compact.
     * @param nonce      Allocator-scoped replay protection nonce.
     * @param expires    Timestamp when the compact expires.
     * @param typehash   Typehash of the entire compact including subtypes of the witness.
     * @param witness    EIP712 structured hash of witness.
     * @return claimHash EIP712 structured hash of the compact to register.
     */
    function _registerUsingCompact(
        address sponsor,
        uint256 tokenId,
        uint256 amount,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) internal returns (bytes32 claimHash) {
        // Reassign sponsor to the caller if the null address was provided.
        sponsor = sponsor.usingCallerIfNull();

        claimHash = HashLib.toClaimHashFromDeposit(sponsor, tokenId, amount, arbiter, nonce, expires, typehash, witness);
        sponsor.registerCompact(claimHash, typehash);
    }

    /**
     * @notice Internal function to register a batch compact by its components.
     * @dev Constructs and registers the compact that consists exactly of the provided
     * arguments.
     * @param sponsor            Account that the compact should be registered for.
     * @param idsAndAmounts      Ids and amounts associated with the registered compact.
     * @param arbiter            Account able to initiate a claim against the registered compact.
     * @param nonce              Allocator-scoped replay protection nonce.
     * @param expires            Timestamp when the compact expires.
     * @param typehash           Typehash of the entire compact including subtypes of the witness.
     * @param witness            EIP712 structured hash of witness.
     * @param replacementAmounts An array of replacement amounts.
     * @return claimHash         EIP712 structured hash of the registered compact.
     */
    function _registerUsingBatchCompact(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        uint256[] memory replacementAmounts
    ) internal returns (bytes32 claimHash) {
        // Reassign sponsor to the caller if the null address was provided.
        sponsor = sponsor.usingCallerIfNull();

        claimHash = HashLib.toClaimHashFromBatchDeposit(
            sponsor, idsAndAmounts, arbiter, nonce, expires, typehash, witness, replacementAmounts
        );
        sponsor.registerCompact(claimHash, typehash);
    }
}
