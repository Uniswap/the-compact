// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ComponentLib } from "./ComponentLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { EventLib } from "./EventLib.sol";
import { HashLib } from "./HashLib.sol";
import { IdLib } from "./IdLib.sol";
import { RegistrationLib } from "./RegistrationLib.sol";
import { ValidityLib } from "./ValidityLib.sol";

import { AllocatorLib } from "./AllocatorLib.sol";

/**
 * @title ClaimProcessorLib
 * @notice Library contract implementing internal functions with helper logic for
 * processing claims against a signed or registered compact.
 * @dev IMPORTANT NOTE: logic for processing claims assumes that the utilized structs are
 * formatted in a very specific manner — if parameters are rearranged or new parameters
 * are inserted, much of this functionality will break. Proceed with caution when making
 * any changes.
 */
library ClaimProcessorLib {
    using ComponentLib for bytes32;
    using ClaimProcessorLib for uint256;
    using ClaimProcessorLib for bytes32;
    using EfficiencyLib for bool;
    using EfficiencyLib for uint256;
    using EventLib for address;
    using HashLib for uint256;
    using IdLib for uint256;
    using ValidityLib for uint256;
    using ValidityLib for uint96;
    using ValidityLib for bytes32;
    using RegistrationLib for address;
    using AllocatorLib for address;

    /**
     * @notice Internal function for validating claim execution parameters. Extracts and validates
     * signatures from calldata, checks expiration, verifies allocator registration, consumes the
     * nonce, derives the domain separator, and validates both the sponsor authorization (either
     * through direct registration or a provided signature or EIP-1271 call) and the (potentially
     * qualified) allocator authorization. Finally, emits a Claim event.
     * @dev caller of this function MUST implement reentrancy guard.
     * @param claimHash              The EIP-712 hash of the compact for which the claim is being validated.
     * @param allocatorId            The unique identifier for the allocator mediating the claim.
     * @param calldataPointer        Pointer to the location of the associated struct in calldata.
     * @param domainSeparator        The local domain separator.
     * @param sponsorDomainSeparator The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @param idsAndAmounts          The claimable resource lock IDs and amounts.
     * @param typehash               The EIP-712 typehash used for the claim message.
     * @return sponsor               The extracted address of the claim sponsor.
     */
    function validate(
        bytes32 claimHash,
        uint96 allocatorId,
        uint256 calldataPointer,
        bytes32 domainSeparator,
        bytes32 sponsorDomainSeparator,
        bytes32 typehash,
        uint256[2][] memory idsAndAmounts
    ) internal returns (address sponsor) {
        // Extract sponsor, nonce, and expires from calldata.
        uint256 nonce;
        uint256 expires;
        assembly ("memory-safe") {
            // Extract sponsor address from calldata, sanitizing upper 96 bits.
            sponsor := shr(0x60, calldataload(add(calldataPointer, 0x4c)))

            // Extract nonce and expiration timestamp from calldata.
            nonce := calldataload(add(calldataPointer, 0x60))
            expires := calldataload(add(calldataPointer, 0x80))

            // Swap domain separator for provided sponsorDomainSeparator if a nonzero value was supplied.
            sponsorDomainSeparator := add(sponsorDomainSeparator, mul(iszero(sponsorDomainSeparator), domainSeparator))
        }

        // Ensure that the claim hasn't expired.
        expires.later();

        // Retrieve allocator address and consume nonce, ensuring it has not already been consumed.
        address allocator = allocatorId.fromRegisteredAllocatorIdWithConsumed(nonce);

        // Validate that the sponsor has authorized the claim.
        _validateSponsor(sponsor, claimHash, calldataPointer, sponsorDomainSeparator, typehash, idsAndAmounts);

        // Validate that the allocator has authorized the claim.
        _validateAllocator(allocator, sponsor, claimHash, calldataPointer, idsAndAmounts, nonce, expires);

        // Emit claim event.
        sponsor.emitClaim(claimHash, allocator, nonce);
    }

    /**
     * @notice Internal function for processing simple claims with local domain
     * signatures. Extracts claim parameters from calldata, validates the claim,
     * and executes operations for multiple recipients. Uses the zero sponsor
     * domain separator.
     * @param claimHash       The EIP-712 hash of the compact for which the claim is being processed.
     * @param calldataPointer Pointer to the location of the associated struct in calldata.
     * @param typehash        The EIP-712 typehash used for the claim message.
     * @param domainSeparator The local domain separator.
     */
    function processSimpleClaim(bytes32 claimHash, uint256 calldataPointer, bytes32 typehash, bytes32 domainSeparator)
        internal
    {
        claimHash.processClaimWithComponents(calldataPointer, 0, typehash, domainSeparator, validate);
    }

    /**
     * @notice Internal function for processing simple batch claims with local domain
     * signatures. Extracts batch claim parameters from calldata, validates the claim,
     * and executes operations for multiple resource locks to multiple recipients. Uses the
     * message hash itself as the qualification message and a zero sponsor domain separator.
     * @param claimHash       The EIP-712 hash of the compact for which the claim is being processed.
     * @param calldataPointer Pointer to the location of the associated struct in calldata.
     * @param typehash        The EIP-712 typehash used for the claim message.
     * @param domainSeparator The local domain separator.
     */
    function processSimpleBatchClaim(
        bytes32 claimHash,
        uint256 calldataPointer,
        bytes32 typehash,
        bytes32 domainSeparator
    ) internal {
        claimHash.processClaimWithBatchComponents(calldataPointer, 0, typehash, domainSeparator, validate);
    }

    /**
     * @notice Internal function for processing claims with sponsor domain signatures.
     * Extracts claim parameters from calldata, validates the claim using the provided
     * sponsor domain, and executes operations for multiple recipients. Uses the message
     * hash itself as the qualification message.
     * @param claimHash       The EIP-712 hash of the compact for which the claim is being processed.
     * @param calldataPointer Pointer to the location of the associated struct in calldata.
     * @param sponsorDomain   The domain separator for the sponsor's signature.
     * @param typehash        The EIP-712 typehash used for the claim message.
     * @param domainSeparator The local domain separator.
     */
    function processClaimWithSponsorDomain(
        bytes32 claimHash,
        uint256 calldataPointer,
        bytes32 sponsorDomain,
        bytes32 typehash,
        bytes32 domainSeparator
    ) internal {
        claimHash.processClaimWithComponents(calldataPointer, sponsorDomain, typehash, domainSeparator, validate);
    }

    /**
     * @notice Internal function for processing batch claims with sponsor domain
     * signatures. Extracts batch claim parameters from calldata, validates the claim
     * using the provided sponsor domain, and executes operations for multiple resource
     * locks to multiple recipients. Uses the message hash itself as the qualification
     * message.
     * @param claimHash       The EIP-712 hash of the compact for which the claim is being processed.
     * @param calldataPointer Pointer to the location of the associated struct in calldata.
     * @param sponsorDomain   The domain separator for the sponsor's signature.
     * @param typehash        The EIP-712 typehash used for the claim message.
     * @param domainSeparator The local domain separator.
     */
    function processBatchClaimWithSponsorDomain(
        bytes32 claimHash,
        uint256 calldataPointer,
        bytes32 sponsorDomain,
        bytes32 typehash,
        bytes32 domainSeparator
    ) internal {
        claimHash.processClaimWithBatchComponents(calldataPointer, sponsorDomain, typehash, domainSeparator, validate);
    }

    /**
     * @notice Private view function to validate that a sponsor has authorized a given claim.
     * @dev Extracts the sponsor signature from calldata and validates authorization through
     * ECDSA, direct registration, EIP1271, or emissary.
     * @param sponsor                The address of the sponsor of the claimed compact.
     * @param claimHash              The EIP-712 hash of the compact where authorization is being checked.
     * @param calldataPointer        Pointer to the location of the associated struct in calldata.
     * @param sponsorDomainSeparator The domain separator for the sponsor's signature.
     * @param typehash               The EIP-712 typehash used for the claim message.
     * @param idsAndAmounts          The claimable resource lock IDs and amounts.
     */
    function _validateSponsor(
        address sponsor,
        bytes32 claimHash,
        uint256 calldataPointer,
        bytes32 sponsorDomainSeparator,
        bytes32 typehash,
        uint256[2][] memory idsAndAmounts
    ) private {
        bytes calldata sponsorSignature;
        assembly ("memory-safe") {
            // Extract sponsor signature from calldata using offset stored at calldataPointer + 0x20.
            let sponsorSignaturePtr := add(calldataPointer, calldataload(add(calldataPointer, 0x20)))
            sponsorSignature.offset := add(0x20, sponsorSignaturePtr)
            sponsorSignature.length := calldataload(sponsorSignaturePtr)
        }

        // Validate sponsor authorization through either ECDSA, direct registration, EIP1271, or emissary.
        claimHash.validateSponsorAndConsumeRegistration(
            sponsor, sponsorSignature, sponsorDomainSeparator, idsAndAmounts, typehash
        );
    }

    /**
     * @notice Private function to validate that an allocator has authorized a given claim.
     * @dev Extracts allocator data from calldata and validates allocator authorization through the allocator interface.
     * @param allocator       The address of the allocator mediating the claim.
     * @param sponsor         The address of the sponsor of the claimed compact.
     * @param claimHash       The EIP-712 hash of the compact where authorization is being checked.
     * @param calldataPointer Pointer to the location of the associated struct in calldata.
     * @param idsAndAmounts   The claimable resource lock IDs and amounts.
     * @param nonce           The nonce used for the claim.
     * @param expires         The expiration timestamp for the claim.
     */
    function _validateAllocator(
        address allocator,
        address sponsor,
        bytes32 claimHash,
        uint256 calldataPointer,
        uint256[2][] memory idsAndAmounts,
        uint256 nonce,
        uint256 expires
    ) private {
        // Extract allocator signature from calldata using offset stored at calldataPointer.
        bytes calldata allocatorData;
        assembly ("memory-safe") {
            let allocatorDataPtr := add(calldataPointer, calldataload(calldataPointer))
            allocatorData.offset := add(0x20, allocatorDataPtr)
            allocatorData.length := calldataload(allocatorDataPtr)
        }

        _validateAllocatorUsingExtractedData(
            allocator, sponsor, claimHash, allocatorData, idsAndAmounts, nonce, expires
        );
    }

    /**
     * @notice Private function to validate that the allocator has authorized the claim.
     * @dev Validates allocator authorization through the allocator interface using provided allocator data.
     * @param allocator     The address of the allocator mediating the claim.
     * @param sponsor       The address of the sponsor of the claimed compact.
     * @param claimHash     The EIP-712 hash of the compact where authorization is being checked.
     * @param allocatorData The allocator-specific data for claim authorization.
     * @param idsAndAmounts The claimable resource lock IDs and amounts.
     * @param nonce         The nonce used for the claim.
     * @param expires       The expiration timestamp for the claim.
     */
    function _validateAllocatorUsingExtractedData(
        address allocator,
        address sponsor,
        bytes32 claimHash,
        bytes calldata allocatorData,
        uint256[2][] memory idsAndAmounts,
        uint256 nonce,
        uint256 expires
    ) private {
        // Validate allocator authorization through the allocator interface.
        allocator.callAuthorizeClaim(claimHash, sponsor, nonce, expires, idsAndAmounts, allocatorData);
    }
}
