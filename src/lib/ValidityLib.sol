// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Scope } from "../types/Scope.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";

import { IdLib } from "./IdLib.sol";
import { ConsumerLib } from "./ConsumerLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { DomainLib } from "./DomainLib.sol";
import { EmissaryLib } from "./EmissaryLib.sol";
import { RegistrationLib } from "./RegistrationLib.sol";

import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title ValidityLib
 * @notice Library contract implementing logic for validating expirations,
 * signatures, nonces (including consuming unused nonces), and token addresses.
 */
library ValidityLib {
    using RegistrationLib for address;
    using ValidityLib for address;
    using IdLib for uint96;
    using IdLib for uint256;
    using IdLib for ResetPeriod;
    using ConsumerLib for uint256;
    using EfficiencyLib for bool;
    using EfficiencyLib for uint256;
    using EfficiencyLib for ResetPeriod;
    using DomainLib for bytes32;
    using ValidityLib for uint256;
    using EmissaryLib for bytes32;
    using EmissaryLib for uint256[2][];
    using FixedPointMathLib for uint256;
    using SignatureCheckerLib for address;

    error NoIdsAndAmountsProvided();

    /**
     * @notice Internal function that retrieves an allocator's address from their ID and
     * consumes a nonce in their scope. Reverts if the allocator is not registered.
     * @param allocatorId The unique identifier for a registered allocator.
     * @param nonce       The nonce to consume in the allocator's scope.
     * @return allocator  The address of the registered allocator.
     */
    function fromRegisteredAllocatorIdWithConsumed(uint96 allocatorId, uint256 nonce)
        internal
        returns (address allocator)
    {
        allocator = allocatorId.toRegisteredAllocator();
        nonce.consumeNonceAsAllocator(allocator);
    }

    /**
     * @notice Internal function that retrieves an allocator's address from a resource lock ID
     * and consumes a nonce in their scope. Reverts if the allocator is not registered.
     * @param id         The ERC6909 token identifier containing the allocator ID.
     * @param nonce      The nonce to consume in the allocator's scope.
     * @return allocator The address of the registered allocator.
     */
    function toRegisteredAllocatorWithConsumed(uint256 id, uint256 nonce) internal returns (address allocator) {
        allocator = id.toAllocator();
        nonce.consumeNonceAsAllocator(allocator);
    }

    /**
     * @notice Internal view function that ensures that a timestamp has not yet passed.
     * Reverts if the provided timestamp is not in the future.
     * @param expires The timestamp to check.
     */
    function later(uint256 expires) internal view {
        assembly ("memory-safe") {
            if iszero(gt(expires, timestamp())) {
                // revert Expired(expiration);
                mstore(0, 0xf80dbaea)
                mstore(0x20, expires)
                revert(0x1c, 0x24)
            }
        }
    }

    /**
     * @notice Internal function that validates a signature against an expected signer.
     * Returns if the signature is valid or if the caller is the expected signer, otherwise
     * reverts. The message hash is combined with the domain separator before verification.
     * If ECDSA recovery fails, an EIP-1271 isValidSignature check is performed. Note that
     * an emissary check will not be performed.
     * @param messageHash     The EIP-712 hash of the message to verify.
     * @param expectedSigner  The address that should have signed the message.
     * @param signature       The signature to verify.
     * @param domainSeparator The domain separator to combine with the message hash.
     */
    function hasValidSponsor(
        bytes32 messageHash,
        address expectedSigner,
        bytes calldata signature,
        bytes32 domainSeparator
    ) internal view {
        // Apply domain separator to message hash to derive the digest.
        bytes32 digest = messageHash.withDomain(domainSeparator);

        // First, check signature against digest with ECDSA (or ensure sponsor is caller).
        if (expectedSigner.isValidECDSASignatureCalldata(digest, signature)) {
            return;
        }

        // Finally, check EIP1271 using the digest and signature.
        if (!expectedSigner.isValidERC1271SignatureNowCalldata(digest, signature)) {
            assembly ("memory-safe") {
                // revert InvalidSignature();
                mstore(0, 0x8baa579f)
                revert(0x1c, 0x04)
            }
        }
    }

    /**
     * @notice Internal function that validates a signature or registration against an expected
     * signer. If the initial verification fails, the emissary is used to valdiate the claim.
     * Returns if the signature is valid or if the caller is the expected signer, otherwise
     * reverts. The claim hash is combined with the domain separator before verification.
     * If ECDSA recovery fails, an EIP-1271 isValidSignature check is performed with half of
     * available gas. If EIP-1271 fails, and an IEmissary is set for the sponsor, an
     * IEmissary.verifyClaim check is performed.
     * @param claimHash           The EIP-712 hash of the claim to verify.
     * @param expectedSigner      The address that should have signed the message.
     * @param signature           The signature to verify.
     * @param domainSeparator     The domain separator to combine with the message hash.
     * @param typehash            The EIP-712 typehash used for the claim message.
     * @param shortestResetPeriod The shortest reset period across all resource locks on the compact.
     */
    function hasValidSponsorOrRegistration(
        bytes32 claimHash,
        address expectedSigner,
        bytes calldata signature,
        bytes32 domainSeparator,
        uint256[2][] memory idsAndAmounts,
        bytes32 typehash,
        uint256 shortestResetPeriod
    ) internal view {
        // Get registration status early if no signature is supplied.
        bool checkedRegistrationPeriod;
        if (signature.length == 0) {
            uint256 registrationTimestamp = expectedSigner.toRegistrationTimestamp(claimHash, typehash);

            if ((registrationTimestamp != 0).and(registrationTimestamp + shortestResetPeriod > block.timestamp)) {
                return;
            }

            checkedRegistrationPeriod = true;
        }

        // Apply domain separator to message hash to derive the digest.
        bytes32 digest = claimHash.withDomain(domainSeparator);

        // First, check signature against digest with ECDSA (or ensure sponsor is caller).
        if (expectedSigner.isValidECDSASignatureCalldata(digest, signature)) {
            return;
        }

        // Next, check for an active registration if not yet checked.
        if (!checkedRegistrationPeriod) {
            uint256 registrationTimestamp = expectedSigner.toRegistrationTimestamp(claimHash, typehash);

            if ((registrationTimestamp != 0).and(registrationTimestamp + shortestResetPeriod > block.timestamp)) {
                return;
            }
        }

        // Then, check EIP1271 using the digest, supplying half of available gas.
        if (expectedSigner.isValidERC1271SignatureNowCalldataHalfGas(digest, signature)) {
            return;
        }

        // Finally, fallback to emissary using the digest
        digest.verifyWithEmissary(expectedSigner, idsAndAmounts.extractSameLockTag(), signature);
    }

    /**
     * @notice Internal view function to check if a nonce has been consumed in an
     * allocator's scope.
     * @param allocator The allocator whose scope to check.
     * @param nonce     The nonce to check.
     * @return          Whether the nonce has been consumed.
     */
    function hasConsumedAllocatorNonce(address allocator, uint256 nonce) internal view returns (bool) {
        return nonce.isConsumedByAllocator(allocator);
    }

    /**
     * @notice Internal pure function that validates a token address is not the zero
     * address (which represents native tokens). Reverts if the address is zero.
     * @param token The token address to validate.
     * @return      The validated token address.
     */
    function excludingNative(address token) internal pure returns (address) {
        assembly ("memory-safe") {
            if iszero(shl(96, token)) {
                // revert InvalidToken(0);
                mstore(0x40, 0x961c9a4f)
                revert(0x5c, 0x24)
            }
        }

        return token;
    }

    /**
     * @notice Internal pure function for validating that a resource lock's scope is compatible
     * with the provided sponsor domain separator. Reverts if an exogenous claim (indicated by
     * a non-zero sponsor domain separator) attempts to claim against a chain-specific resource
     * lock (indicated by the most significant bit of the id).
     * @param sponsorDomainSeparator The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @param id                     The ERC6909 token identifier of the resource lock.
     */
    function ensureValidScope(bytes32 sponsorDomainSeparator, uint256 id) internal pure {
        assembly ("memory-safe") {
            if iszero(or(iszero(sponsorDomainSeparator), iszero(shr(255, id)))) {
                // revert InvalidScope(id)
                mstore(0, 0xa06356f5)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }
        }
    }

    /**
     * @notice Internal pure function for determining if a resource lock has chain-specific
     * scope in the context of an exogenous claim. Returns true if the claim is exogenous
     * (indicated by a non-zero sponsor domain separator) and the resource lock is
     * chain-specific.
     * @param id                     The ERC6909 token identifier of the resource lock.
     * @param sponsorDomainSeparator The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @return                       Whether the resource lock's scope is incompatible with the claim context.
     */
    function scopeNotMultichain(uint256 id, bytes32 sponsorDomainSeparator) internal pure returns (bool) {
        return (sponsorDomainSeparator != bytes32(0)).and(id.toScope() == Scope.ChainSpecific);
    }

    /// @dev Returns whether `signature` is valid for `signer` and `hash`.
    /// using `ecrecover`.
    function isValidECDSASignatureCalldata(address signer, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool isValid)
    {
        // Determine whether the signer is the caller.
        bool signerIsCaller = signer == msg.sender;

        // Exit early if signer is either the caller or the null address.
        if ((signer == address(0)).or(signerIsCaller)) {
            // Valid if signer is caller, otherwise invalid (null address).
            return signerIsCaller;
        }

        assembly ("memory-safe") {
            // Cache free memory pointer.
            let m := mload(0x40)

            // Use a faux loop to support breaking early.
            for { } 1 { } {
                // examine the length of the supplied signature.
                switch signature.length
                case 64 {
                    // Parse length 64 as EIP2098 compact signatures.
                    let vs := calldataload(add(signature.offset, 0x20))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x40, calldataload(signature.offset)) // `r`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                }
                case 65 {
                    // Parse length 65 as standard rsv signatures.
                    mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) // `v`.
                    calldatacopy(0x40, signature.offset, 0x40) // `r`, `s`.
                }
                default { break }

                // Prepare hash in scratch space.
                mstore(0x00, hash)

                // Call the ecrecover precompile and examine returndata for validity.
                let recovered := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
                isValid := gt(returndatasize(), shl(96, xor(signer, recovered)))

                // Restore the zero slot and free memory pointer.
                mstore(0x60, 0)
                mstore(0x40, m)
                break
            }
        }
    }

    /// @dev Returns whether `signature` is valid for `hash` for an ERC1271 `signer` contract.
    /// Sourced from Solady with a modification to only supply half of available gas.
    function isValidERC1271SignatureNowCalldataHalfGas(address signer, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool isValid)
    {
        assembly ("memory-safe") {
            let m := mload(0x40)
            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            mstore(add(m, 0x44), signature.length)
            // Copy the `signature` over.
            calldatacopy(add(m, 0x64), signature.offset, signature.length)
            isValid := staticcall(div(gas(), 2), signer, m, add(signature.length, 0x64), d, 0x20)
            isValid := and(eq(mload(d), f), isValid)
        }
    }
}
