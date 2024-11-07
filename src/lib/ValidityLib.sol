// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Scope } from "../types/Scope.sol";

import { IdLib } from "./IdLib.sol";
import { ConsumerLib } from "./ConsumerLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { DomainLib } from "./DomainLib.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title ValidityLib
 * @notice Library contract implementing logic for validating expirations,
 * signatures, nonces (including consuming unused nonces), and token addresses.
 */
library ValidityLib {
    using IdLib for uint96;
    using IdLib for uint256;
    using ConsumerLib for uint256;
    using EfficiencyLib for bool;
    using DomainLib for bytes32;
    using SignatureCheckerLib for address;
    using ValidityLib for uint256;

    /**
     * @notice Internal function that retrieves an allocator's address from their ID and
     * consumes a nonce in their scope. Reverts if the allocator is not registered.
     * @param allocatorId The unique identifier for a registered allocator.
     * @param nonce       The nonce to consume in the allocator's scope.
     * @return allocator  The address of the registered allocator.
     */
    function fromRegisteredAllocatorIdWithConsumed(uint96 allocatorId, uint256 nonce) internal returns (address allocator) {
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
     * @notice Internal view function that validates a signature against an expected signer.
     * Returns if the signature is valid or if the caller is the expected signer, otherwise
     * reverts. The message hash is combined with the domain separator before verification.
     * If ECDSA recovery fails, an EIP-1271 isValidSignature check is performed.
     * @param messageHash     The EIP-712 hash of the message to verify.
     * @param expectedSigner  The address that should have signed the message.
     * @param signature       The signature to verify.
     * @param domainSeparator The domain separator to combine with the message hash.
     */
    function signedBy(bytes32 messageHash, address expectedSigner, bytes calldata signature, bytes32 domainSeparator) internal view {
        // Apply domain separator to message hash and verify it was signed correctly.
        bool hasValidSigner = expectedSigner.isValidSignatureNowCalldata(messageHash.withDomain(domainSeparator), signature);

        assembly ("memory-safe") {
            // Allow signature check to be bypassed if caller is the expected signer.
            if iszero(or(hasValidSigner, eq(expectedSigner, caller()))) {
                // revert InvalidSignature();
                mstore(0, 0x8baa579f)
                revert(0x1c, 0x04)
            }
        }
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
     * @notice Internal pure function that checks if an amount is within an allocated
     * amount. Reverts if the amount exceeds the allocation.
     * @param amount          The amount to validate.
     * @param allocatedAmount The maximum allowed amount.
     */
    function withinAllocated(uint256 amount, uint256 allocatedAmount) internal pure {
        assembly ("memory-safe") {
            if lt(allocatedAmount, amount) {
                // revert AllocatedAmountExceeded(allocatedAmount, amount);
                mstore(0, 0x3078b2f6)
                mstore(0x20, allocatedAmount)
                mstore(0x40, amount)
                revert(0x1c, 0x44)
            }
        }
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

    /**
     * @notice Internal function that combines two claim validations: whether the amount exceeds
     * allocation and whether the resource lock's scope is compatible with the claim context.
     * Returns true if either the allocated amount is exceeded or if the claim is exogenous but
     * the resource lock is chain-specific.
     * @param allocatedAmount         The total amount allocated for the claim.
     * @param amount                  The amount being claimed.
     * @param id                      The ERC6909 token identifier of the resource lock.
     * @param sponsorDomainSeparator  The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @return                        Whether either validation fails.
     */
    function allocationExceededOrScopeNotMultichain(uint256 allocatedAmount, uint256 amount, uint256 id, bytes32 sponsorDomainSeparator) internal pure returns (bool) {
        return (allocatedAmount < amount).or(id.scopeNotMultichain(sponsorDomainSeparator));
    }
}
