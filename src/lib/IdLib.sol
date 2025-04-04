// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";
import { Lock } from "../types/Lock.sol";
import { MetadataLib } from "./MetadataLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { CompactCategory } from "../types/CompactCategory.sol";

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

/**
 * @title IdLib
 * @notice Library contract implementing logic for deriving IDs for allocators and
 * for resource locks, converting between various IDs, and for extracting details
 * related to those IDs. This includes logic for registering allocators and for
 * assigning them an allocator ID.
 */
library IdLib {
    using IdLib for bytes12;
    using IdLib for uint96;
    using IdLib for uint256;
    using IdLib for address;
    using IdLib for ResetPeriod;
    using MetadataLib for Lock;
    using EfficiencyLib for bool;
    using EfficiencyLib for uint8;
    using EfficiencyLib for uint96;
    using EfficiencyLib for bytes12;
    using EfficiencyLib for uint256;
    using EfficiencyLib for address;
    using EfficiencyLib for ResetPeriod;
    using EfficiencyLib for Scope;
    using SignatureCheckerLib for address;
    using EfficientHashLib for bytes;

    error NoAllocatorRegistered(uint96 allocatorId);
    error AllocatorAlreadyRegistered(uint96 allocatorId, address allocator);

    // Storage slot seed for mapping allocator IDs to allocator addresses.
    uint256 private constant _ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED = 0x000044036fc77deaed2300000000000000000000000;

    // keccak256(bytes("AllocatorRegistered(uint96,address)")).
    uint256 private constant _ALLOCATOR_REGISTERED_EVENT_SIGNATURE = 0xc54dcaa67a8fd7b4a9aa6fd57351934c792613d5ec1acbd65274270e6de8f7e4;

    // Error selectors for NoAllocatorRegistered and AllocatorAlreadyRegistered.
    uint256 private constant _NO_ALLOCATOR_REGISTERED_ERROR_SIGNATURE = 0xcf90c3a8;
    uint256 private constant _ALLOCATOR_ALREADY_REGISTERED_ERROR_SIGNATURE = 0xc18b0e97;

    /**
     * @notice Internal function for registering an allocator. Derives an ID for the
     * allocator and stores the allocator's address for that ID, reverting if an
     * allocator has already been registered for the ID in question.
     * @param allocator The address to register as an allocator.
     * @return allocatorId The derived ID for the registered allocator.
     */
    function register(address allocator) internal returns (uint96 allocatorId) {
        // Derive the allocator ID for the provided allocator address.
        allocatorId = allocator.usingAllocatorId();

        assembly ("memory-safe") {
            // Derive storage slot for allocator registration by ID.
            let allocatorSlot := or(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED, allocatorId)

            // Retrieve the allocator value at the derived storage slot.
            let registeredAllocator := sload(allocatorSlot)

            // Revert if an allocator has already been registered for the ID.
            if registeredAllocator {
                mstore(0, _ALLOCATOR_ALREADY_REGISTERED_ERROR_SIGNATURE)
                mstore(0x20, allocatorId)
                mstore(0x40, registeredAllocator)
                revert(0x1c, 0x44)
            }

            // Store allocator address (sanitize first as an added precaution).
            allocator := shr(0x60, shl(0x60, allocator))
            sstore(allocatorSlot, allocator)

            // Emit AllocatorRegistered(allocatorId, allocator) event.
            mstore(0x00, allocatorId)
            mstore(0x20, allocator)
            log1(0x00, 0x40, _ALLOCATOR_REGISTERED_EVENT_SIGNATURE)
        }
    }

    /**
     * @notice Internal view function for constructing a resource lock ID assuming that the
     * provided allocator has been registered. Derives the allocator ID from the registered
     * allocator, and combines it with the provided scope, reset period, and token address
     * to form a single ID value. Reverts if the allocator is not registered.
     * @param token       The address of the underlying token.
     * @param scope       The scope of the resource lock (multichain or single chain).
     * @param resetPeriod The duration after which the resource lock can be reset.
     * @param allocator   The address of the allocator mediating the resource lock.
     * @return id         The derived resource lock ID.
     */
    function toIdIfRegistered(address token, Scope scope, ResetPeriod resetPeriod, address allocator) internal view returns (uint256 id) {
        // Derive the allocator ID for the provided allocator address.
        uint96 allocatorId = allocator.toAllocatorIdIfRegistered();

        // Derive resource lock ID (pack scope, reset period, allocator ID, & token).
        id = (allocatorId.toLockTag(scope, resetPeriod).asUint256() | token.asUint256());
    }

    /**
     * @notice Internal view function for retrieving an allocator's address from their ID.
     * Reverts if no allocator is registered with the provided ID.
     * @param allocatorId The ID to look up.
     * @return allocator  The registered allocator's address.
     */
    function toRegisteredAllocator(uint96 allocatorId) internal view returns (address allocator) {
        assembly ("memory-safe") {
            // Retrieve allocator from storage based on allocator ID.
            allocator := sload(or(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED, allocatorId))

            // Revert if no registered allocator is located.
            if iszero(allocator) {
                mstore(0, _NO_ALLOCATOR_REGISTERED_ERROR_SIGNATURE)
                mstore(0x20, allocatorId)
                revert(0x1c, 0x24)
            }
        }
    }

    /**
     * @notice Internal view function that verifies an allocator is registered and
     * returns their ID. Derives the allocator ID from the address and reverts if the
     * stored address doesn't exactly match the provided one.
     * @param allocator    The address to check registration for.
     * @return allocatorId The derived allocator ID.
     */
    function toAllocatorIdIfRegistered(address allocator) internal view returns (uint96 allocatorId) {
        // Derive the allocator ID for the provided allocator address.
        allocatorId = allocator.usingAllocatorId();

        assembly ("memory-safe") {
            // Revert on any difference between original address and stored address.
            if xor(allocator, sload(or(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED, allocatorId))) {
                mstore(0, _NO_ALLOCATOR_REGISTERED_ERROR_SIGNATURE)
                mstore(0x20, allocatorId)
                revert(0x1c, 0x24)
            }
        }
    }

    /**
     * @notice Internal view function for extracting and validating an allocator ID from
     * a resource lock ID. Reverts if the allocator is not registered.
     * @param id           The resource lock ID to extract from.
     * @return allocatorId The validated allocator ID.
     */
    function toRegisteredAllocatorId(uint256 id) internal view returns (uint96 allocatorId) {
        allocatorId = id.toAllocatorId();
        allocatorId.mustHaveARegisteredAllocator();
    }

    /**
     * @notice Internal view function that checks if an allocator ID has a registered
     * allocator. Reverts if no allocator is registered.
     * @param allocatorId The allocator ID to check.
     */
    function mustHaveARegisteredAllocator(uint96 allocatorId) internal view {
        assembly ("memory-safe") {
            // NOTE: consider an SLOAD bypass for a fully compact allocator
            if iszero(sload(or(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED, allocatorId))) {
                mstore(0, _NO_ALLOCATOR_REGISTERED_ERROR_SIGNATURE)
                mstore(0x20, allocatorId)
                revert(0x1c, 0x24)
            }
        }
    }

    /**
     * @notice Internal view function that checks if an allocator can be registered.
     * Returns true if any of the following are true:
     *  - The caller is the allocator
     *  - The allocator address contains code
     *  - The proof is a valid create2 deployment that derives the allocator address
     *    (e.g. proof must take the form of 0xff ++ factory ++ salt ++ initcode hash)
     * @param allocator The address to check.
     * @param proof     An 85-byte value containing create2 address derivation parameters.
     * @return          Whether the allocator can be registered.
     */
    function canBeRegistered(address allocator, bytes calldata proof) internal view returns (bool) {
        return (msg.sender == allocator).or(allocator.code.length > 0).or(proof.length == 85 && (proof[0] == 0xff).and(allocator == address(uint160(uint256(proof.hashCalldata())))));
    }

    /**
     * @notice Internal view function for retrieving an allocator's address from a
     * resource lock ID. Reverts if no allocator has been registered for the ID.
     * @param id         The resource lock ID to extract the allocator from.
     * @return allocator The address of the allocator.
     */
    function toAllocator(uint256 id) internal view returns (address allocator) {
        allocator = id.toAllocatorId().toRegisteredAllocator();
    }

    /**
     * @notice Internal view function for extracting the full Lock struct from a
     * resource lock ID.
     * @param id    The resource lock ID to extract from.
     * @return lock A Lock struct containing token, allocator, reset period, and scope.
     */
    function toLock(uint256 id) internal view returns (Lock memory lock) {
        lock.token = id.toAddress();
        lock.allocator = id.toAllocator();
        lock.resetPeriod = id.toResetPeriod();
        lock.scope = id.toScope();
    }

    /**
     * @notice Internal pure function for building the "lock tag" from an
     * allocatorId, scope, and reset period.
     * @param allocatorId The allocator ID.
     * @param scope       The scope of the resource lock (multichain or single chain).
     * @param resetPeriod The duration after which the resource lock can be reset.
     * @return            The lock tag.
     */
    function toLockTag(uint96 allocatorId, Scope scope, ResetPeriod resetPeriod) internal pure returns (bytes12) {
        // Derive lock tag (pack scope, reset period, & allocator ID).
        return ((scope.asUint256() << 255) | (resetPeriod.asUint256() << 252) | (allocatorId.asUint256() << 160)).asBytes12();
    }

    /**
     * @notice Internal pure function for extracting the "lock tag" from an ID.
     * @param id The resource lock ID.
     * @return lockTag The lock tag.
     */
    function toLockTag(uint256 id) internal pure returns (bytes12 lockTag) {
        // Extract the lock tag.
        assembly ("memory-safe") {
            lockTag := shl(160, shr(160, id))
        }
    }

    /**
     * @notice Internal pure function for extracting the last 20 bytes of an
     * underlying uint256 as an address. This represents either the token
     * address (for a resource lock ID) or the claimant address (for a claimant
     * value).
     * @param id The uint256 to extract from.
     * @return   The address.
     */
    function toAddress(uint256 id) internal pure returns (address) {
        return id.asSanitizedAddress();
    }

    /**
     * @notice Internal pure function for creating a new resource lock ID with a
     * different token address.
     * @param id         The resource lock ID to modify.
     * @param token      The new token address.
     * @return updatedId The modified resource lock ID.
     */
    function withReplacedToken(uint256 id, address token) internal pure returns (uint256 updatedId) {
        assembly ("memory-safe") {
            updatedId := or(shl(160, shr(160, id)), shr(96, shl(96, token)))
        }
    }

    /**
     * @notice Internal pure function for creating a new resource lock ID from an
     * existing id and a lock tag.
     * @param id         The resource lock ID to modify.
     * @param lockTag    The new lock tag.
     * @return updatedId The modified resource lock ID.
     */
    function withReplacedLockTag(uint256 id, bytes12 lockTag) internal pure returns (uint256 updatedId) {
        assembly ("memory-safe") {
            updatedId := or(shl(160, shr(160, lockTag)), shr(96, shl(96, id)))
        }
    }

    /**
     * @notice Internal pure function for extracting the scope from a resource lock ID.
     * @param id     The resource lock ID to extract from.
     * @return scope The scope (uppermost bit).
     */
    function toScope(uint256 id) internal pure returns (Scope scope) {
        assembly ("memory-safe") {
            // extract uppermost bit
            scope := shr(255, id)
        }
    }

    /**
     * @notice Internal pure function for extracting the reset period from a resource
     * lock ID.
     * @param id           The resource lock ID to extract from.
     * @return resetPeriod The reset period (bits 252-254).
     */
    function toResetPeriod(uint256 id) internal pure returns (ResetPeriod resetPeriod) {
        assembly ("memory-safe") {
            // extract 2nd, 3rd & 4th uppermost bits
            resetPeriod := and(shr(252, id), 7)
        }
    }

    /**
     * @notice Internal pure function for extracting the reset period from a resource
     * lock tag.
     * @param lockTag      The resource lock tag to extract from.
     * @return resetPeriod The reset period (bits 252-254).
     */
    function toResetPeriod(bytes12 lockTag) internal pure returns (ResetPeriod resetPeriod) {
        assembly ("memory-safe") {
            // extract 2nd, 3rd & 4th uppermost bits
            resetPeriod := and(shr(252, lockTag), 7)
        }
    }

    /**
     * @notice Internal pure function for extracting the compact flag from a resource
     * lock ID. The compact flag is a 4-bit component of the allocator ID.
     * @param id           The resource lock ID to extract from.
     * @return compactFlag The compact flag (bits 248-251).
     */
    function toCompactFlag(uint256 id) internal pure returns (uint8 compactFlag) {
        assembly ("memory-safe") {
            // extract 5th, 6th, 7th & 8th uppermost bits
            compactFlag := and(shr(248, id), 15)
        }
    }

    /**
     * @notice Internal pure function for extracting the allocator ID from a resource
     * lock ID. The allocator ID is a 92-bit value, with the first 4 bits representing
     * the compact flag and the last 88 bits matching the last 88 bits of the underlying
     * allocator, but is represented by a uint96 as solidity only supports uint values
     * for multiples of 8 bits.
     * @param id           The resource lock ID to extract from.
     * @return allocatorId The allocator ID (bits 160-251).
     */
    function toAllocatorId(uint256 id) internal pure returns (uint96 allocatorId) {
        assembly ("memory-safe") {
            // Extract bits 5-96.
            allocatorId := shr(164, shl(4, id))
        }
    }

    /**
     * @notice Internal pure function for converting a reset period to its duration in
     * seconds. There are eight distinct reset periods ranging from one second to
     * thirty days. Specific periods include some additional padding:
     *  - One hour is padded by five minutes
     *  - Seven days is padded by one hour
     * @dev No bounds check performed; ensure that the enum value is in range.
     * @param resetPeriod The reset period to convert.
     * @return duration   The duration in seconds.
     */
    function toSeconds(ResetPeriod resetPeriod) internal pure returns (uint256 duration) {
        assembly ("memory-safe") {
            // Bitpacked durations in 24-bit segments:
            // 278d00  094890  015180  000f3c  000258  00003c  00000f  000001
            // 30 days 7 days  1 day   1 hour  10 min  1 min   15 sec  1 sec
            let bitpacked := 0x278d00094890015180000f3c00025800003c00000f000001

            // Shift right by period * 24 bits & mask the least significant 24 bits.
            duration := and(shr(mul(resetPeriod, 24), bitpacked), 0xffffff)
        }
    }

    /**
     * @notice Internal pure function for computing an address's compact flag. The flag
     * is a 4-bit value that represents how "compact" the address of an allocator is. A
     * fully "compact" allocator address will have nine leading zero bytes, or eighteen
     * leading zero nibbles. To be considered even partially compact, the account must
     * have at least two leading zero bytes, or four leading zero nibbles. The full
     * scoring formula is therefore:
     *  - 0-3 leading zero nibbles: 0
     *  - 4-17 leading zero nibbles: number of leading zeros minus 3
     *  - 18+ leading zero nibbles: 15
     * @param allocator    The address to compute the flag for.
     * @return compactFlag The computed compact flag.
     */
    function toCompactFlag(address allocator) internal pure returns (uint8 compactFlag) {
        assembly ("memory-safe") {
            // Extract the uppermost 72 bits of the address.
            let x := shr(184, shl(96, allocator))

            // Propagate the highest set bit.
            x := or(x, shr(1, x))
            x := or(x, shr(2, x))
            x := or(x, shr(4, x))
            x := or(x, shr(8, x))
            x := or(x, shr(16, x))
            x := or(x, shr(32, x))

            // Count set bits to derive most significant bit in the last byte.
            let y := sub(x, and(shr(1, x), 0x5555555555555555))
            y := add(and(y, 0x3333333333333333), and(shr(2, y), 0x3333333333333333))
            y := and(add(y, shr(4, y)), 0x0f0f0f0f0f0f0f0f)
            y := add(y, shr(8, y))
            y := add(y, shr(16, y))
            y := add(y, shr(32, y))

            // Look up final value in the sequence.
            compactFlag := and(shr(and(sub(72, and(y, 127)), not(3)), 0xfedcba9876543210000), 15)
        }
    }

    /**
     * @notice Internal pure function for computing an allocator's ID from their address.
     * Combines the compact flag (4 bits) with the last 88 bits of the address.
     * @param allocator    The address to compute the ID for.
     * @return allocatorId The computed allocator ID.
     */
    function usingAllocatorId(address allocator) internal pure returns (uint96 allocatorId) {
        uint8 compactFlag = allocator.toCompactFlag();

        assembly ("memory-safe") {
            allocatorId := or(shl(88, compactFlag), shr(168, shl(168, allocator)))
        }
    }

    /**
     * @notice Internal pure function for extracting the allocator ID from a resource
     * lock tag. The allocator ID is a 92-bit value, with the first 4 bits representing
     * the compact flag and the last 88 bits matching the last 88 bits of the underlying
     * allocator, but is represented by a uint96 as solidity only supports uint values
     * for multiples of 8 bits.
     * @param lockTag      The resource lock tag to extract from.
     * @return allocatorId The allocator ID (bits 160-251).
     */
    function toAllocatorId(bytes12 lockTag) internal pure returns (uint96 allocatorId) {
        assembly ("memory-safe") {
            // Extract bits 5-96.
            allocatorId := shr(164, shl(4, lockTag))
        }
    }

    /**
     * @notice Internal view function for ensuring that the allocator ID from a resource
     * lock tag is registered to an allocator.
     * @param lockTag The resource lock tag to check allocator registration for.
     */
    function hasRegisteredAllocatorId(bytes12 lockTag) internal view {
        lockTag.toAllocatorId().mustHaveARegisteredAllocator();
    }

    /**
     * @notice Internal pure function for deriving a resource lock ID from a Lock struct.
     * The ID consists of:
     *  - Bit 255: scope
     *  - Bits 252-254: reset period
     *  - Bits 160-251: allocator ID (first 4 bits are compact flag, next 88 from allocator address)
     *  - Bits 0-159: token address
     * @dev Note that this will return an ID even if the allocator is unregistered.
     * @param lock The Lock struct containing the resource lock's components.
     * @return id  The derived resource lock ID.
     */
    function toId(Lock memory lock) internal pure returns (uint256 id) {
        id = ((lock.scope.asUint256() << 255) | (lock.resetPeriod.asUint256() << 252) | (lock.allocator.usingAllocatorId().asUint256() << 160) | lock.token.asUint256());
    }
}
