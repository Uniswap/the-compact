// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";

import { ConsumerLib } from "./ConsumerLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { IdLib } from "./IdLib.sol";
import { ValidityLib } from "./ValidityLib.sol";

import { ITheCompact } from "../interfaces/ITheCompact.sol";

/**
 * @title AllocatorLogic
 * @notice Inherited contract implementing internal functions with logic for registering
 * new allocators, allowing registered allocators to directly consume nonces within their
 * scope, and querying for information on nonce consumption and lock details.
 */
contract AllocatorLogic {
    using IdLib for uint96;
    using IdLib for uint256;
    using IdLib for address;
    using ConsumerLib for uint256;
    using EfficiencyLib for uint256;
    using ValidityLib for address;

    /**
     * @notice Internal function for marking allocator nonces as consumed. Once consumed, a nonce
     * cannot be reused to claim resource locks referencing that allocator. Called by the external
     * consume function and during claim processing to prevent replay attacks.
     * @param nonces Array of nonces to mark as consumed for the calling allocator.
     * @return       Whether all nonces were successfully marked as consumed.
     */
    function _consume(uint256[] calldata nonces) internal returns (bool) {
        // NOTE: this may not be necessary, consider removing
        msg.sender.usingAllocatorId().mustHaveARegisteredAllocator();

        unchecked {
            uint256 i;

            assembly ("memory-safe") {
                i := nonces.offset
            }

            uint256 end = i + (nonces.length << 5);
            uint256 nonce;
            for (; i < end; i += 0x20) {
                assembly ("memory-safe") {
                    nonce := calldataload(i)
                }
                nonce.consumeNonceAsAllocator(msg.sender);

                emit ITheCompact.NonceConsumedDirectly(msg.sender, nonce);
            }
        }

        return true;
    }

    /**
     * @notice Internal function for registering an allocator. Validates that one of three
     * conditions is met: caller is the allocator address, allocator address contains code, or
     * proof represents valid create2 deployment parameters that derive the allocator address.
     * @param allocator    The address to register as an allocator.
     * @param proof        An 85-byte value containing create2 address derivation parameters.
     * @return allocatorId A unique identifier assigned to the registered allocator.
     */
    function _registerAllocator(address allocator, bytes calldata proof) internal returns (uint96 allocatorId) {
        allocator = uint256(uint160(allocator)).asSanitizedAddress();
        if (!allocator.canBeRegistered(proof)) {
            assembly ("memory-safe") {
                // revert InvalidRegistrationProof(allocator)
                mstore(0, 0x4e7f492b)
                mstore(0x20, allocator)
                revert(0x1c, 0x24)
            }
        }

        allocatorId = allocator.register();
    }

    /**
     * @notice Internal view function for checking whether a specific nonce has been consumed by
     * an allocator.
     * @param nonce     The nonce to check.
     * @param allocator The address of the allocator.
     * @return          Whether the nonce has been consumed.
     */
    function _hasConsumedAllocatorNonce(uint256 nonce, address allocator) internal view returns (bool) {
        return allocator.hasConsumedAllocatorNonce(nonce);
    }

    /**
     * @notice Internal view function for retrieving the details of a resource lock.
     * @param id           The ERC6909 token identifier for the resource lock.
     * @return token       The address of the underlying token (or address(0) for native tokens).
     * @return allocator   The address of the allocator mediating the resource lock.
     * @return resetPeriod The duration after which the underlying tokens can be withdrawn once a forced withdrawal is initiated.
     * @return scope       The scope of the resource lock (multichain or single chain).
     * @return lockTag     The lock tag containing the allocator ID, the reset period, and the scope.
     */
    function _getLockDetails(uint256 id) internal view returns (address token, address allocator, ResetPeriod resetPeriod, Scope scope, bytes12 lockTag) {
        token = id.toAddress();
        allocator = id.toAllocatorId().toRegisteredAllocator();
        resetPeriod = id.toResetPeriod();
        scope = id.toScope();
        lockTag = id.toLockTag();
    }
}
