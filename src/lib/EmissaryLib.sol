// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IdLib } from "./IdLib.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { EmissaryConfig, EmissaryStatus } from "../types/EmissaryStatus.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";

/**
 * @title EmissaryLib
 * @notice This library manages the assignment and verification of emissaries for sponsors
 * within the system. An emissary is an address that can verify claims on behalf of a sponsor.
 * The library enforces security constraints and scheduling rules to ensure proper delegation.
 *
 * @dev The library uses a storage-efficient design with a single storage slot for all emissary
 * configurations, using mappings to organize data by sponsor and allocator ID. This allows for
 * efficient storage and access while maintaining data isolation between different sponsors.
 *
 * Key Components:
 * - EmissarySlot: Storage structure that maps sponsors to their allocator ID configurations
 * - EmissaryConfig: Configuration data for each emissary assignment, including reset periods
 * - Assignment scheduling: Enforces cooldown periods between assignments to prevent abuse
 * - Verification: Delegates claim verification to the assigned emissary contract
 *
 * Security Features:
 * - Timelock mechanism for reassignment to prevent rapid succession of emissaries
 * - Clear state management with Disabled/Enabled/Scheduled statuses
 * - Storage cleanup when emissaries are removed
 */
library EmissaryLib {
    using IdLib for bytes12;
    using IdLib for uint256;
    using IdLib for ResetPeriod;
    using EfficiencyLib for bool;

    // Sentinel value of type(uint96).max representing an emissary without a scheduled assignment.
    uint96 private constant NOT_SCHEDULED = 0xffffffffffffffffffffffff;

    // Scope for storage slots containing emissary configurations.
    // bytes4(keccak256("_EMISSARY_SCOPE")).
    uint256 private constant _EMISSARY_SCOPE = 0x2d5c707e;

    // bytes4(keccak256("verifyClaim(address,bytes32,bytes32,bytes,bytes12)")).
    uint32 private constant _VERIFY_CLAIM_SELECTOR = 0xf699ba1c;

    // keccak256("EmissaryAssigned(address,bytes12,address)").
    uint256 private constant _EMISSARY_ASSIGNED_EVENT_SIGNATURE =
        0x92de0e90f030663724bafa9b7a9ba2643e3f4ced55f1cfee8b01e2682aeb45fd;

    // keccak256("EmissaryAssignmentScheduled(address,bytes12,uint256)").
    uint256 private constant _EMISSARY_ASSIGNMENT_SCHEDULED_EVENT_SIGNATURE =
        0x16c05a1aea0a2659b53f72fda6b47106e4aa07338b16993a01ece024df9d8cc4;

    /**
     * @notice Internal function to assign or remove an emissary for a specific sponsor and
     * lock tag. This ensures that the assignment process adheres to the scheduling rules
     * and prevents invalid or premature assignments. It also clears the configuration
     * when removing an emissary to keep storage clean and avoid stale data.
     * @param lockTag     The lockTag of the emissary.
     * @param newEmissary The address of the new emissary, or address(0) to remove.
     */
    function assignEmissary(bytes12 lockTag, address newEmissary) internal {
        EmissaryConfig storage config = _getEmissaryConfig(msg.sender, lockTag);
        uint256 assignableAt = config.assignableAt;
        address currentEmissary = config.emissary;

        // Ensure assignment has been properly scheduled if an emissary is currently set.
        // Note that assignment can occur immediately if no emissary is set. Emissaries that
        // do not have a scheduled assignment will have an assignableAt of type(uint96).max
        // which will prohibit assignment as the timestamp cannot exceed that value.
        assembly ("memory-safe") {
            if and(iszero(iszero(currentEmissary)), gt(assignableAt, timestamp())) {
                // Revert EmissaryAssignmentUnavailable(assignableAt);
                mstore(0, 0x174f0776)
                mstore(0x20, assignableAt)
                revert(0x1c, 0x24)
            }
        }

        // If new Emissary is address(0), that means that the sponsor wants to remove their emissary.
        // In that event, wipe all related storage.
        if (newEmissary == address(0)) {
            // If the new emissary is address(0), this means the emissary should be removed.
            // Clear all related storage fields to maintain a clean state and avoid stale data.
            delete config.emissary;
            delete config.assignableAt;
        }
        // Otherwise, set the provided newEmissary.
        else {
            config.emissary = newEmissary;
            config.assignableAt = NOT_SCHEDULED;
        }

        assembly ("memory-safe") {
            // Emit EmissaryAssigned(msg.sender, lockTag, newEmissary) event.
            log4(0, 0, _EMISSARY_ASSIGNED_EVENT_SIGNATURE, caller(), lockTag, newEmissary)
        }
    }

    /**
     * @notice Internal function to schedule a future assignment for an emissary.
     * The scheduling mechanism ensures that emissaries cannot be reassigned arbitrarily,
     * enforcing a reset period that must elapse before a new assignment is possible.
     * This prevents abuse of the system by requiring a cooldown period between assignments.
     * @param lockTag       The lock tag for the assignment.
     * @return assignableAt The timestamp when the assignment becomes available.
     */
    function scheduleEmissaryAssignment(bytes12 lockTag) internal returns (uint256 assignableAt) {
        // Get the current emissary config from storage.
        EmissaryConfig storage emissaryConfig = _getEmissaryConfig(msg.sender, lockTag);

        unchecked {
            // Extract three-bit resetPeriod from lockTag, convert to seconds, & add to current time.
            assignableAt = block.timestamp + lockTag.toResetPeriod().toSeconds();
        }

        // Write the resultant value to storage. Note that assignableAt is expected to remain in uint96
        // range, as block timestamps will not reach upper uint96 range in realistic timeframes and
        // ResetPeriod is capped at thirty days.
        emissaryConfig.assignableAt = uint96(assignableAt);

        assembly ("memory-safe") {
            // Emit EmissaryAssignmentScheduled(msg.sender, lockTag, assignableAt) event.
            mstore(0, assignableAt)
            log3(0, 0x20, _EMISSARY_ASSIGNMENT_SCHEDULED_EVENT_SIGNATURE, caller(), lockTag)
        }
    }

    /**
     * @notice Internal view function to verify a claim using the assigned emissary.
     * This function delegates the verification logic to the emissary contract,
     * ensuring that the verification process is modular and can be updated independently.
     * If no emissary is assigned, the verification fails, enforcing the requirement
     * for an active emissary to validate claims.
     * @param digest    The digest of the claim on the notarized chain.
     * @param claimHash The hash of the claim to verify.
     * @param sponsor   The address of the sponsor.
     * @param lockTag   The lock tag for the claim.
     * @param signature The signature to verify.
     */
    function verifyWithEmissary(
        bytes32 digest,
        bytes32 claimHash,
        address sponsor,
        bytes12 lockTag,
        bytes calldata signature
    ) internal view {
        // Retrieve the emissary for the sponsor and lock tag from storage.
        EmissaryConfig storage emissaryConfig = _getEmissaryConfig(sponsor, lockTag);

        // Delegate the verification process to the assigned emissary contract.
        _callVerifyClaim(emissaryConfig.emissary, sponsor, digest, claimHash, signature, lockTag);
    }

    /**
     * @notice Internal view function to retrieve the current status of an emissary for a given
     * sponsor and lock tag. The status provides insight into whether the emissary is active,
     * disabled, or scheduled for reassignment. This provides visibility into the state of the
     * emissary system without needing to interpret raw configuration data.
     * @param sponsor          The address of the sponsor.
     * @param lockTag          The lock tag for the emissary.
     * @return status          The current status of the emissary.
     * @return assignableAt    The timestamp when the emissary can be reassigned.
     * @return currentEmissary The address of the currently assigned emissary.
     */
    function getEmissaryStatus(address sponsor, bytes12 lockTag)
        internal
        view
        returns (EmissaryStatus status, uint256 assignableAt, address currentEmissary)
    {
        EmissaryConfig storage emissaryConfig = _getEmissaryConfig(sponsor, lockTag);
        assignableAt = emissaryConfig.assignableAt;
        currentEmissary = emissaryConfig.emissary;

        // Determine the emissary's status based on its current state:
        // - If there is no current emissary, the status is Disabled and assignableAt must be zero.
        // - If assignableAt is NOT_SCHEDULED, the emissary is Enabled and active.
        // - If assignableAt is set to a future timestamp, the emissary is Scheduled for reassignment.
        if (currentEmissary == address(0)) {
            status = EmissaryStatus.Disabled;
        } else if (assignableAt == NOT_SCHEDULED) {
            status = EmissaryStatus.Enabled;
        } else {
            status = EmissaryStatus.Scheduled;
        }
    }

    /**
     * @notice Internal pure function to extract and verify that all IDs in a given idsAndAmounts array have
     * the same lock tag.
     * @param idsAndAmounts Array of [id, amount] pairs.
     * @return lockTag      The common lock tag across all IDs.
     */
    function extractSameLockTag(uint256[2][] memory idsAndAmounts) internal pure returns (bytes12 lockTag) {
        // Store the first lockTag for the first id. Note that idsAndAmounts is known to be non-zero
        // length at this point, as it gets checked in _buildIdsAndAmountsWithConsistentAllocatorIdCheck in ComponentLib.
        lockTag = idsAndAmounts[0][0].toLockTag();

        // Initialize an error buffer.
        uint256 errorBuffer;

        // Retrieve the length of the array.
        uint256 idsAndAmountsLength = idsAndAmounts.length;

        // Iterate over remaining array elements.
        for (uint256 i = 1; i < idsAndAmountsLength; ++i) {
            // Set the error buffer if lockTag does not match initial lockTag.
            errorBuffer |= (idsAndAmounts[i][0].toLockTag() != lockTag).asUint256();
        }

        // Ensure that no lockTag values differ.
        assembly ("memory-safe") {
            if errorBuffer {
                // Revert InvalidLockTag();
                mstore(0, 0xbbfc3c51)
                revert(0x1c, 0x04)
            }
        }
    }

    /**
     * @notice Private view function to perform a low-level verifyClaim staticcall to an
     * emissary, ensuring that the expected magic value (verifyClaim function selector) is
     * returned. Reverts if the magic value is not returned successfully.
     * @param emissary  The emissary to perform the call to.
     * @param sponsor   The address of the sponsor.
     * @param digest    The digest of the claim to verify.
     * @param claimHash The hash of the claim to verify.
     * @param signature The signature to verify.
     * @param lockTag   The lock tag for the claim.
     */
    function _callVerifyClaim(
        address emissary,
        address sponsor,
        bytes32 digest,
        bytes32 claimHash,
        bytes calldata signature,
        bytes12 lockTag
    ) private view {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Derive offset to start of data for the call from memory pointer.
            let dataStart := add(m, 0x1c)

            // Prepare fixed-location components of calldata.
            mstore(add(m, 0x20), sponsor)
            mstore(add(m, 0x0c), 0) // Clear any dirty upper bits on sponsor.
            mstore(m, _VERIFY_CLAIM_SELECTOR)
            mstore(add(m, 0x40), digest)
            mstore(add(m, 0x60), claimHash)
            mstore(add(m, 0x80), 0xa0)
            mstore(add(m, 0xa0), lockTag)
            mstore(add(m, 0xac), 0) // clear any dirty lower bits on lock tag.
            mstore(add(m, 0xc0), signature.length)
            calldatacopy(add(m, 0xe0), signature.offset, signature.length)

            // Ensure initial scratch space is cleared as an added precaution.
            mstore(0, 0)

            // Perform a staticcall to emissary and write response to scratch space.
            let success := staticcall(gas(), emissary, dataStart, add(0xc4, signature.length), 0, 0x20)

            // Revert if the required magic value was not received back.
            if iszero(eq(mload(0), shl(0xe0, _VERIFY_CLAIM_SELECTOR))) {
                // Bubble up if the call failed and there's data. Note that remaining gas is not evaluated before
                // copying the returndata buffer into memory. Out-of-gas errors can be triggered via revert bombing.
                if iszero(or(success, iszero(returndatasize()))) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }

                // revert InvalidSignature();
                mstore(0, 0x8baa579f)
                revert(0x1c, 0x04)
            }
        }
    }

    /**
     * @notice Private pure function to retrieve the configuration for a given emissary.
     * This ensures that emissary-specific settings (like reset period and assignment time)
     * are stored and retrieved in a consistent and isolated manner to prevent conflicts.
     * The function uses a combination of sponsor address, lockTag, and a scope constant
     * to compute a unique storage slot for the configuration.
     * @param sponsor The address of the sponsor that the emissary is associated with.
     * @param lockTag The lock tag to which the emissary assignment is associated.
     * @return config The configuration for the emissary in storage.
     */
    function _getEmissaryConfig(address sponsor, bytes12 lockTag)
        private
        pure
        returns (EmissaryConfig storage config)
    {
        // Pack and hash scope, sponsor, and lock tag to derive emissary config storage slot.
        assembly ("memory-safe") {
            // Start by writing the sponsor address to scratch space so that the 20 bytes of
            // address data are placed at memory location 0x20. The first 12 bytes of the
            // variable for the sponsor are unused and overwritten by the subsequent write.
            mstore(0x14, sponsor)

            // Next, write the emissary scope value to scratch space so that the 4 bytes of
            // scope data are placed at the memory location 0x1c. The first 28 bytes of the
            // variable for the emissary scope are unused and will be omitted from the slot
            // derivation; a right-aligned value is preferred over a left-aligned one like
            // bytes4 to reduce code size requirements without needing bitshift operations.
            mstore(0, _EMISSARY_SCOPE)

            // Then, write the lock tag value to scratch space so that the 12 bytes of
            // lock tag data are placed at memory location 0x34. This data is left-aligned
            // and so it can be placed directly at the intended memory location, and the
            // final 20 bytes will not be included in the slot derivation. Note that these
            // unused least-significant bits will overflow into the free memory pointer and
            // will need to be cleared in a subsequent step if there are any dirty lower bits
            // on the lockTag value. Since a valid free memory pointer can never grow to a
            // value that would require the 20 most-significant bytes in the pointer (as this
            // would certainly exhaust memory long before they were needed), these bytes can
            // safely be used as long as they are cleared before accessing the pointer again.
            mstore(0x34, lockTag)

            // Compute storage slot from packed data.
            // Start at offset 0x1c (28 bytes) and hash 0x24 (36 bytes) of data in total:
            // - _EMISSARY_SCOPE (4 bytes from at 0x1c to 0x20)
            // - Sponsor address (20 bytes from 0x20 to 0x34)
            // - Lock tag (12 bytes from 0x34 to 0x40)
            config.slot := keccak256(0x1c, 0x24)

            // Finally, wipe the leftmost 20 bytes of the free memory pointer that may have
            // been set when writing the lock tag (assuming dirty lower bits were present).
            mstore(0x34, 0)
        }
    }
}
