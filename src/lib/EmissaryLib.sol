// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IdLib } from "./IdLib.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";
import { EmissaryConfig, EmissaryStatus } from "../types/EmissaryStatus.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { IEmissary } from "../interfaces/IEmissary.sol";

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
    using IdLib for address;
    using IdLib for uint256;
    using IdLib for ResetPeriod;
    using IdLib for uint96;
    using EfficiencyLib for bytes12;
    using EfficiencyLib for bool;
    using EfficiencyLib for uint256;

    error EmissaryAssignmentUnavailable(uint256 assignAt);
    error InvalidLockTag();
    error InvalidEmissaryStatus();

    event EmissaryAssigned(address indexed sponsor, bytes12 indexed lockTag, address indexed emissary);
    event EmissaryAssignmentScheduled(address indexed sponsor, bytes12 indexed lockTag, uint256 indexed assignableAt);

    uint96 constant NOT_SCHEDULED = type(uint96).max;

    // Storage slot for emissary configurations
    // Maps: keccak256(_EMISSARY_SCOPE) => EmissarySlot
    uint256 private constant _EMISSARY_SCOPE = 0x2d5c707;

    // bytes4(keccak256("verifyClaim(address,bytes32,bytes,bytes12)")).
    uint32 private constant _VERIFY_CLAIM_SELECTOR = 0xcd4d6588;

    /**
     * @dev Retrieves the configuration for a given emissary.
     * This ensures that emissary-specific settings (like reset period and assignment time)
     * are stored and retrieved in a consistent and isolated manner to prevent conflicts.
     * The function uses a combination of sponsor address, lockTag, and a scope constant
     * to compute a unique storage slot for the configuration.
     */
    function _getEmissaryConfig(address sponsor, bytes12 lockTag)
        private
        pure
        returns (EmissaryConfig storage config)
    {
        assembly ("memory-safe") {
            // Pack data for computing storage slot.
            mstore(0x14, sponsor) // Offset 0x14 (20 bytes): Store 20-byte sponsor address
            mstore(0, _EMISSARY_SCOPE) // Offset 0 (0 bytes): Store 4-byte scope value
            mstore(0x20, lockTag) // Offset 0x20 (12 bytes): Store 12-byte lock tag

            // Compute storage slot from packed data.
            // Start at offset 0x1c (28 bytes), which includes:
            // - The 4 bytes of _EMISSARY_SCOPE (which is stored at position 0x00)
            // - The entire 20-byte sponsor address (which starts at position 0x14)
            // - The entire 12-byte lock tag (which starts at position 0x34)
            // Hash 0x24 (36 bytes) of data in total
            config.slot := keccak256(0x1c, 0x24)
        }
    }

    /**
     * @dev Assigns or removes an emissary for a specific sponsor and allocator ID.
     * The function ensures that the assignment process adheres to the scheduling rules
     * and prevents invalid or premature assignments. It also clears the configuration
     * when removing an emissary to keep storage clean and avoid stale data.
     * @param lockTag The lockTag of the emissary
     * @param newEmissary The address of the new emissary (use address(0) to remove)
     */
    function assignEmissary(bytes12 lockTag, address newEmissary) internal {
        EmissaryConfig storage config = _getEmissaryConfig(msg.sender, lockTag);
        uint256 _assignableAt = config.assignableAt;
        address _emissary = config.emissary;

        // Ensures that the assignment has been scheduled properly.
        // Without this check, an emissary could be assigned without proper scheduling,
        // leading to uncontrolled state transitions.
        require(_assignableAt != NOT_SCHEDULED, EmissaryAssignmentUnavailable(NOT_SCHEDULED));

        // The second check ensures that either there is no current emissary,
        // or the reset period has elapsed before allowing a new assignment.
        // This enforces the cooldown period between assignments to prevent abuse.
        require(
            _emissary == address(0) || config.assignableAt <= block.timestamp,
            EmissaryAssignmentUnavailable(config.assignableAt)
        );

        // If new Emissary is address(0), that means that the sponsor wants to remove the emissary feature.
        // In that event, wipe all storage.
        if (newEmissary == address(0)) {
            // If the new emissary is address(0), this means the emissary should be removed.
            // Clear all related storage fields to maintain a clean state and avoid stale data.
            delete config.emissary;
            delete config.assignableAt;
        }
        // Otherwise, set the provided resetPeriod.
        else {
            config.emissary = newEmissary;
            config.assignableAt = NOT_SCHEDULED;
        }

        emit EmissaryAssigned(msg.sender, lockTag, newEmissary);
    }

    /**
     * @dev Schedules a future assignment for an emissary.
     * The scheduling mechanism ensures that emissaries cannot be reassigned arbitrarily,
     * enforcing a reset period that must elapse before a new assignment is possible.
     * This prevents abuse of the system by requiring a cooldown period between assignments.
     * @param lockTag The lock tag for the assignment
     * @return assignableAt The timestamp when the assignment becomes available
     */
    function scheduleEmissaryAssignment(bytes12 lockTag) internal returns (uint256 assignableAt) {
        // Get the current emissary config from storage.
        EmissaryConfig storage emissaryConfig = _getEmissaryConfig(msg.sender, lockTag);

        unchecked {
            // Extract five bit resetPeriod from lockTag, convert to seconds, & add to current time.
            assignableAt = block.timestamp + lockTag.toResetPeriod().toSeconds();

            // Ensure that assignableAt is in the future and is not greater than type(uint96.max).
            if ((assignableAt < block.timestamp).or(assignableAt > type(uint96).max)) {
                revert InvalidLockTag();
            }
        }

        // Write the resultant value to storage.
        emissaryConfig.assignableAt = uint96(assignableAt);

        // Emit an EmissaryAssignmentScheduled event.
        emit EmissaryAssignmentScheduled(msg.sender, lockTag, assignableAt);
    }

    /**
     * @dev Extracts and verifies that all IDs in the array have the same lock tag.
     * @param idsAndAmounts Array of [id, amount] pairs
     * @return lockTag The common lock tag across all IDs
     */
    function extractSameLockTag(uint256[2][] memory idsAndAmounts) internal pure returns (bytes12 lockTag) {
        // Retrieve the length of the array.
        uint256 idsAndAmountsLength = idsAndAmounts.length;

        // Ensure length is at least 1.
        if (idsAndAmountsLength == 0) {
            revert InvalidLockTag();
        }

        // Store the first lockTag for the first id.
        lockTag = idsAndAmounts[0][0].toLockTag();

        // Initialize an error buffer.
        uint256 errorBuffer;

        // Iterate over remaining array elements.
        unchecked {
            for (uint256 i = 1; i < idsAndAmountsLength; ++i) {
                // Set the error buffer if lockTag does not match initial lockTag.
                errorBuffer |= (idsAndAmounts[i][0].toLockTag() != lockTag).asUint256();
            }
        }

        // Ensure that no lockTag values differ.
        if (errorBuffer.asBool()) {
            revert InvalidLockTag();
        }
    }

    /**
     * @dev Verifies a claim using the assigned emissary.
     * This function delegates the verification logic to the emissary contract,
     * ensuring that the verification process is modular and can be updated independently.
     * If no emissary is assigned, the verification fails, enforcing the requirement
     * for an active emissary to validate claims.
     * @param claimHash The hash of the claim to verify.
     * @param sponsor   The address of the sponsor.
     * @param lockTag   The lock tag for the claim.
     * @param signature The signature to verify.
     */
    function verifyWithEmissary(bytes32 claimHash, address sponsor, bytes12 lockTag, bytes calldata signature)
        internal
        view
    {
        // Retrieve the emissary for the sponsor and lock tag from storage.
        EmissaryConfig storage emissaryConfig = _getEmissaryConfig(sponsor, lockTag);

        // Delegate the verification process to the assigned emissary contract.
        _callVerifyClaim(emissaryConfig.emissary, sponsor, claimHash, signature, lockTag);
    }

    /**
     * @dev Perform a low-level verifyClaim staticcall to an emissary, ensuring that
     * the expected magic value (verifyClaim function selector) is returned. Reverts
     * if the magic value is not returned successfully.
     * @param emissary  The emissary to perform the call to.
     * @param sponsor   The address of the sponsor.
     * @param claimHash The hash of the claim to verify.
     * @param signature The signature to verify.
     * @param lockTag   The lock tag for the claim.
     */
    function _callVerifyClaim(
        address emissary,
        address sponsor,
        bytes32 claimHash,
        bytes calldata signature,
        bytes12 lockTag
    ) private view {
        assembly ("memory-safe") {
            // Sanitize sponsor and lock tag.
            sponsor := shr(0x60, shl(0x60, sponsor))
            lockTag := shl(0xa0, shr(0xa0, lockTag))

            // Retrieve the free memory pointer; memory will be left dirtieed.
            let m := mload(0x40)

            // Derive offset to start of data for the call from memory pointer.
            let dataStart := add(m, 0x1c)

            // Prepare fixed-location components of calldata.
            mstore(m, _VERIFY_CLAIM_SELECTOR)
            mstore(add(m, 0x20), sponsor)
            mstore(add(m, 0x40), claimHash)
            mstore(add(m, 0x60), 0x80)
            mstore(add(m, 0x80), lockTag)
            mstore(add(m, 0xa0), signature.length)
            calldatacopy(add(m, 0xc0), signature.offset, signature.length)

            // Ensure sure initial scratch space is cleared as an added precaution.
            mstore(0, 0)

            // Perform a staticcall to emissary and write response to scratch space.
            let success := staticcall(gas(), emissary, dataStart, add(0xa4, signature.length), 0, 0x20)

            // Revert if the required magic value was not received back.
            if iszero(eq(mload(0), shl(224, _VERIFY_CLAIM_SELECTOR))) {
                // Bubble up revert if the call failed and there's data.
                // NOTE: consider evaluating remaining gas to protect against revert bombing.
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
     * @dev Retrieves the current status of an emissary for a given sponsor and lock tag.
     * The status provides insight into whether the emissary is active, disabled, or scheduled for reassignment.
     * This helps external contracts and users understand the state of the emissary system
     * without needing to interpret raw configuration data.
     * @param sponsor The address of the sponsor
     * @param lockTag The lock tag for the emissary
     * @return status The current status of the emissary
     * @return assignableAt The timestamp when the emissary can be reassigned
     * @return currentEmissary The address of the currently assigned emissary
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
        // - If there is no current emissary, the status is Disabled.
        // - If assignableAt is NOT_SCHEDULED, the emissary is Enabled and active.
        // - If assignableAt is set to a future timestamp, the emissary is Scheduled for reassignment.
        if (currentEmissary == address(0)) {
            status = EmissaryStatus.Disabled;
        } else if (assignableAt == NOT_SCHEDULED) {
            status = EmissaryStatus.Enabled;
        } else if (assignableAt != 0) {
            status = EmissaryStatus.Scheduled;
        } else {
            revert InvalidEmissaryStatus();
        }
    }
}
