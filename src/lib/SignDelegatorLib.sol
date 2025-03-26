// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ISignDelegator } from "../interfaces/ISignDelegator.sol";

/**
 * @title SignDelegatorLib
 * @dev Library for managing signature delegation functionality.
 * Allows accounts to delegate signature verification to external contracts.
 * Uses a custom storage pattern to efficiently store delegator addresses and timelocks.
 */
library SignDelegatorLib {
    //keccak("signdelegator.slot")
    uint256 private constant _DELEGATOR_MASTER_SLOT_SEED = 0xbe041d4237e1dfa7eb;

    // Event signature for logging delegator changes
    event SignDelegatorSet(address indexed sponsor, address indexed operator);
    event SignDelegatorRequested(address indexed sponsor, uint48 validAfter);

    error SignDelegatorTimelockViolation(address sponsor);

    uint256 private constant TIMELOCK_DELAY = 1 days;

    /**
     * @dev Verifies a signature using the sponsor's delegated operator.
     * @param sponsor The address that has delegated signature verification.
     * @param claimHash The hash of the claim being verified.
     * @param signature The signature to verify.
     * @return success True if the signature is valid, false otherwise.
     * @notice If no delegator is set for the sponsor, returns false.
     * @notice Calls the delegator contract's verifyClaim function and checks for the correct return value.
     */
    function verifyByDelegator(address sponsor, bytes32 claimHash, bytes calldata signature) internal returns (bool) {
        address delegator = getSignDelegator(sponsor);
        // should no delegator be set, we can return false
        if (delegator == address(0)) return false;
        // TODO: possible gas griefing here
        return ISignDelegator(delegator).verifyClaim(sponsor, claimHash, signature) == ISignDelegator.verifyClaim.selector;
    }

    /**
     * @dev Sets a new signature delegator for a sponsor.
     * @param sponsor The address that is delegating signature verification.
     * @param operator The address of the delegator contract that will verify signatures.
     * @notice This function can only be called if there is no active timelock or if the timelock has passed.
     * @notice Emits a SignDelegatorSet event upon successful delegation.
     * @notice Reverts with "SignatureDelegatorTimelock()" if a timelock is active.
     */
    function setSignDelegatorTo(address sponsor, address operator) internal {
        bytes32 slot = _computeDelegatorSlot(sponsor);
        uint256 currentValue;
        uint48 currentTimelock;

        assembly ("memory-safe") {
            // Load current value
            currentValue := sload(slot)

            // Extract current timelock (upper 12 bytes)
            currentTimelock := shr(0xA0, currentValue)
        }

        // Check if timelock has passed or is zero (not set)
        if (currentTimelock == 0 || currentTimelock < uint48(block.timestamp)) {
            // Update storage with new operator while preserving timelock
            assembly ("memory-safe") {
                // Combine new operator with existing timelock
                let newValue :=
                    or(
                        shl(0xA0, currentTimelock), // Preserve timestamp
                        and(operator, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) // Ensure only address bits
                    )

                // Store new value
                sstore(slot, newValue)
            }

            emit SignDelegatorSet(sponsor, operator);
        } else {
            revert SignDelegatorTimelockViolation(sponsor);
        }
    }

    /**
     * @dev Sets a timelock for changing the signature delegator.
     * @param sponsor The address that is setting a timelock for delegation changes.
     * @notice The timelock is stored in the upper 12 bytes of the same storage slot as the delegator address.
     * @notice Emits a SignDelegatorRequested event upon setting the timelock.
     */
    function setSignDelegatorTimelock(address sponsor) internal {
        uint48 newTimelock;
        assembly ("memory-safe") {
            // Compute the storage slot
            mstore(0x00, _DELEGATOR_MASTER_SLOT_SEED)
            mstore(0x20, sponsor)
            let slot := keccak256(0x00, 0x40)

            // Load current value
            let currentValue := sload(slot)

            // Extract current operator (lower 20 bytes)
            let currentOperator := and(currentValue, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

            // Combine new timelock with existing operator
            newTimelock := add(timestamp(), TIMELOCK_DELAY)
            let newValue := or(shl(0xA0, newTimelock), currentOperator)

            // Store new value
            sstore(slot, newValue)
        }

        emit SignDelegatorRequested(msg.sender, newTimelock);
    }

    /**
     * @dev Helper function to compute the storage slot for a sponsor's delegator information.
     * @param sponsor The address for which to compute the storage slot.
     * @return slot The computed storage slot.
     * @notice Uses a fixed seed combined with the sponsor address to generate a unique storage slot.
     * @notice The slot stores both the delegator address (lower 20 bytes) and timelock (upper 12 bytes).
     */
    function _computeDelegatorSlot(address sponsor) private pure returns (bytes32 slot) {
        assembly ("memory-safe") {
            mstore(0x00, _DELEGATOR_MASTER_SLOT_SEED)
            mstore(0x20, sponsor)
            slot := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Retrieves the current signature delegator for a sponsor.
     * @param sponsor The address whose delegator is being queried.
     * @return operator The address of the delegator contract, or address(0) if none is set.
     * @notice Extracts the lower 20 bytes from the storage slot to get the delegator address.
     */
    function getSignDelegator(address sponsor) internal view returns (address operator) {
        bytes32 slot = _computeDelegatorSlot(sponsor);
        assembly ("memory-safe") {
            // Load current value and return operator (lower 20 bytes)
            operator := and(sload(slot), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        }
    }

    /**
     * @dev Retrieves the current timelock for a sponsor's delegator changes.
     * @param sponsor The address whose timelock is being queried.
     * @return timelock The timestamp after which the delegator can be changed.
     * @notice Extracts the upper 12 bytes from the storage slot to get the timelock value.
     * @notice A timelock of 0 means no timelock is active.
     */
    function getSignDelegatorTimelock(address sponsor) internal view returns (uint48 timelock) {
        bytes32 slot = _computeDelegatorSlot(sponsor);
        assembly ("memory-safe") {
            // Load current value and return timelock (upper 12 bytes)
            timelock := shr(0xA0, sload(slot))
        }
    }
}
