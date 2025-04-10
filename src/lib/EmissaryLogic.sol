// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { EmissaryLib } from "./EmissaryLib.sol";
import { IdLib } from "./IdLib.sol";
import { IAllocator } from "../interfaces/IAllocator.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";
import { EmissaryStatus } from "../types/EmissaryStatus.sol";

/**
 * @title EmissaryLogic
 * @notice Logic that provides functionality for delegating signature verification
 * @dev This contract enables accounts to delegate signature verification to another address,
 *      which is particularly important for maintaining credible commitments in TheCompact ecosystem.
 *
 * When EOAs upgrade to smart accounts (as enabled by EIP-7702), their signature
 * verification method potentially changes from ECDSA to ERC1271. This creates a potential issue
 * where an EOA could use EIP-7702 to redelegate to a new account implementation and break previously
 * established credible commitments.
 *
 * EmissaryLogic introduces a delegation mechanism where signature verification can be
 * delegated to an external contract that verifies claim hashes on behalf of the sponsor.
 * This creates more reliable credible commitments by ensuring signature verification
 * remains consistent even if the account implementation changes.
 *
 * A timelock mechanism is implemented to prevent immediate changes to emissaries,
 * providing additional security against malicious redelegation attempts.
 * The contract provides functions to schedule and assign emissaries, as well as
 * get the current status of an emissary assignment.
 */
abstract contract EmissaryLogic {
    using IdLib for address;
    using IdLib for uint96;
    using IdLib for bytes12;
    using EmissaryLib for bytes12;
    using EmissaryLib for address;

    error InvalidEmissaryAssignment();

    /**
     * @notice Initiates the timelock process for changing an emissary
     * @param lockTag The lock tag to schedule emissary assignment for.
     * @return emissaryAssignmentAvailableAt The time at which assigment can be performed.
     * @dev This function starts the timelock period that must pass before
     *      a new emissary can be set. The timelock is specific to the caller (msg.sender).
     *      After calling this function, the caller must wait for the timelock period to expire
     *      before calling `assignEmissary`.
     *
     *      The timelock mechanism ensures that changes to emissaries are not immediate,
     *      providing a security buffer to prevent malicious or accidental redelegation attempts.
     *      This period allows time for any necessary reviews or interventions.
     *
     *      The function utilizes `toAllocatorIdIfRegistered` to validate and convert the allocator
     *      address to its corresponding ID, ensuring that only registered allocators can proceed.
     *
     * @custom:emits EmissaryTimelockSet event through the library call, signaling the start of the timelock period.
     */
    function _scheduleEmissaryAssignment(bytes12 lockTag) internal returns (uint256 emissaryAssignmentAvailableAt) {
        lockTag.hasRegisteredAllocatorId();
        emissaryAssignmentAvailableAt = lockTag.scheduleEmissaryAssignment();
    }

    /**
     * @notice Sets a new emissary for the sponsor
     * @dev This function can only be called after the timelock period has passed.
     *      The timelock must be initiated by calling `scheduleEmissaryAssignment` first.
     *      The emissary address can be set to the zero address to remove delegation,
     *      effectively disabling the current emissary.
     *
     *      The emissary address must not be the address of the allocator to prevent
     *      conflicts of interest and maintain the integrity of the delegation mechanism.
     *
     *      The function utilizes `toAllocatorIdIfRegistered` to validate and convert the allocator
     *      address to its corresponding ID, ensuring that only registered allocators can proceed.
     *
     *      The `ResetPeriod` parameter specifies the reset behavior for the emissary assignment,
     *      adding flexibility to the delegation process.
     *
     * @param emissary The address that will be authorized to sign on behalf of the sponsor.
     *                  Set to address(0) to remove the current emissary.
     * @custom:emits EmissarySet event through the library call, signaling the successful assignment of a new emissary
     * @custom:throws If the timelock period has not passed or was not initiated, ensuring secure delegation practices
     */
    function _assignEmissary(bytes12 lockTag, address emissary) internal returns (bool) {
        // Extract allocatorId from locktag and ensure that the allocator is registered.
        address allocator = lockTag.toAllocatorId().toRegisteredAllocator();

        // Ensure allocator is not the emissary, which would grant them unilateral control.
        require(allocator != emissary, InvalidEmissaryAssignment());

        // Assign the emissary of the lock tag for the caller.
        lockTag.assignEmissary(emissary);

        return true;
    }

    /**
     * @notice Retrieves the current status of an emissary assignment for a given sponsor and allocator
     * @dev This function queries the emissary status, which can be one of the following:
     *      - `Disabled`: No emissary is currently assigned.
     *      - `Enabled`: An emissary is currently active and can sign on behalf of the sponsor.
     *      - `Scheduled`: An emissary assignment is pending and will become active after the timelock period.
     *
     *      The function also returns the timestamp when the emissary assignment will be available,
     *      and the address of the current emissary if one is assigned.
     *
     *      The `usingAllocatorId` function is used to retrieve the allocator's ID, ensuring consistent
     *      and accurate status retrieval.
     *
     * @param sponsor The address of the sponsor who has delegated signature verification.
     * @param lockTag The lock tag associated with the emissary assignment.
     * @return status The current status of the emissary assignment (Disabled, Enabled, or Scheduled).
     * @return assignableAt The timestamp when the emissary assignment will be available (if scheduled).
     * @return currentEmissary The address of the currently assigned emissary, if any.
     */
    function _getEmissaryStatus(address sponsor, bytes12 lockTag)
        internal
        view
        returns (EmissaryStatus status, uint256 assignableAt, address currentEmissary)
    {
        lockTag.hasRegisteredAllocatorId();

        return sponsor.getEmissaryStatus(lockTag);
    }
}
