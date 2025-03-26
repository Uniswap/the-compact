// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { SignDelegatorLib } from "./SignDelegatorLib.sol";

/**
 * @title SignDelegatorLogic
 * @notice Logic that provides functionality for delegating signature verification
 * @dev This contract enables accounts to delegate signature verification to another address,
 *      which is particularly important for maintaining credible commitments in TheCompact ecosystem.
 *
 * When EOAs upgrade to smart accounts (as enabled by EIP-7702), their signature
 * verification method potentially changes from ECDSA to ERC1271. This creates a potential issue
 * where an EOA could use EIP-7702 to redelegate to a new account implementation and break previously
 * established credible commitments.
 *
 * SignDelegatorLogic introduces a delegation mechanism where signature verification can be
 * delegated to a static contract that verifies claim hashes on behalf of the sponsor.
 * This creates more reliable credible commitments by ensuring signature verification
 * remains consistent even if the account implementation changes.
 *
 * A timelock mechanism is implemented to prevent immediate changes to delegators,
 * providing additional security against malicious redelegation attempts,
 * that would break credible commitments made using the SignDelegator
 *
 */
abstract contract SignDelegatorLogic {
    /**
     * @notice Initiates the timelock process for changing a signature delegator
     * @dev This function starts the timelock period that must pass before
     *      a new signature delegator can be set. The timelock is specific to the caller (msg.sender).
     *      After calling this function, the caller must wait for the timelock period to expire
     *      before calling `setSignDelegator`.
     * @custom:emits SignDelegatorTimelockSet event through the library call
     */
    function requestSetSignDelegator() external {
        SignDelegatorLib.setSignDelegatorTimelock(msg.sender);
    }

    /**
     * @notice Sets a new signature delegator for the caller
     * @dev This function can only be called after the timelock period has passed.
     *      The timelock must be initiated by calling `requestSetSignDelegator` first.
     *      The delegator address can be set to the zero address to remove delegation.
     * @param delegator The address that will be authorized to sign on behalf of the caller.
     *                  Set to address(0) to remove the current delegator.
     * @custom:emits SignDelegatorSet event through the library call
     * @custom:throws If the timelock period has not passed or was not initiated
     */
    function setSignDelegator(address delegator) external {
        // TODO: should we use IERC165 here?
        SignDelegatorLib.setSignDelegatorTo(msg.sender, delegator);
    }
}
