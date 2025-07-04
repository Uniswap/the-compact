// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IAllocator } from "../interfaces/IAllocator.sol";
import { IERC1271 } from "permit2/src/interfaces/IERC1271.sol";
import { TheCompact } from "../TheCompact.sol";

/**
 * @title ReentrantAllocator
 * @notice A test allocator that attempts to make a reentrant call to TheCompact
 * by checking the reentrancy guard slot during the attest function.
 */
contract ReentrantAllocator is IAllocator, IERC1271 {
    // Storage slot used for the reentrancy guard in TheCompact
    uint256 private constant _REENTRANCY_GUARD_SLOT = 0x929eee149b4bd21268;

    // Address of TheCompact contract
    TheCompact public theCompact;

    // Flag to track if a reentrant call was detected
    bool public reentrantCallDetected;

    // Value read from the reentrancy guard slot
    bytes32 public reentrancyGuardValue;

    /**
     * @notice Constructor to initialize the allocator with TheCompact address
     * @param _theCompact Address of TheCompact contract
     */
    constructor(address _theCompact) {
        theCompact = TheCompact(_theCompact);
    }

    /**
     * @notice Called on standard transfers to validate the transfer.
     */
    function attest(address, address, address, uint256, uint256) external pure returns (bytes4) {
        return IAllocator.attest.selector;
    }

    /**
     * @notice Authorize a claim. Called from The Compact as part of claim processing.
     * During this call, it attempts to read the reentrancy guard slot
     * to check if it contains the caller's address, which would indicate
     * that the reentrancy guard is active.
     */
    function authorizeClaim(bytes32, address arbiter, address, uint256, uint256, uint256[2][] calldata, bytes calldata)
        external
        returns (bytes4)
    {
        // Try to read the reentrancy guard slot using exttload (transient storage)
        try theCompact.exttload(bytes32(_REENTRANCY_GUARD_SLOT)) returns (bytes32 value) {
            reentrancyGuardValue = value;

            // Check if the reentrancy guard is set to the arbiter
            if (address(uint160(uint256(value))) == arbiter) {
                reentrantCallDetected = true;
            }
        } catch {
            // If exttload fails (e.g., transient storage not supported), try extsload
            reentrancyGuardValue = theCompact.extsload(bytes32(_REENTRANCY_GUARD_SLOT));

            // Check if the reentrancy guard is set to the arbiter
            if (address(uint160(uint256(reentrancyGuardValue))) == arbiter) {
                reentrantCallDetected = true;
            }
        }

        return IAllocator.authorizeClaim.selector;
    }

    /**
     * @notice Check if given allocatorData authorizes a claim.
     */
    function isClaimAuthorized(bytes32, address, address, uint256, uint256, uint256[2][] calldata, bytes calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }

    /**
     * @notice ERC1271 implementation for signature validation
     */
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return IERC1271.isValidSignature.selector;
    }
}
