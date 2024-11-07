// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Lock } from "../types/Lock.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";

import { DomainLib } from "./DomainLib.sol";
import { IdLib } from "./IdLib.sol";
import { MetadataRenderer } from "./MetadataRenderer.sol";

import { Tstorish } from "tstorish/Tstorish.sol";

/**
 * @title ConstructorLogic
 * @notice Inherited contract implementing internal functions with logic for initializing
 * immutable variables and deploying the metadata renderer contract, as well as for setting
 * and clearing resource locks, retrieving metadata from the metadata renderer, and safely
 * interacting with Permit2. Note that TSTORE will be used for the reentrancy lock on chains
 * that support it, with a fallback to SSTORE where it is not supported along with a utility
 * for activating TSTORE support if the chain eventually adds support for it.
 */
contract ConstructorLogic is Tstorish {
    using DomainLib for bytes32;
    using DomainLib for uint256;
    using IdLib for uint256;

    // Address of the Permit2 contract, optionally used for depositing ERC20 tokens.
    address private constant _PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    // Storage slot used for the reentrancy guard, whether using TSTORE or SSTORE.
    uint256 private constant _REENTRANCY_GUARD_SLOT = 0x929eee149b4bd21268;

    // Chain ID at deployment, used for triggering EIP-712 domain separator updates.
    uint256 private immutable _INITIAL_CHAIN_ID;

    // Initial EIP-712 domain separator, computed at deployment time.
    bytes32 private immutable _INITIAL_DOMAIN_SEPARATOR;

    // Instance of the metadata renderer contract deployed during construction.
    MetadataRenderer private immutable _METADATA_RENDERER;

    // Whether Permit2 was deployed on the chain at construction time.
    bool private immutable _PERMIT2_INITIALLY_DEPLOYED;

    /**
     * @notice Constructor that initializes immutable variables and deploys the metadata
     * renderer. Captures the initial chain ID and domain separator, deploys the metadata
     * renderer, and checks for Permit2 deployment.
     */
    constructor() {
        _INITIAL_CHAIN_ID = block.chainid;
        _INITIAL_DOMAIN_SEPARATOR = block.chainid.toNotarizedDomainSeparator();
        _METADATA_RENDERER = new MetadataRenderer();
        _PERMIT2_INITIALLY_DEPLOYED = _checkPermit2Deployment();
    }

    /**
     * @notice Internal function to set the reentrancy guard using either TSTORE or SSTORE.
     * Called as part of functions that require reentrancy protection. Reverts if called
     * again before the reentrancy guard has been cleared.
     * @dev Note that the caller is set to the value; this enables external contracts to
     * ascertain the account originating the ongoing call while handling the call as long
     * as exttload is available.
     */
    function _setReentrancyGuard() internal {
        uint256 entered = _getTstorish(_REENTRANCY_GUARD_SLOT);

        assembly ("memory-safe") {
            if entered {
                // revert ReentrantCall(address existingCaller)
                mstore(0, 0xf57c448b)
                mstore(0x20, entered)
                revert(0x1c, 0x24)
            }

            entered := caller()
        }

        _setTstorish(_REENTRANCY_GUARD_SLOT, entered);
    }

    /**
     * @notice Internal function to clear the reentrancy guard using either TSTORE or SSTORE.
     * Called as part of functions that require reentrancy protection.
     */
    function _clearReentrancyGuard() internal {
        _clearTstorish(_REENTRANCY_GUARD_SLOT);
    }

    /**
     * @notice Internal view function that checks whether Permit2 is deployed. Returns true
     * if Permit2 was deployed at construction time, otherwise checks current deployment status.
     * @return Whether Permit2 is currently deployed.
     */
    function _isPermit2Deployed() internal view returns (bool) {
        if (_PERMIT2_INITIALLY_DEPLOYED) {
            return true;
        }

        return _checkPermit2Deployment();
    }

    /**
     * @notice Internal view function that returns the current EIP-712 domain separator,
     * updating it if the chain ID has changed since deployment.
     * @return The current domain separator.
     */
    function _domainSeparator() internal view returns (bytes32) {
        return _INITIAL_DOMAIN_SEPARATOR.toLatest(_INITIAL_CHAIN_ID);
    }

    /**
     * @notice Internal view function for retrieving the name for a given token ID.
     * @param id The ERC6909 token identifier.
     * @return The token's name.
     */
    function _name(uint256 id) internal view returns (string memory) {
        return _METADATA_RENDERER.name(id);
    }

    /**
     * @notice Internal view function for retrieving the symbol for a given token ID.
     * @param id The ERC6909 token identifier.
     * @return The token's symbol.
     */
    function _symbol(uint256 id) internal view returns (string memory) {
        return _METADATA_RENDERER.symbol(id);
    }

    /**
     * @notice Internal view function for retrieving the URI for a given token ID.
     * @param id The ERC6909 token identifier.
     * @return The token's URI.
     */
    function _tokenURI(uint256 id) internal view returns (string memory) {
        return _METADATA_RENDERER.uri(id.toLock(), id);
    }

    /**
     * @notice Private view function that checks whether Permit2 is currently deployed by
     * checking for code at the Permit2 address.
     * @return permit2Deployed Whether there is code at the Permit2 address.
     */
    function _checkPermit2Deployment() private view returns (bool permit2Deployed) {
        assembly ("memory-safe") {
            permit2Deployed := iszero(iszero(extcodesize(_PERMIT2)))
        }
    }
}
