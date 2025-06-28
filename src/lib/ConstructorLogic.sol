// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { DomainLib } from "./DomainLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { MetadataRenderer } from "./MetadataRenderer.sol";
import { _NATIVE_TOKEN_BENCHMARK_SCOPE, _ERC20_TOKEN_BENCHMARK_SCOPE } from "./TransferBenchmarkLib.sol";
import { TransferBenchmarker } from "./TransferBenchmarker.sol";

import { Tstorish } from "./Tstorish.sol";

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
    using EfficiencyLib for uint256;

    // Address of the Permit2 contract, optionally used for depositing ERC20 tokens.
    address private constant _PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    // Storage slot used for the reentrancy guard, whether using TSTORE or SSTORE.
    uint256 private constant _REENTRANCY_GUARD_SLOT = 0x929eee149b4bd21268;

    // Chain ID at deployment, used for triggering EIP-712 domain separator updates.
    uint256 private immutable _INITIAL_CHAIN_ID;

    // Initial EIP-712 domain separator, computed at deployment time.
    bytes32 private immutable _INITIAL_DOMAIN_SEPARATOR;

    // Whether Permit2 was deployed on the chain at construction time.
    bool private immutable _PERMIT2_INITIALLY_DEPLOYED;

    // Declare uint256 representations of various metadata-related function selectors.
    uint256 private constant _NAME_SELECTOR = 0xad800c;
    uint256 private constant _SYMBOL_SELECTOR = 0x4e41a1fb;
    uint256 private constant _DECIMALS_SELECTOR = 0x3f47e662;
    uint256 private constant _URI_SELECTOR = 0x0e89341c;

    // Declare an immutable argument for the account of the benchmarker contract.
    address private immutable _BENCHMARKER;

    /**
     * @notice Constructor that initializes immutable variables and deploys the metadata
     * renderer. Captures the initial chain ID and domain separator, deploys the metadata
     * renderer, and checks for Permit2 deployment.
     */
    constructor() {
        _INITIAL_CHAIN_ID = block.chainid;
        _INITIAL_DOMAIN_SEPARATOR = block.chainid.toNotarizedDomainSeparator();
        new MetadataRenderer();
        _PERMIT2_INITIALLY_DEPLOYED = _checkPermit2Deployment();

        // Deploy contract for benchmarking native and generic ERC20 token withdrawals. Note
        // that benchmark cannot be evaluated as part of contract creation as it requires
        // that the ERC20 account is not already warm as part of deriving the benchmark.
        _BENCHMARKER = address(new TransferBenchmarker());
    }

    /**
     * @notice Internal function to set the reentrancy guard using either TSTORE or SSTORE.
     * Called as part of functions that require reentrancy protection. Reverts if called
     * again before the reentrancy guard has been cleared.
     * @dev Note that the caller is set to the value; this enables external contracts to
     * ascertain the account originating the ongoing call while handling the call using
     * exttload. Also note that the value is actually set to a value of 1 when cleared;
     * this results in a significant efficiency improvement for environments that do not
     * yet support tstore, and additionally provides a mechanism to determine whether the
     * contract has been entered in a previous stage of the current transaction for
     * environments that do support it.
     */
    function _setReentrancyGuard() internal {
        // Retrieve the current reentrancy sentinel value.
        uint256 entered = _getTstorish(_REENTRANCY_GUARD_SLOT);

        assembly ("memory-safe") {
            // Consider any value over 1 as indicating that reentrancy is disallowed.
            if gt(entered, 1) {
                // revert ReentrantCall(address existingCaller)
                mstore(0, 0xf57c448b)
                mstore(0x20, entered)
                revert(0x1c, 0x24)
            }

            // Use the address of the caller for the updated sentinel value.
            entered := caller()
        }

        // Store the updated sentinel value.
        _setTstorish(_REENTRANCY_GUARD_SLOT, entered);
    }

    /**
     * @notice Internal function to clear the reentrancy guard using either TSTORE or SSTORE.
     * Called as part of functions that require reentrancy protection.
     */
    function _clearReentrancyGuard() internal {
        // Store a value of 1 for the updated sentinel value. This indicates that the
        // contract can be entered again while keeping the sentinel storage slot dirty.
        _setTstorish(_REENTRANCY_GUARD_SLOT, 1);
    }

    /**
     * @notice Internal function to benchmark the gas costs of token transfers.
     * Measures both native token and ERC20 token transfer costs and stores them.
     */
    function _benchmark() internal {
        address benchmarker = _BENCHMARKER;

        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let success := call(gas(), benchmarker, callvalue(), 0, calldatasize(), 0, 0x40)
            if iszero(success) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }

            sstore(_NATIVE_TOKEN_BENCHMARK_SCOPE, mload(0))
            sstore(_ERC20_TOKEN_BENCHMARK_SCOPE, mload(0x20))
        }
    }

    /**
     * @notice Internal view function for retrieving the benchmarked gas costs for
     * both native token and ERC20 token withdrawals.
     * @return nativeTokenStipend The benchmarked gas cost for native token withdrawals.
     * @return erc20TokenStipend  The benchmarked gas cost for ERC20 token withdrawals.
     */
    function _getRequiredWithdrawalFallbackStipends()
        internal
        view
        returns (uint256 nativeTokenStipend, uint256 erc20TokenStipend)
    {
        assembly ("memory-safe") {
            nativeTokenStipend := sload(_NATIVE_TOKEN_BENCHMARK_SCOPE)
            erc20TokenStipend := sload(_ERC20_TOKEN_BENCHMARK_SCOPE)
        }
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
    function _domainSeparator() internal view virtual returns (bytes32) {
        return _INITIAL_DOMAIN_SEPARATOR.toLatest(_INITIAL_CHAIN_ID);
    }

    /**
     * @notice Internal view function for retrieving the name for a given token ID.
     * @param id The ERC6909 token identifier.
     * @return The token's name.
     */
    function _name(uint256 id) internal view returns (string memory) {
        _viaMetadataRenderer(uint256(_NAME_SELECTOR).asStubborn(), id);
    }

    /**
     * @notice Internal view function for retrieving the symbol for a given token ID.
     * @param id The ERC6909 token identifier.
     * @return The token's symbol.
     */
    function _symbol(uint256 id) internal view returns (string memory) {
        _viaMetadataRenderer(uint256(_SYMBOL_SELECTOR).asStubborn(), id);
    }

    /**
     * @notice Internal view function for retrieving the decimals for a given token ID.
     * @param id The ERC6909 token identifier.
     * @return The token's decimals.
     */
    function _decimals(uint256 id) internal view returns (uint8) {
        _viaMetadataRenderer(uint256(_DECIMALS_SELECTOR).asStubborn(), id);
    }

    /**
     * @notice Internal view function for retrieving the URI for a given token ID.
     * @param id The ERC6909 token identifier.
     * @return The token's URI.
     */
    function _tokenURI(uint256 id) internal view returns (string memory) {
        _viaMetadataRenderer(uint256(_URI_SELECTOR).asStubborn(), id);
    }

    /**
     * @notice Private view function that checks whether Permit2 is currently deployed by
     * checking for code at the Permit2 address.
     * @return permit2Deployed Whether there is code at the Permit2 address.
     */
    function _checkPermit2Deployment() private view returns (bool permit2Deployed) {
        assembly ("memory-safe") {
            permit2Deployed := gt(extcodesize(_PERMIT2), 0)
        }
    }

    /**
     * @notice Private view function for calling the metadata renderer and passing
     * through the result. Note that this function will forceably return or revert,
     * exiting the current call stack.
     * @param functionSelector A uint256 representation of the function selector to use.
     * @param id The ERC6909 token identifier.
     */
    function _viaMetadataRenderer(uint256 functionSelector, uint256 id) private view {
        assembly ("memory-safe") {
            // Prepare RLP-encoded inputs for metadata renderer address in scratch space.
            mstore(0x14, address()) // Deployer address.
            mstore(0, 0xd694) // RLP prefix for given input sizes.
            mstore8(0x34, 0x02) // Metadata renderer contract deployment nonce.

            // Derive metadata renderer contract address by hashing the prepared inputs.
            // Dirty upper bits will be ignored when performing the subsequent staticcall.
            let metadataRenderer := keccak256(0x1e, 0x17)

            // Prepare calldata for staticcall to metadata renderer via provided arguments.
            mstore(0, functionSelector)
            mstore(0x20, id)

            // Perform staticcall to derived account using prepared calldata.
            let success := staticcall(gas(), metadataRenderer, 0x1c, 0x24, 0, 0)

            // Copy the full returndata buffer to memory.
            returndatacopy(0, 0, returndatasize())

            // Bubble up the revert if the staticcall reverted; otherwise return.
            if iszero(success) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}
