// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BatchTransfer, SplitBatchTransfer } from "../types/BatchClaims.sol";
import { BasicTransfer, SplitTransfer } from "../types/Claims.sol";
import { TransferComponent, SplitComponent, SplitByIdComponent } from "../types/Components.sol";

import { ClaimHashLib } from "./ClaimHashLib.sol";
import { ComponentLib } from "./ComponentLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { EventLib } from "./EventLib.sol";
import { TransferFunctionCastLib } from "./TransferFunctionCastLib.sol";
import { IdLib } from "./IdLib.sol";
import { ConstructorLogic } from "./ConstructorLogic.sol";
import { ValidityLib } from "./ValidityLib.sol";
import { AllocatorLib } from "./AllocatorLib.sol";

/**
 * @title TransferLogic
 * @notice Inherited contract implementing internal functions with logic for processing
 * allocated token transfers and withdrawals. These calls are submitted directly by the
 * sponsor and therefore only need to be independently authorized by the allocator. To
 * construct the authorizing Compact or BatchCompact payload, the arbiter is set as the
 * sponsor.
 */
contract TransferLogic is ConstructorLogic {
    using ClaimHashLib for BasicTransfer;
    using ClaimHashLib for SplitTransfer;
    using ClaimHashLib for BatchTransfer;
    using ClaimHashLib for SplitBatchTransfer;
    using ComponentLib for SplitTransfer;
    using ComponentLib for BatchTransfer;
    using ComponentLib for SplitBatchTransfer;
    using ComponentLib for SplitComponent[];
    using IdLib for uint256;
    using EfficiencyLib for bool;
    using EventLib for address;
    using ValidityLib for uint96;
    using ValidityLib for uint256;
    using ValidityLib for bytes32;
    using TransferFunctionCastLib for function(bytes32, address, BasicTransfer calldata, uint256[2][] memory) internal;
    using TransferFunctionCastLib for function(TransferComponent[] calldata, uint256, function (TransferComponent[] calldata, uint256) internal pure returns (uint96)) internal returns (address);
    using AllocatorLib for address;

    // bytes4(keccak256("attest(address,address,address,uint256,uint256)")).
    uint32 private constant _ATTEST_SELECTOR = 0x1a808f91;

    /**
     * @notice Internal function for processing a split transfer or withdrawal. Validates the
     * allocator signature, checks expiration, consumes the nonce, and executes the transfer
     * or withdrawal operation targeting multiple recipients from a single resource lock.
     * @param transfer  A SplitTransfer struct containing signature, nonce, expiry, and split transfer details.
     * @return          Whether the transfer was successfully processed.
     */
    function _processSplitTransfer(SplitTransfer calldata transfer) internal returns (bool) {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0] = [transfer.id, transfer.recipients.aggregate()];

        // Derive hash, validate expiry, consume nonce, and check allocator signature.
        _notExpiredAndAuthorizedByAllocator.usingSplitTransfer()(transfer.toClaimHash(), transfer.id.toRegisteredAllocatorWithConsumed(transfer.nonce), transfer, idsAndAmounts);

        // Perform the split transfers or withdrawals.
        transfer.processSplitTransfer();

        // Clear the reentancy guard.
        _clearReentrancyGuard();

        return true;
    }

    /**
     * @notice Internal function for processing a split batch transfer or withdrawal. Validates
     * the allocator signature, checks expiration, consumes the nonce, ensures consistent
     * allocator across all resource locks, and executes the transfer or withdrawal operation
     * for multiple recipients from multiple resource locks.
     * @param transfer  A SplitBatchTransfer struct containing signature, nonce, expiry, and split batch transfer details.
     * @return          Whether the transfer was successfully processed.
     */
    function _processSplitBatchTransfer(SplitBatchTransfer calldata transfer) internal returns (bool) {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        // Navigate to the split batch components array in calldata.
        SplitByIdComponent[] calldata transfers = transfer.transfers;

        // Retrieve the total number of components.
        uint256 totalIds = transfers.length;
        uint256[2][] memory idsAndAmounts = new uint256[2][](totalIds);

        unchecked {
            // Iterate over each component in calldata.
            for (uint256 i = 0; i < totalIds; ++i) {
                // Navigate to location of the component in calldata.
                SplitByIdComponent calldata component = transfers[i];

                // Process transfer for each split component in the set.
                idsAndAmounts[i] = [component.id, component.portions.aggregate()];
            }
        }

        // Derive hash, validate expiry, consume nonce, and check allocator signature.
        _notExpiredAndAuthorizedByAllocator.usingSplitBatchTransfer()(
            transfer.toClaimHash(), _deriveConsistentAllocatorAndConsumeNonce.usingSplitByIdComponent()(transfer.transfers, transfer.nonce, _allocatorIdOfSplitByIdComponent), transfer, idsAndAmounts
        );

        // Perform the split batch transfers or withdrawals.
        transfer.performSplitBatchTransfer();

        // Clear the reentancy guard.
        _clearReentrancyGuard();

        return true;
    }

    /**
     * @notice Internal function for ensuring a transfer has been attested by its allocator.
     * Makes a call to the allocator's attest function and reverts if the attestation fails
     * due to a reverted call or due to the call not returning the required magic value. Note
     * that this call is stateful.
     * @param from    The account transferring tokens.
     * @param to      The account receiving tokens.
     * @param id      The ERC6909 token identifier of the resource lock.
     * @param amount  The amount of tokens being transferred.
     */
    function _ensureAttested(address from, address to, uint256 id, uint256 amount) internal {
        // Derive the allocator address from the supplied id.
        address allocator = id.toAllocator();

        assembly ("memory-safe") {
            // Sanitize from and to addresses.
            from := shr(0x60, shl(0x60, from))
            to := shr(0x60, shl(0x60, to))

            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Ensure sure initial scratch space is cleared as an added precaution.
            mstore(0, 0)

            // Derive offset to start of data for the call from memory pointer.
            let dataStart := add(m, 0x1c)

            // Prepare calldata: attest(caller(), from, to, id, amount).
            mstore(m, _ATTEST_SELECTOR)
            mstore(add(m, 0x20), caller())
            mstore(add(m, 0x40), from)
            mstore(add(m, 0x60), to)
            mstore(add(m, 0x80), id)
            mstore(add(m, 0xa0), amount)

            // Perform call to allocator and write response to scratch space.
            let success := call(gas(), allocator, 0, dataStart, 0xa4, 0, 0x20)

            // Revert if the required magic value was not received back.
            if iszero(eq(mload(0), shl(224, _ATTEST_SELECTOR))) {
                // Bubble up revert if the call failed and there's data.
                // NOTE: consider evaluating remaining gas to protect against revert bombing.
                if iszero(or(success, iszero(returndatasize()))) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }

                // revert UnallocatedTransfer(msg.sender, from, to, id, amount)
                mstore(m, 0x014c9310)
                revert(dataStart, 0xa4)
            }
        }
    }

    /**
     * @notice Private function that checks expiration, verifies the allocator's signature,
     * and emits a claim event.
     * @param messageHash     The EIP-712 hash of the transfer message.
     * @param allocator       The address of the allocator.
     * @param transferPayload The BasicTransfer struct containing signature and expiry.
     * @param idsAndAmounts   An array with IDs and aggregate transfer amounts.
     */
    function _notExpiredAndAuthorizedByAllocator(bytes32 messageHash, address allocator, BasicTransfer calldata transferPayload, uint256[2][] memory idsAndAmounts) private {
        // Ensure that the expiration timestamp is still in the future.
        transferPayload.expires.later();

        allocator.callAuthorizeClaim(
            messageHash,
            msg.sender, // sponsor
            transferPayload.nonce,
            transferPayload.expires,
            idsAndAmounts,
            transferPayload.allocatorData
        );

        // Emit Claim event.
        msg.sender.emitClaim(messageHash, allocator);
    }

    /**
     * @notice Private function that ensures all components in a batch transfer share the
     * same allocator and consumes the nonce. Reverts if any component has a different
     * allocator or if the batch is empty.
     * @param components           Array of transfer components to check.
     * @param nonce                The nonce to consume.
     * @param allocatorIdRetrieval Function pointer to retrieve allocatorId from components array (handles split components).
     * @return allocator           The validated allocator address.
     */
    function _deriveConsistentAllocatorAndConsumeNonce(
        TransferComponent[] calldata components,
        uint256 nonce,
        function (TransferComponent[] calldata, uint256) internal pure returns (uint96) allocatorIdRetrieval
    ) private returns (address allocator) {
        // Retrieve the total number of components.
        uint256 totalComponents = components.length;

        // Track errors, starting with whether total number of components is zero.
        uint256 errorBuffer = (totalComponents == 0).asUint256();

        // Retrieve the ID of the initial component and derive the allocator ID.
        uint96 allocatorId = allocatorIdRetrieval(components, 0);

        // Retrieve the allocator address and consume the nonce.
        allocator = allocatorId.fromRegisteredAllocatorIdWithConsumed(nonce);

        unchecked {
            // Iterate over each additional component in calldata.
            for (uint256 i = 1; i < totalComponents; ++i) {
                // Retrieve ID and mark error if derived allocatorId differs from initial one.
                errorBuffer |= (allocatorIdRetrieval(components, i) != allocatorId).asUint256();
            }
        }

        // Revert if an error was encountered.
        assembly ("memory-safe") {
            if errorBuffer {
                // revert InvalidBatchAllocation()
                mstore(0, 0x3a03d3bb)
                revert(0x1c, 0x04)
            }
        }
    }

    /**
     * @notice Private pure function that retrieves the ID of a batch transfer component from
     * an array of components at a specific index and uses it to derive an allocator ID.
     * @param components   Array of batch transfer components.
     * @param index        The index of the batch transfer component to retrieve.
     * @return allocatorId The allocator ID derived from the transfer component at the given index.
     */
    function _allocatorIdOfTransferComponentId(TransferComponent[] calldata components, uint256 index) private pure returns (uint96) {
        // Retrieve ID from the component and derive corresponding allocator ID.
        return components[index].id.toAllocatorId();
    }

    /**
     * @notice Private pure function that retrieves the ID of a split batch transfer component
     * from an array of components at a specific index and uses it to derive an allocator ID.
     * @param components   Array of split batch transfer components.
     * @param index        The index of the split batch transfer component to retrieve.
     * @return allocatorId The allocator ID derived from the transfer component at the given index.
     */
    function _allocatorIdOfSplitByIdComponent(SplitByIdComponent[] calldata components, uint256 index) private pure returns (uint96) {
        // Retrieve ID from the component and derive corresponding allocator ID.
        return components[index].id.toAllocatorId();
    }
}
