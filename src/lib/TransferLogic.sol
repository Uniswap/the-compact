// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocatedBatchTransfer } from "../types/BatchClaims.sol";
import { AllocatedTransfer } from "../types/Claims.sol";
import { TransferComponent, Component, ComponentsById } from "../types/Components.sol";

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
    using ClaimHashLib for AllocatedTransfer;
    using ClaimHashLib for AllocatedBatchTransfer;
    using ComponentLib for AllocatedTransfer;
    using ComponentLib for AllocatedBatchTransfer;
    using ComponentLib for Component[];
    using IdLib for uint256;
    using EfficiencyLib for bool;
    using EventLib for address;
    using ValidityLib for uint96;
    using ValidityLib for uint256;
    using ValidityLib for bytes32;
    using
    TransferFunctionCastLib
    for function(bytes32, address, AllocatedTransfer calldata, uint256[2][] memory) internal;
    using AllocatorLib for address;

    // bytes4(keccak256("attest(address,address,address,uint256,uint256)")).
    uint32 private constant _ATTEST_SELECTOR = 0x1a808f91;

    /**
     * @notice Internal function for processing a transfer or withdrawal. Validates the
     * allocator signature, checks expiration, consumes the nonce, and executes the transfer
     * or withdrawal operation targeting multiple recipients from a single resource lock.
     * @param transfer  An AllocatedTransfer struct containing signature, nonce, expiry, and transfer details.
     * @return          Whether the transfer was successfully processed.
     */
    function _processTransfer(AllocatedTransfer calldata transfer) internal returns (bool) {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0] = [transfer.id, transfer.recipients.aggregate()];

        // Derive hash, validate expiry, consume nonce, and check allocator signature.
        _notExpiredAndAuthorizedByAllocator(
            transfer.toClaimHash(),
            transfer.id.toRegisteredAllocatorWithConsumed(transfer.nonce),
            transfer,
            idsAndAmounts
        );

        // Perform the transfers or withdrawals.
        transfer.processTransfer();

        // Clear the reentancy guard.
        _clearReentrancyGuard();

        return true;
    }

    /**
     * @notice Internal function for processing a batch transfer or withdrawal. Validates
     * the allocator signature, checks expiration, consumes the nonce, ensures consistent
     * allocator across all resource locks, and executes the transfer or withdrawal operation
     * for multiple recipients from multiple resource locks.
     * @param transfer  An AllocatedBatchTransfer struct containing signature, nonce, expiry, and batch transfer details.
     * @return          Whether the transfer was successfully processed.
     */
    function _processBatchTransfer(AllocatedBatchTransfer calldata transfer) internal returns (bool) {
        // Set the reentrancy guard.
        _setReentrancyGuard();

        // Navigate to the batch components array in calldata.
        ComponentsById[] calldata transfers = transfer.transfers;

        // Retrieve the total number of components.
        uint256 totalIds = transfers.length;
        uint256[2][] memory idsAndAmounts = new uint256[2][](totalIds);

        unchecked {
            // Iterate over each component in calldata.
            for (uint256 i = 0; i < totalIds; ++i) {
                // Navigate to location of the component in calldata.
                ComponentsById calldata component = transfers[i];

                // Process transfer for each component in the set.
                idsAndAmounts[i] = [component.id, component.portions.aggregate()];
            }
        }

        // Derive hash, validate expiry, consume nonce, and check allocator signature.
        _notExpiredAndAuthorizedByAllocator.usingBatchTransfer()(
            transfer.toClaimHash(),
            _deriveConsistentAllocatorAndConsumeNonce(transfer.transfers, transfer.nonce),
            transfer,
            idsAndAmounts
        );

        // Perform the batch transfers or withdrawals.
        transfer.performBatchTransfer();

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
     * @param transferPayload The AllocatedTransfer struct containing signature and expiry.
     * @param idsAndAmounts   An array with IDs and aggregate transfer amounts.
     */
    function _notExpiredAndAuthorizedByAllocator(
        bytes32 messageHash,
        address allocator,
        AllocatedTransfer calldata transferPayload,
        uint256[2][] memory idsAndAmounts
    ) private {
        uint256 expires = transferPayload.expires;
        uint256 nonce = transferPayload.nonce;

        // Ensure that the expiration timestamp is still in the future.
        expires.later();

        allocator.callAuthorizeClaim(
            messageHash,
            msg.sender, // sponsor
            nonce,
            expires,
            idsAndAmounts,
            transferPayload.allocatorData
        );

        // Emit Claim event.
        msg.sender.emitClaim(messageHash, allocator, nonce);
    }

    /**
     * @notice Private function that ensures all components in a batch transfer share the
     * same allocator and consumes the nonce. Reverts if any component has a different
     * allocator or if the batch is empty.
     * @param components           Array of transfer components to check.
     * @param nonce                The nonce to consume.
     * @return allocator           The validated allocator address.
     */
    function _deriveConsistentAllocatorAndConsumeNonce(ComponentsById[] calldata components, uint256 nonce)
        private
        returns (address allocator)
    {
        // Retrieve the total number of components.
        uint256 totalComponents = components.length;

        // Track errors, starting with whether total number of components is zero.
        uint256 errorBuffer = (totalComponents == 0).asUint256();

        // Revert if an error was encountered.
        assembly ("memory-safe") {
            if errorBuffer {
                // revert InvalidBatchAllocation()
                mstore(0, 0x3a03d3bb)
                revert(0x1c, 0x04)
            }
        }

        // Retrieve the ID of the initial component and derive the allocator ID.
        uint96 allocatorId = components[0].id.toAllocatorId();

        // Retrieve the allocator address and consume the nonce.
        allocator = allocatorId.fromRegisteredAllocatorIdWithConsumed(nonce);

        unchecked {
            // Iterate over each additional component in calldata.
            for (uint256 i = 1; i < totalComponents; ++i) {
                // Retrieve ID and mark error if derived allocatorId differs from initial one.
                errorBuffer |= (components[i].id.toAllocatorId() != allocatorId).asUint256();
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
}
