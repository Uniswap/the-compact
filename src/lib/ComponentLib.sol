// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { SplitTransfer } from "../types/Claims.sol";
import { BatchTransfer, SplitBatchTransfer } from "../types/BatchClaims.sol";

import { TransferComponent, SplitComponent, SplitByIdComponent, BatchClaimComponent, SplitBatchClaimComponent } from "../types/Components.sol";

import { EfficiencyLib } from "./EfficiencyLib.sol";
import { EventLib } from "./EventLib.sol";
import { HashLib } from "./HashLib.sol";
import { IdLib } from "./IdLib.sol";
import { RegistrationLib } from "./RegistrationLib.sol";
import { ValidityLib } from "./ValidityLib.sol";

/**
 * @title ComponentLib
 * @notice Library contract implementing internal functions with helper logic for
 * processing claims that incorporate split and/or batch components.
 * @dev IMPORTANT NOTE: logic for processing claims assumes that the utilized structs are
 * formatted in a very specific manner — if parameters are rearranged or new parameters
 * are inserted, much of this functionality will break. Proceed with caution when making
 * any changes.
 */
library ComponentLib {
    using ComponentLib for SplitComponent[];
    using EfficiencyLib for bool;
    using EfficiencyLib for uint256;
    using EfficiencyLib for bytes32;
    using EventLib for address;
    using HashLib for uint256;
    using IdLib for uint256;
    using ValidityLib for uint256;
    using ValidityLib for uint96;
    using ValidityLib for bytes32;
    using RegistrationLib for address;

    /**
     * @notice Internal function for performing a set of split transfers or withdrawals.
     * Executes the transfer or withdrawal operation targeting multiple recipients from
     * a single resource lock.
     * @param transfer  A SplitTransfer struct containing split transfer details.
     * @param operation Function pointer to either _release or _withdraw for executing the claim.
     * @return          Whether the transfer was successfully processed.
     */
    function processSplitTransfer(SplitTransfer calldata transfer, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        // Process the transfer for each split component.
        _processSplitTransferComponents(transfer.recipients, transfer.id, operation);

        return true;
    }

    /**
     * @notice Internal function for performing a set of batch transfer or withdrawal operations.
     * Executes the transfer or withdrawal operation for a single recipient from multiple
     * resource locks.
     * @param transfer  A BatchTransfer struct containing batch transfer details.
     * @param operation Function pointer to either _release or _withdraw for executing the claim.
     * @return          Whether the transfer was successfully processed.
     */
    function performBatchTransfer(BatchTransfer calldata transfer, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        // Navigate to the transfer components in calldata.
        TransferComponent[] calldata transfers = transfer.transfers;

        // Retrieve the recipient and the total number of components.
        address recipient = transfer.recipient;
        uint256 totalTransfers = transfers.length;

        unchecked {
            // Iterate over each component in calldata.
            for (uint256 i = 0; i < totalTransfers; ++i) {
                // Navigate to location of the component in calldata.
                TransferComponent calldata component = transfers[i];

                // Perform the transfer or withdrawal for the component.
                operation(msg.sender, recipient, component.id, component.amount);
            }
        }

        return true;
    }

    /**
     * @notice Internal function for performing a set of split batch transfers or withdrawals.
     * Executes the transfer or withdrawal operation for multiple recipients from multiple
     * resource locks.
     * @param transfer  A SplitBatchTransfer struct containing split batch transfer details.
     * @param operation Function pointer to either _release or _withdraw for executing the claim.
     * @return          Whether the transfer was successfully processed.
     */
    function performSplitBatchTransfer(SplitBatchTransfer calldata transfer, function(address, address, uint256, uint256) internal returns (bool) operation) internal returns (bool) {
        // Navigate to the split batch components array in calldata.
        SplitByIdComponent[] calldata transfers = transfer.transfers;

        // Retrieve the total number of components.
        uint256 totalIds = transfers.length;

        unchecked {
            // Iterate over each component in calldata.
            for (uint256 i = 0; i < totalIds; ++i) {
                // Navigate to location of the component in calldata.
                SplitByIdComponent calldata component = transfers[i];

                // Process transfer for each split component in the set.
                _processSplitTransferComponents(component.portions, component.id, operation);
            }
        }

        return true;
    }

    /**
     * @notice Internal function for processing qualified split claims with potentially exogenous
     * sponsor signatures. Extracts claim parameters from calldata, validates the claim,
     * validates the scope, and executes either releases of ERC6909 tokens or withdrawals of
     * underlying tokens to multiple recipients.
     * @param messageHash              The EIP-712 hash of the claim message.
     * @param qualificationMessageHash The EIP-712 hash of the allocator's qualification message.
     * @param calldataPointer          Pointer to the location of the associated struct in calldata.
     * @param offsetToId               Offset to segment of calldata where relevant claim parameters begin.
     * @param sponsorDomainSeparator   The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @param typehash                 The EIP-712 typehash used for the claim message.
     * @param domainSeparator          The local domain separator.
     * @param operation                Function pointer to either _release or _withdraw for executing the claim.
     * @param validation               Function pointer to the _validate function.
     * @return                         Whether the split claim was successfully processed.
     */
    function processClaimWithSplitComponents(
        bytes32 messageHash,
        bytes32 qualificationMessageHash,
        uint256 calldataPointer,
        uint256 offsetToId,
        bytes32 sponsorDomainSeparator,
        bytes32 typehash,
        bytes32 domainSeparator,
        function(address, address, uint256, uint256) internal returns (bool) operation,
        function(bytes32, uint96, bytes32, uint256, bytes32, bytes32, bytes32) internal returns (address) validation
    ) internal returns (bool) {
        // Declare variables for parameters that will be extracted from calldata.
        uint256 id;
        uint256 allocatedAmount;
        SplitComponent[] calldata components;

        assembly ("memory-safe") {
            // Calculate pointer to claim parameters using provided offset.
            let calldataPointerWithOffset := add(calldataPointer, offsetToId)

            // Extract resource lock id and allocated amount.
            id := calldataload(calldataPointerWithOffset)
            allocatedAmount := calldataload(add(calldataPointerWithOffset, 0x20))

            // Extract array of split components containing claimant addresses and amounts.
            let componentsPtr := add(calldataPointer, calldataload(add(calldataPointerWithOffset, 0x40)))
            components.offset := add(0x20, componentsPtr)
            components.length := calldataload(componentsPtr)
        }

        // Validate the claim and extract the sponsor address.
        address sponsor = validation(messageHash, id.toAllocatorId(), qualificationMessageHash, calldataPointer, domainSeparator, sponsorDomainSeparator, typehash);

        // Verify the resource lock scope is compatible with the provided domain separator.
        sponsorDomainSeparator.ensureValidScope(id);

        // Process each split component, verifying total amount and executing operations.
        return components.verifyAndProcessSplitComponents(sponsor, id, allocatedAmount, operation);
    }

    /**
     * @notice Internal function for processing qualified batch claims with potentially exogenous
     * sponsor signatures. Extracts batch claim parameters from calldata, validates the claim,
     * executes operations, and performs optimized validation of allocator consistency, amounts,
     * and scopes. If any validation fails, all operations are reverted after explicitly
     * identifying the specific validation failures.
     * @param messageHash              The EIP-712 hash of the claim message.
     * @param qualificationMessageHash The EIP-712 hash of the allocator's qualification message.
     * @param calldataPointer          Pointer to the location of the associated struct in calldata.
     * @param offsetToId               Offset to segment of calldata where relevant claim parameters begin.
     * @param sponsorDomainSeparator   The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @param typehash                 The EIP-712 typehash used for the claim message.
     * @param domainSeparator          The local domain separator.
     * @param operation                Function pointer to either _release or _withdraw for executing the claim.
     * @param validation               Function pointer to the _validate function.
     * @return                         Whether the batch claim was successfully processed.
     */
    function processClaimWithBatchComponents(
        bytes32 messageHash,
        bytes32 qualificationMessageHash,
        uint256 calldataPointer,
        uint256 offsetToId,
        bytes32 sponsorDomainSeparator,
        bytes32 typehash,
        bytes32 domainSeparator,
        function(address, address, uint256, uint256) internal returns (bool) operation,
        function(bytes32, uint96, bytes32, uint256, bytes32, bytes32, bytes32) internal returns (address) validation
    ) internal returns (bool) {
        // Declare variables for parameters that will be extracted from calldata.
        BatchClaimComponent[] calldata claims;
        address claimant;

        assembly ("memory-safe") {
            // Calculate pointer to claim parameters using provided offset.
            let calldataPointerWithOffset := add(calldataPointer, offsetToId)

            // Extract array of batch claim components and claimant address.
            let claimsPtr := add(calldataPointer, calldataload(calldataPointerWithOffset))
            claims.offset := add(0x20, claimsPtr)
            claims.length := calldataload(claimsPtr)
            claimant := calldataload(add(calldataPointerWithOffset, 0x20))
        }

        // Extract allocator id from first claim for validation.
        uint96 firstAllocatorId = claims[0].id.toAllocatorId();

        // Validate the claim and extract the sponsor address.
        address sponsor = validation(messageHash, firstAllocatorId, qualificationMessageHash, calldataPointer, domainSeparator, sponsorDomainSeparator, typehash);

        // Revert if the batch is empty.
        uint256 totalClaims = claims.length;

        // Process first claim and initialize error tracking.
        // NOTE: many of the bounds checks on these array accesses can be skipped as an optimization
        BatchClaimComponent calldata component = claims[0];
        uint256 id = component.id;
        uint256 amount = component.amount;
        uint256 errorBuffer = (totalClaims == 0).or(component.allocatedAmount.allocationExceededOrScopeNotMultichain(amount, id, sponsorDomainSeparator)).asUint256();

        // Execute transfer or withdrawal for first claim.
        operation(sponsor, claimant, id, amount);

        unchecked {
            // Process remaining claims while accumulating potential errors.
            for (uint256 i = 1; i < totalClaims; ++i) {
                component = claims[i];
                id = component.id;
                amount = component.amount;
                errorBuffer |= (id.toAllocatorId() != firstAllocatorId).or(component.allocatedAmount.allocationExceededOrScopeNotMultichain(amount, id, sponsorDomainSeparator)).asUint256();

                operation(sponsor, claimant, id, amount);
            }

            _revertWithInvalidBatchAllocationIfError(errorBuffer);
        }

        return true;
    }

    /**
     * @notice Internal function for processing qualified split batch claims with potentially
     * exogenous sponsor signatures. Extracts split batch claim parameters from calldata,
     * validates the claim, and executes split operations for each resource lock. Uses optimized
     * validation of allocator consistency and scopes, with explicit validation on failure to
     * identify specific issues. Each resource lock can be split among multiple recipients.
     * @param messageHash              The EIP-712 hash of the claim message.
     * @param qualificationMessageHash The EIP-712 hash of the allocator's qualification message.
     * @param calldataPointer          Pointer to the location of the associated struct in calldata.
     * @param offsetToId               Offset to segment of calldata where relevant claim parameters begin.
     * @param sponsorDomainSeparator   The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @param typehash                 The EIP-712 typehash used for the claim message.
     * @param domainSeparator          The local domain separator.
     * @param operation                Function pointer to either _release or _withdraw for executing the claim.
     * @param validation               Function pointer to the _validate function.
     * @return                         Whether the split batch claim was successfully processed.
     */
    function processClaimWithSplitBatchComponents(
        bytes32 messageHash,
        bytes32 qualificationMessageHash,
        uint256 calldataPointer,
        uint256 offsetToId,
        bytes32 sponsorDomainSeparator,
        bytes32 typehash,
        bytes32 domainSeparator,
        function(address, address, uint256, uint256) internal returns (bool) operation,
        function(bytes32, uint96, bytes32, uint256, bytes32, bytes32, bytes32) internal returns (address) validation
    ) internal returns (bool) {
        // Declare variable for SplitBatchClaimComponent array that will be extracted from calldata.
        SplitBatchClaimComponent[] calldata claims;

        assembly ("memory-safe") {
            // Extract array of split batch claim components.
            let claimsPtr := add(calldataPointer, calldataload(add(calldataPointer, offsetToId)))
            claims.offset := add(0x20, claimsPtr)
            claims.length := calldataload(claimsPtr)
        }

        // Extract allocator id from first claim for validation.
        uint96 firstAllocatorId = claims[0].id.toAllocatorId();

        // Validate the claim and extract the sponsor address.
        address sponsor = validation(messageHash, firstAllocatorId, qualificationMessageHash, calldataPointer, domainSeparator, sponsorDomainSeparator, typehash);

        // Initialize tracking variables.
        uint256 totalClaims = claims.length;
        uint256 errorBuffer = (totalClaims == 0).asUint256();
        uint256 id;

        unchecked {
            // Process each claim component while accumulating potential errors.
            for (uint256 i = 0; i < totalClaims; ++i) {
                SplitBatchClaimComponent calldata claimComponent = claims[i];
                id = claimComponent.id;
                errorBuffer |= (id.toAllocatorId() != firstAllocatorId).or(id.scopeNotMultichain(sponsorDomainSeparator)).asUint256();

                // Process each split component, verifying total amount and executing operations.
                claimComponent.portions.verifyAndProcessSplitComponents(sponsor, id, claimComponent.allocatedAmount, operation);
            }

            // Revert if any errors occurred.
            _revertWithInvalidBatchAllocationIfError(errorBuffer);
        }

        return true;
    }

    /**
     * @notice Internal function for verifying and processing split components. Ensures that the
     * sum of split amounts doesn't exceed the allocated amount, checks for arithmetic overflow,
     * and executes the specified operation for each split recipient. Reverts if the total
     * claimed amount exceeds the allocation or if arithmetic overflow occurs during summation.
     * @param claimants       Array of split components specifying recipients and their amounts.
     * @param sponsor         The address of the claim sponsor.
     * @param id              The ERC6909 token identifier of the resource lock.
     * @param allocatedAmount The total amount allocated for this claim.
     * @param operation       Function pointer to either _release or _withdraw for executing the claim.
     * @return                Whether all split components were successfully processed.
     */
    function verifyAndProcessSplitComponents(
        SplitComponent[] calldata claimants,
        address sponsor,
        uint256 id,
        uint256 allocatedAmount,
        function(address, address, uint256, uint256) internal returns (bool) operation
    ) internal returns (bool) {
        // Initialize tracking variables.
        uint256 totalClaims = claimants.length;
        uint256 spentAmount = 0;
        uint256 errorBuffer = (totalClaims == 0).asUint256();

        unchecked {
            // Process each split component while tracking total amount and checking for overflow.
            for (uint256 i = 0; i < totalClaims; ++i) {
                SplitComponent calldata component = claimants[i];
                uint256 amount = component.amount;

                // Track total amount claimed, checking for overflow.
                uint256 updatedSpentAmount = amount + spentAmount;
                errorBuffer |= (updatedSpentAmount < spentAmount).asUint256();
                spentAmount = updatedSpentAmount;

                // Execute transfer or withdrawal for the split component.
                operation(sponsor, component.claimant, id, amount);
            }
        }

        // Revert if an overflow occurred or if total claimed amount exceeds allocation.
        errorBuffer |= (allocatedAmount < spentAmount).asUint256();
        assembly ("memory-safe") {
            if errorBuffer {
                // revert AllocatedAmountExceeded(allocatedAmount, amount);
                mstore(0, 0x3078b2f6)
                mstore(0x20, allocatedAmount)
                mstore(0x40, spentAmount)
                revert(0x1c, 0x44)
            }
        }

        return true;
    }

    /**
     * @notice Private function for performing a set of split transfers or withdrawals
     * given an array of split components and an ID for an associated resource lock.
     * Executes the transfer or withdrawal operation targeting multiple recipients.
     * @param recipients A SplitComponent struct array containing split transfer details.
     * @param id         The ERC6909 token identifier of the resource lock.
     * @param operation  Function pointer to either _release or _withdraw for executing the claim.
     */
    function _processSplitTransferComponents(SplitComponent[] calldata recipients, uint256 id, function(address, address, uint256, uint256) internal returns (bool) operation) private {
        // Retrieve the total number of components.
        uint256 totalSplits = recipients.length;

        unchecked {
            // Iterate over each additional component in calldata.
            for (uint256 i = 0; i < totalSplits; ++i) {
                // Navigate to location of the component in calldata.
                SplitComponent calldata component = recipients[i];

                // Perform the transfer or withdrawal for the portion.
                operation(msg.sender, component.claimant, id, component.amount);
            }
        }
    }

    /**
     * @notice Private pure function that reverts with an InvalidBatchAllocation error
     * if an error buffer is nonzero.
     * @param errorBuffer The error buffer to check.
     */
    function _revertWithInvalidBatchAllocationIfError(uint256 errorBuffer) private pure {
        // Revert if any errors occurred.
        assembly ("memory-safe") {
            if errorBuffer {
                // revert InvalidBatchAllocation()
                mstore(0, 0x3a03d3bb)
                revert(0x1c, 0x04)
            }
        }
    }
}
