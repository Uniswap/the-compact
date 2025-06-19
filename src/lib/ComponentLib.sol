// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocatedTransfer } from "../types/Claims.sol";
import { AllocatedBatchTransfer } from "../types/BatchClaims.sol";
import { Component, ComponentsById, BatchClaimComponent } from "../types/Components.sol";

import { EfficiencyLib } from "./EfficiencyLib.sol";
import { IdLib } from "./IdLib.sol";
import { ValidityLib } from "./ValidityLib.sol";
import { TransferLib } from "./TransferLib.sol";

/**
 * @title ComponentLib
 * @notice Library contract implementing internal functions with helper logic for
 * processing claims including those with batch components.
 * @dev IMPORTANT NOTE: logic for processing claims assumes that the utilized structs are
 * formatted in a very specific manner — if parameters are rearranged or new parameters
 * are inserted, much of this functionality will break. Proceed with caution when making
 * any changes.
 */
library ComponentLib {
    using TransferLib for address;
    using ComponentLib for Component[];
    using EfficiencyLib for bool;
    using IdLib for uint256;
    using ValidityLib for uint256;
    using ValidityLib for bytes32;

    error NoIdsAndAmountsProvided();

    /**
     * @notice Internal function for performing a set of transfers or withdrawals.
     * Executes the transfer or withdrawal operation targeting multiple recipients from
     * a single resource lock.
     * @param transfer  An AllocatedTransfer struct containing transfer details.
     * @return          Whether the transfer was successfully processed.
     */
    function processTransfer(AllocatedTransfer calldata transfer) internal returns (bool) {
        // Process the transfer for each component.
        _processTransferComponents(transfer.recipients, transfer.id);

        return true;
    }

    /**
     * @notice Internal function for performing a set of batch transfers or withdrawals.
     * Executes the transfer or withdrawal operation for multiple recipients from multiple
     * resource locks.
     * @param transfer  An AllocatedBatchTransfer struct containing batch transfer details.
     */
    function processBatchTransfer(AllocatedBatchTransfer calldata transfer) internal {
        // Navigate to the batch components array in calldata.
        ComponentsById[] calldata transfers = transfer.transfers;

        // Retrieve the total number of components.
        uint256 totalIds = transfers.length;
        // Iterate over each component in calldata.
        for (uint256 i = 0; i < totalIds; ++i) {
            // Navigate to location of the component in calldata.
            ComponentsById calldata component = transfers[i];

            // Process transfer for each component in the set.
            _processTransferComponents(component.portions, component.id);
        }
    }

    /**
     * @notice Internal function for processing claims with potentially exogenous sponsor
     * signatures. Extracts claim parameters from calldata, validates the claim, validates
     * the scope, and executes either releases of ERC6909 tokens or withdrawals of underlying
     * tokens to multiple recipients.
     * @param claimHash              The EIP-712 hash of the compact for which the claim is being processed.
     * @param calldataPointer        Pointer to the location of the associated struct in calldata.
     * @param sponsorDomainSeparator The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @param typehash               The EIP-712 typehash used for the claim message.
     * @param domainSeparator        The local domain separator.
     * @param validation             Function pointer to the _validate function.
     */
    function processClaimWithComponents(
        bytes32 claimHash,
        uint256 calldataPointer,
        bytes32 sponsorDomainSeparator,
        bytes32 typehash,
        bytes32 domainSeparator,
        function(bytes32, uint96, uint256, bytes32, bytes32, bytes32, uint256[2][] memory) internal returns (address)
            validation
    ) internal {
        // Declare variables for parameters that will be extracted from calldata.
        uint256 id;
        uint256 allocatedAmount;
        Component[] calldata components;

        assembly ("memory-safe") {
            // Calculate pointer to claim parameters using expected offset.
            let calldataPointerWithOffset := add(calldataPointer, 0xe0)

            // Extract resource lock id and allocated amount.
            id := calldataload(calldataPointerWithOffset)
            allocatedAmount := calldataload(add(calldataPointerWithOffset, 0x20))

            // Extract array of components containing claimant addresses and amounts.
            let componentsPtr := add(calldataPointer, calldataload(add(calldataPointerWithOffset, 0x40)))
            components.offset := add(0x20, componentsPtr)
            components.length := calldataload(componentsPtr)
        }

        // Initialize idsAndAmounts array.
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0] = [id, allocatedAmount];

        // Validate the claim and extract the sponsor address.
        address sponsor = validation(
            claimHash,
            id.toAllocatorId(),
            calldataPointer,
            domainSeparator,
            sponsorDomainSeparator,
            typehash,
            idsAndAmounts
        );

        // Verify the resource lock scope is compatible with the provided domain separator.
        sponsorDomainSeparator.ensureValidScope(id);

        // Process each component, verifying total amount and executing operations.
        components.verifyAndProcessComponents(sponsor, id, allocatedAmount);
    }

    /**
     * @notice Internal function for processing qualified batch claims with potentially
     * exogenous sponsor signatures. Extracts batch claim parameters from calldata,
     * validates the claim, and executes operations for each resource lock. Uses optimized
     * validation of allocator consistency and scopes, with explicit validation on failure to
     * identify specific issues. Each resource lock can be split among multiple recipients.
     * @param claimHash              The EIP-712 hash of the compact for which the claim is being processed.
     * @param calldataPointer          Pointer to the location of the associated struct in calldata.
     * @param sponsorDomainSeparator   The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @param typehash                 The EIP-712 typehash used for the claim message.
     * @param domainSeparator          The local domain separator.
     * @param validation               Function pointer to the _validate function.
     */
    function processClaimWithBatchComponents(
        bytes32 claimHash,
        uint256 calldataPointer,
        bytes32 sponsorDomainSeparator,
        bytes32 typehash,
        bytes32 domainSeparator,
        function(bytes32, uint96, uint256, bytes32, bytes32, bytes32, uint256[2][] memory) internal returns (address)
            validation
    ) internal {
        // Declare variable for BatchClaimComponent array that will be extracted from calldata.
        BatchClaimComponent[] calldata claims;
        assembly ("memory-safe") {
            // Extract array of batch claim components.
            let claimsPtr := add(calldataPointer, calldataload(add(calldataPointer, 0xe0)))
            claims.offset := add(0x20, claimsPtr)
            claims.length := calldataload(claimsPtr)
        }

        // Parse into idsAndAmounts & extract first allocatorId.
        (uint256[2][] memory idsAndAmounts, uint96 firstAllocatorId) =
            _buildIdsAndAmountsWithConsistentAllocatorIdCheck(claims, sponsorDomainSeparator);

        // Validate the claim and extract the sponsor address.
        address sponsor = validation(
            claimHash,
            firstAllocatorId,
            calldataPointer,
            domainSeparator,
            sponsorDomainSeparator,
            typehash,
            idsAndAmounts
        );

        // Process each claim component.
        for (uint256 i = 0; i < idsAndAmounts.length; ++i) {
            BatchClaimComponent calldata claimComponent = claims[i];

            // Process each component, verifying total amount and executing operations.
            claimComponent.portions.verifyAndProcessComponents(
                sponsor, claimComponent.id, claimComponent.allocatedAmount
            );
        }
    }

    /**
     * @notice Internal function for building an array of resource lock IDs and their allocated
     * amounts from batch claim components. Also extracts the allocator ID from the first item
     * for validation purposes. Verifies that all claims use the same allocator and have valid
     * scopes.
     * @param claims                 Array of batch claim components to process.
     * @param sponsorDomainSeparator The domain separator for the sponsor's signature, or zero for non-exogenous claims.
     * @return idsAndAmounts         Array of [id, allocatedAmount] pairs for each claim component.
     * @return firstAllocatorId      The allocator ID extracted from the first claim component.
     */
    function _buildIdsAndAmountsWithConsistentAllocatorIdCheck(
        BatchClaimComponent[] calldata claims,
        bytes32 sponsorDomainSeparator
    ) internal pure returns (uint256[2][] memory idsAndAmounts, uint96 firstAllocatorId) {
        uint256 totalClaims = claims.length;
        if (totalClaims == 0) {
            revert NoIdsAndAmountsProvided();
        }

        // Extract allocator id and amount from first claim for validation.
        BatchClaimComponent calldata claimComponent = claims[0];
        uint256 id = claimComponent.id;
        firstAllocatorId = id.toAllocatorId();

        // Initialize idsAndAmounts array and register the first element.
        idsAndAmounts = new uint256[2][](totalClaims);
        idsAndAmounts[0] = [id, claimComponent.allocatedAmount];

        // Initialize error tracking variable.
        uint256 errorBuffer = id.scopeNotMultichain(sponsorDomainSeparator).asUint256();

        // Register each additional element & accumulate potential errors.
        for (uint256 i = 1; i < totalClaims; ++i) {
            claimComponent = claims[i];
            id = claimComponent.id;

            errorBuffer |=
                (id.toAllocatorId() != firstAllocatorId).or(id.scopeNotMultichain(sponsorDomainSeparator)).asUint256();

            // Include the id and amount in idsAndAmounts.
            idsAndAmounts[i] = [id, claimComponent.allocatedAmount];
        }

        // Revert if any errors occurred.
        assembly ("memory-safe") {
            if errorBuffer {
                // revert InvalidBatchAllocation()
                mstore(0, 0x3a03d3bb)
                revert(0x1c, 0x04)
            }
        }
    }

    /**
     * @notice Internal function for verifying and processing components. Ensures that the
     * sum of amounts doesn't exceed the allocated amount, checks for arithmetic overflow,
     * and executes the specified operation for each recipient. Reverts if the total claimed
     * amount exceeds the allocation or if arithmetic overflow occurs during summation.
     * @param claimants       Array of components specifying recipients and their amounts.
     * @param sponsor         The address of the claim sponsor.
     * @param id              The ERC6909 token identifier of the resource lock.
     * @param allocatedAmount The total amount allocated for this claim.
     */
    function verifyAndProcessComponents(
        Component[] calldata claimants,
        address sponsor,
        uint256 id,
        uint256 allocatedAmount
    ) internal {
        // Initialize tracking variables.
        uint256 totalClaims = claimants.length;
        uint256 spentAmount;
        uint256 errorBuffer;

        unchecked {
            // Process each component while tracking total amount and checking for overflow.
            for (uint256 i = 0; i < totalClaims; ++i) {
                Component calldata component = claimants[i];
                uint256 amount = component.amount;

                // Track total amount claimed, checking for overflow.
                spentAmount += amount;
                errorBuffer |= (spentAmount < amount).asUint256();

                sponsor.performOperation(id, component.claimant, amount);
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
    }

    /**
     * @notice Internal pure function for summing all amounts in a Component array.
     * Checks for arithmetic overflow during summation and reverts if detected.
     * @param recipients A Component struct array containing transfer details.
     * @return sum Total amount across all components.
     */
    function aggregate(Component[] calldata recipients) internal pure returns (uint256 sum) {
        assembly ("memory-safe") {
            let errorBuffer := 0

            let end := add(shl(6, recipients.length), recipients.offset) // Each component has 2 elements, each element 32 bytes
            let dataOffset := add(recipients.offset, 0x20) // Point to first amount

            for { } lt(dataOffset, end) { dataOffset := add(dataOffset, 0x40) } {
                let amount := calldataload(dataOffset)
                sum := add(amount, sum)
                errorBuffer := or(errorBuffer, lt(sum, amount))
            }

            if errorBuffer {
                // Revert Panic(0x11) (arithmetic overflow)
                mstore(0, 0x4e487b71)
                mstore(0x20, 0x11)
                revert(0x1c, 0x24)
            }
        }
    }

    /**
     * @notice Private function for performing a set of transfers or withdrawals
     * given an array of components and an ID for an associated resource lock.
     * Executes the transfer or withdrawal operation targeting multiple recipients.
     * @param recipients A Component struct array containing transfer details.
     * @param id         The ERC6909 token identifier of the resource lock.
     */
    function _processTransferComponents(Component[] calldata recipients, uint256 id) private {
        // Retrieve the total number of components.
        uint256 totalComponents = recipients.length;

        // Iterate over each additional component in calldata.
        for (uint256 i = 0; i < totalComponents; ++i) {
            // Navigate to location of the component in calldata.
            Component calldata component = recipients[i];

            // Perform the transfer or withdrawal for the portion.
            msg.sender.performOperation(id, component.claimant, component.amount);
        }
    }
}
