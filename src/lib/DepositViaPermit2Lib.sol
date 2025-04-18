// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { CompactCategory } from "../types/CompactCategory.sol";
import {
    COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPEHASH,
    PERMIT2_DEPOSIT_WITNESS_FRAGMENT_HASH,
    PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE,
    PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO,
    PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE,
    PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO,
    TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE,
    TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO,
    COMPACT_ACTIVATION_TYPEHASH,
    BATCH_COMPACT_ACTIVATION_TYPEHASH,
    COMPACT_BATCH_ACTIVATION_TYPEHASH,
    BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH,
    PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_ONE,
    PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_TWO,
    PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_THREE,
    PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_ONE,
    COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_TWO,
    COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_THREE,
    COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FOUR
} from "../types/EIP712Types.sol";

/**
 * @title DepositViaPermit2Lib
 * @notice Library contract implementing internal functions with logic for processing
 * token deposits via permit2. These deposits leverage Permit2 witness data to either
 * indicate the parameters of the lock to deposit into and the recipient of the deposit,
 * or the parameters of the compact to register alongside the deposit. Deposits can also
 * involve a single ERC20 token or a batch of tokens in a single Permit2 authorization.
 * @dev IMPORTANT NOTE: this logic operates directly on unallocated memory, and reads
 * directly from fixed calldata offsets; proceed with EXTREME caution when making any
 * modifications to either this logic contract (including the insertion of new logic) or
 * to the associated permit2 deposit function interfaces!
 */
library DepositViaPermit2Lib {
    // Selector for the batch `permit2.permitWitnessTransferFrom` function.
    uint256 private constant _BATCH_PERMIT_WITNESS_TRANSFER_FROM_SELECTOR = 0xfe8ec1a7;

    error InvalidCompactCategory();

    /**
     * @notice Internal view function for preparing batch deposit permit2 calldata.
     * Prepares known arguments and offsets in memory and returns pointers to the start
     * of the prepared calldata as well as to the start of the witness typestring.
     * @param totalTokensLessInitialNative The number of non-native tokens to deposit.
     * @param firstUnderlyingTokenIsNative Whether the first underlying token is native.
     * @return m The memory pointer to the start of the prepared calldata.
     * @return typestringMemoryLocation The memory pointer to the start of the typestring.
     */
    function beginPreparingBatchDepositPermit2Calldata(
        uint256 totalTokensLessInitialNative,
        bool firstUnderlyingTokenIsNative
    ) internal view returns (uint256 m, uint256 typestringMemoryLocation) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            m := mload(0x40)

            // Derive size of each token chunk (2 words per token).
            let tokenChunk := shl(6, totalTokensLessInitialNative)

            // Derive size of two token chunks (4 words per token).
            let twoTokenChunks := shl(1, tokenChunk)

            // Derive memory location of the `permitted` calldata struct.
            let permittedCalldataLocation := add(add(0x24, calldataload(0x24)), shl(6, firstUnderlyingTokenIsNative))

            // Prepare the initial fragment of the witness typestring.
            mstore(m, _BATCH_PERMIT_WITNESS_TRANSFER_FROM_SELECTOR)
            mstore(add(m, 0x20), 0xc0) // permitted offset
            mstore(add(m, 0x40), add(0x140, tokenChunk)) // details offset
            mstore(add(m, 0x60), calldataload(0x04)) // depositor
            // Skip witnessHash at 0x80 as it is not yet known.
            mstore(add(m, 0xa0), add(0x160, twoTokenChunks)) // witness offset
            // Skip signatureOffset at 0xc0 as it is not yet known.
            mstore(add(m, 0xe0), 0x60) // permitted tokens relative offset
            mstore(add(m, 0x100), calldataload(0x44)) // nonce
            mstore(add(m, 0x120), calldataload(0x64)) // deadline
            mstore(add(m, 0x140), totalTokensLessInitialNative) // permitted.length

            // Copy permitted data from calldata to memory.
            calldatacopy(add(m, 0x160), permittedCalldataLocation, tokenChunk)

            // Derive memory location of the `details` calldata struct.
            let detailsOffset := add(add(m, 0x160), tokenChunk)

            // Store the length of the `details` array.
            mstore(detailsOffset, totalTokensLessInitialNative)

            // Derive start, next, & end locations for iterating through `details` array.
            let starting := add(detailsOffset, 0x20)
            let next := add(detailsOffset, 0x40)
            let end := shl(6, totalTokensLessInitialNative)

            // Iterate through `details` array and copy data from calldata to memory.
            for { let i := 0 } lt(i, end) { i := add(i, 0x40) } {
                // Copy this contract as the recipient address.
                mstore(add(starting, i), address())

                // Copy full token amount as the requested amount.
                mstore(add(next, i), calldataload(add(permittedCalldataLocation, add(0x20, i))))
            }

            // Derive memory location of the witness typestring.
            typestringMemoryLocation := add(m, add(0x180, twoTokenChunks))

            // NOTE: strongly consider allocating memory here as the inline assembly scope
            // is being left (it *should* be fine for now as the function between assembly
            // blocks does not allocate any new memory).
        }
    }

    /**
     * @notice Internal pure function for deriving typehashes and simultaneously
     * preparing the witness typestring component of the call to permit2.
     * @param memoryLocation      The memory pointer to the start of the typestring.
     * @param category            The CompactCategory of the deposit. Must be Compact or BatchCompact.
     * @param witness             The witness string to insert.
     * @param usingBatch          Whether the deposit involves a batch.
     * @return activationTypehash The derived activation typehash.
     * @return compactTypehash    The derived compact typehash.
     */
    function writeWitnessAndGetTypehashes(
        uint256 memoryLocation,
        CompactCategory category,
        string calldata witness,
        bool usingBatch
    ) internal pure returns (bytes32 activationTypehash, bytes32 compactTypehash) {
        assembly ("memory-safe") {
            // Internal assembly function for writing the witness and typehashes.
            // Used to enable leaving the inline assembly scope early when the
            // witness is empty (no-witness case).
            function writeWitnessAndGetTypehashes(memLocation, c, witnessOffset, witnessLength, usesBatch) ->
                derivedActivationTypehash,
                derivedCompactTypehash
            {
                // Derive memory offset for the witness typestring data.
                let memoryOffset := add(memLocation, 0x20)

                // Declare variables for start of Activation and Category-specific data.
                let activationStart
                let categorySpecificStart

                // Handle non-batch cases.
                if iszero(usesBatch) {
                    // Prepare initial Activation witness typestring fragment.
                    mstore(add(memoryOffset, 0x09), PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO)
                    mstore(memoryOffset, PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE)

                    // Set memory pointers for Activation and Category-specific data start.
                    activationStart := add(memoryOffset, 0x13)
                    categorySpecificStart := add(memoryOffset, 0x29)
                }

                // Proceed with batch case if preparation of activation has not begun.
                if iszero(activationStart) {
                    // Prepare initial BatchActivation witness typestring fragment.
                    mstore(add(memoryOffset, 0x16), PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO)
                    mstore(memoryOffset, PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE)

                    // Set memory pointers for Activation and Category-specific data.
                    activationStart := add(memoryOffset, 0x18)
                    categorySpecificStart := add(memoryOffset, 0x36)
                }

                // Declare variable for end of Category-specific data.
                let categorySpecificEnd

                // Handle Compact (non-batch, single-chain) case.
                if iszero(c) {
                    // Prepare next typestring fragment using Compact witness typestring.
                    mstore(categorySpecificStart, PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_ONE)
                    mstore(add(categorySpecificStart, 0x20), PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_TWO)
                    mstore(add(categorySpecificStart, 0x40), PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_THREE)
                    mstore(add(categorySpecificStart, 0x68), PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FIVE)
                    mstore(add(categorySpecificStart, 0x60), PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FOUR)

                    // Set memory pointers for Activation and Category-specific data end.
                    categorySpecificEnd := add(categorySpecificStart, 0x88)
                    categorySpecificStart := add(categorySpecificStart, 0x10)
                }

                // Handle BatchCompact (single-chain) case.
                if iszero(sub(c, 1)) {
                    // Prepare next typestring fragment using BatchCompact witness typestring.
                    mstore(categorySpecificStart, PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE)
                    mstore(add(categorySpecificStart, 0x20), PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO)
                    mstore(add(categorySpecificStart, 0x40), PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE)
                    mstore(add(categorySpecificStart, 0x73), PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE)
                    mstore(add(categorySpecificStart, 0x60), PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR)

                    // Set memory pointers for Activation and Category-specific data end.
                    categorySpecificEnd := add(categorySpecificStart, 0x93)
                    categorySpecificStart := add(categorySpecificStart, 0x15)
                }

                // Revert on MultichainCompact case or above (registration only applies to the current chain).
                if iszero(categorySpecificEnd) {
                    // revert InvalidCompactCategory();
                    mstore(0, 0xdae3f108)
                    revert(0x1c, 4)
                }

                // Handle no-witness cases.
                if iszero(witnessLength) {
                    // Derive memory offset for region used to retrieve typestring fragment by index.
                    let indexWords := shl(5, c)

                    // Prepare token permissions typestring fragment.
                    mstore(add(categorySpecificEnd, 0x0e), TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO)
                    mstore(sub(categorySpecificEnd, 1), TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE)

                    // Derive total length of typestring and store at start of memory.
                    mstore(memLocation, sub(add(categorySpecificEnd, 0x2e), memoryOffset))

                    // Derive activation typehash based on the compact category for non-batch cases.
                    if iszero(usesBatch) {
                        // Prepare typehashes for Activation.
                        mstore(0, COMPACT_ACTIVATION_TYPEHASH)
                        mstore(0x20, BATCH_COMPACT_ACTIVATION_TYPEHASH)

                        // Retrieve respective typehash by index.
                        derivedActivationTypehash := mload(indexWords)
                    }

                    // Derive activation typehash for batch cases if typehash is not yet derived.
                    if iszero(derivedActivationTypehash) {
                        // Prepare typehashes for BatchActivation.
                        mstore(0, COMPACT_BATCH_ACTIVATION_TYPEHASH)
                        mstore(0x20, BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH)

                        // Retrieve respective typehash by index.
                        derivedActivationTypehash := mload(indexWords)
                    }

                    // Prepare compact typehashes.
                    mstore(0, COMPACT_TYPEHASH)
                    mstore(0x20, BATCH_COMPACT_TYPEHASH)

                    // Retrieve respective typehash by index.
                    derivedCompactTypehash := mload(indexWords)

                    // Leave the inline assembly scope early.
                    leave
                }

                // Copy the supplied compact witness from calldata.
                calldatacopy(categorySpecificEnd, witnessOffset, witnessLength)

                // Insert tokenPermissions typestring fragment.
                let tokenPermissionsFragmentStart := add(categorySpecificEnd, witnessLength)
                mstore(add(tokenPermissionsFragmentStart, 0x0f), TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO)
                mstore(tokenPermissionsFragmentStart, TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE)

                // Derive total length of typestring and store at start of memory.
                mstore(memLocation, sub(add(tokenPermissionsFragmentStart, 0x2f), memoryOffset))

                // Derive activation typehash.
                derivedActivationTypehash :=
                    keccak256(activationStart, sub(add(tokenPermissionsFragmentStart, 1), activationStart))

                // Derive compact typehash.
                derivedCompactTypehash :=
                    keccak256(categorySpecificStart, sub(add(tokenPermissionsFragmentStart, 1), categorySpecificStart))
            }

            // Execute internal assembly function and store derived typehashes.
            activationTypehash, compactTypehash :=
                writeWitnessAndGetTypehashes(memoryLocation, category, witness.offset, witness.length, usingBatch)
        }
    }

    /**
     * @notice Internal pure function for deriving the activation witness hash and
     * writing it to a specified memory location.
     * @param activationTypehash The derived activation typehash.
     * @param idOrIdsHash        Resource lock ID or uint256 representation of the hash of each ID.
     * @param claimHash          The claim hash.
     * @param memoryPointer      The memory pointer to the start of the memory region.
     * @param offset             The offset within the memory region to write the witness hash.
     */
    function deriveAndWriteWitnessHash(
        bytes32 activationTypehash,
        uint256 idOrIdsHash,
        bytes32 claimHash,
        uint256 memoryPointer,
        uint256 offset
    ) internal pure {
        assembly ("memory-safe") {
            // Retrieve and cache free memory pointer.
            let m := mload(0x40)

            // Prepare data for the witness hash: activationTypehash, idOrIdsHash & claimHash.
            mstore(0, activationTypehash)
            mstore(0x20, idOrIdsHash)
            mstore(0x40, claimHash)

            // Derive activation witness hash and write it to specified memory location.
            mstore(add(memoryPointer, offset), keccak256(0, 0x60))

            // Restore the free memory pointer.
            mstore(0x40, m)
        }
    }

    /**
     * @notice Internal pure function for deriving the CompactDeposit witness hash.
     * @param calldataOffset The offset of the CompactDeposit calldata.
     * @return witnessHash   The derived CompactDeposit witness hash.
     */
    function deriveCompactDepositWitnessHash(uint256 calldataOffset) internal pure returns (bytes32 witnessHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare the initial fragment of the witness typestring.
            mstore(m, PERMIT2_DEPOSIT_WITNESS_FRAGMENT_HASH)

            // Copy lockTag & recipient directly from calldata.
            // NOTE: none of these arguments are sanitized; the assumption is that they have to
            // match the signed values anyway, so *should* be fine not to sanitize them but could
            // optionally check that there are no dirty upper bits on any of them.
            calldatacopy(add(m, 0x20), calldataOffset, 0x40)

            // Derive the CompactDeposit witness hash from the prepared data.
            witnessHash := keccak256(m, 0x60)
        }
    }

    /**
     * @notice Internal pure function for inserting the CompactDeposit typestring
     * (used for deposits that do not involve a compact registration) into memory.
     * @param memoryLocation The memory pointer to the start of the typestring.
     */
    function insertCompactDepositTypestring(uint256 memoryLocation) internal pure {
        assembly ("memory-safe") {
            // Write the length of the typestring.
            mstore(memoryLocation, 0x76)

            // Write the data for the typestring.
            mstore(add(memoryLocation, 0x20), COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_ONE)
            mstore(add(memoryLocation, 0x40), COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_TWO)
            mstore(add(memoryLocation, 0x76), COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FOUR)
            mstore(add(memoryLocation, 0x60), COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_THREE)
        }
    }
}
