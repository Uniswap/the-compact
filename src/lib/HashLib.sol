// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocatedBatchTransfer, BatchClaim } from "../types/BatchClaims.sol";
import { AllocatedTransfer, Claim } from "../types/Claims.sol";
import { Component, ComponentsById, BatchClaimComponent } from "../types/Components.sol";
import {
    COMPACT_TYPEHASH,
    COMPACT_TYPESTRING_FRAGMENT_ONE,
    COMPACT_TYPESTRING_FRAGMENT_TWO,
    COMPACT_TYPESTRING_FRAGMENT_THREE,
    COMPACT_TYPESTRING_FRAGMENT_FOUR,
    COMPACT_TYPESTRING_FRAGMENT_FIVE,
    BATCH_COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_SIX,
    LOCK_TYPEHASH,
    MULTICHAIN_COMPACT_TYPEHASH,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SEVEN,
    ELEMENT_TYPEHASH
} from "../types/EIP712Types.sol";

import { ComponentLib } from "./ComponentLib.sol";

/**
 * @title HashLib
 * @notice Library contract implementing logic for deriving hashes as part of processing
 * claims, allocated transfers, and withdrawals, including deriving typehashes when
 * witness data is utilized and qualification hashes when claims have been qualified by
 * the allocator.
 */
library HashLib {
    using ComponentLib for Component[];
    using HashLib for uint256[2][];

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a transfer or withdrawal.
     * @param transfer   An AllocatedTransfer struct containing the transfer details.
     * @return claimHash The EIP-712 compliant message hash.
     */
    function toTransferClaimHash(AllocatedTransfer calldata transfer) internal view returns (bytes32 claimHash) {
        // Declare variable for total amount
        uint256 totalAmount = transfer.recipients.aggregate();

        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare initial components of message data: typehash, arbiter, & sponsor.
            mstore(m, COMPACT_TYPEHASH)
            mstore(add(m, 0x20), caller()) // arbiter: msg.sender
            mstore(add(m, 0x40), caller()) // sponsor: msg.sender

            // Subsequent data copied from calldata: nonce, expires, lockTag & token.
            // Deconstruct id into lockTag + token by inserting an empty word.
            calldatacopy(add(m, 0x60), add(transfer, 0x20), 0x4c)
            mstore(add(m, 0xc0), calldataload(add(transfer, 0x60))) // token
            mstore(add(m, 0xac), 0) // empty word between lockTag & token

            // Prepare final component of message data: aggregate amount.
            mstore(add(m, 0xe0), totalAmount)

            // Derive the message hash from the prepared data.
            claimHash := keccak256(m, 0x100)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a batch transfer or withdrawal.
     * @param transfer   An AllocatedBatchTransfer struct containing the transfer details.
     * @return           The EIP-712 compliant message hash.
     */
    function toBatchTransferClaimHash(AllocatedBatchTransfer calldata transfer) internal view returns (bytes32) {
        // Navigate to the transfer components array in calldata.
        ComponentsById[] calldata transfers = transfer.transfers;

        // Retrieve the length of the commitments array.
        uint256 totalLocks = transfers.length;

        // Allocate working memory for hashing operations.
        (uint256 ptr, uint256 hashesPtr) = _allocateCommitmentsHashingMemory(totalLocks);

        unchecked {
            // Cache lock-specific data start memory pointer location.
            uint256 lockDataStart = ptr + 0x20;

            // Iterate over each transfer component.
            for (uint256 i = 0; i < totalLocks; ++i) {
                // Navigate to the current transfer component.
                ComponentsById calldata transferComponent = transfers[i];

                // Retrieve the id from the current transfer component.
                uint256 id = transferComponent.id;

                // Declare a variable for the total amount.
                uint256 totalAmount = transferComponent.portions.aggregate();

                assembly ("memory-safe") {
                    // Copy data on aggregate committed locks from derived values.
                    // Deconstruct id into lockTag + token by inserting an empty word.
                    mstore(lockDataStart, id) // lockTag
                    mstore(add(lockDataStart, 0x20), id) // token
                    mstore(add(lockDataStart, 0x0c), 0) // empty word between lockTag & token
                    mstore(add(lockDataStart, 0x40), totalAmount)

                    // Hash the prepared elements and store at current position.
                    mstore(add(hashesPtr, shl(5, i)), keccak256(ptr, 0x80))
                }
            }
        }

        // Declare a variable for the commitments hash.
        uint256 commitmentsHash;
        assembly ("memory-safe") {
            // Derive the commitments hash using the prepared lock hashes data.
            commitmentsHash := keccak256(hashesPtr, shl(5, totalLocks))
        }

        // Derive message hash from transfer data and commitments hash.
        return _toBatchTransferClaimHashUsingCommitmentsHash(transfer, commitmentsHash);
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a claim with or without a witness.
     * @param claimPointer Pointer to the claim location in calldata.
     * @return claimHash   The EIP-712 compliant message hash.
     * @return typehash    The EIP-712 typehash.
     */
    function toClaimHash(Claim calldata claimPointer) internal view returns (bytes32 claimHash, bytes32 typehash) {
        assembly ("memory-safe") {
            for { } 1 { } {
                // Retrieve the free memory pointer; memory will be left dirtied.
                let m := mload(0x40)

                // Derive the pointer to the witness typestring.
                let witnessTypestringPtr := add(claimPointer, calldataload(add(claimPointer, 0xc0)))

                // Retrieve the length of the witness typestring.
                let witnessTypestringLength := calldataload(witnessTypestringPtr)

                if iszero(witnessTypestringLength) {
                    // Prepare initial components of message data: typehash & arbiter.
                    mstore(m, COMPACT_TYPEHASH)
                    mstore(add(m, 0x20), caller()) // arbiter: msg.sender

                    // Clear sponsor memory location as an added precaution so that
                    // upper bits of sponsor do not need to be copied from calldata.
                    mstore(add(m, 0x40), 0)

                    // Next data segment copied from calldata: sponsor, nonce & expires.
                    calldatacopy(add(m, 0x4c), add(claimPointer, 0x4c), 0x54)

                    // Prepare final components of message data: lockTag, token and amount.
                    // Deconstruct id into lockTag + token by inserting an empty word.
                    mstore(add(m, 0xa0), calldataload(add(claimPointer, 0xe0))) // lockTag
                    mstore(add(m, 0xac), 0) // last 20 bytes of lockTag and first 12 of token
                    calldatacopy(add(m, 0xcc), add(claimPointer, 0xec), 0x34) // token + amount

                    // Derive the message hash from the prepared data.
                    claimHash := keccak256(m, 0x100)

                    // Set Compact typehash
                    typehash := COMPACT_TYPEHASH

                    break
                }

                // Prepare first component of typestring from five one-word fragments.
                mstore(m, COMPACT_TYPESTRING_FRAGMENT_ONE)
                mstore(add(m, 0x20), COMPACT_TYPESTRING_FRAGMENT_TWO)
                mstore(add(m, 0x40), COMPACT_TYPESTRING_FRAGMENT_THREE)
                mstore(add(m, 0x6b), COMPACT_TYPESTRING_FRAGMENT_FIVE)
                mstore(add(m, 0x60), COMPACT_TYPESTRING_FRAGMENT_FOUR)

                // Copy remaining typestring data from calldata to memory.
                let witnessStart := add(m, 0x8b)
                calldatacopy(witnessStart, add(0x20, witnessTypestringPtr), witnessTypestringLength)

                // Prepare closing ")" parenthesis at the very end of the memory region.
                mstore8(add(witnessStart, witnessTypestringLength), 0x29)

                // Derive the typehash from the prepared data.
                typehash := keccak256(m, add(0x8c, witnessTypestringLength))

                // Prepare initial components of message data: typehash & arbiter.
                mstore(m, typehash)
                mstore(add(m, 0x20), caller()) // arbiter: msg.sender

                // Clear sponsor memory location as an added precaution so that
                // upper bits of sponsor do not need to be copied from calldata.
                mstore(add(m, 0x40), 0)

                // Next data segment copied from calldata: sponsor, nonce, expires.
                calldatacopy(add(m, 0x4c), add(claimPointer, 0x4c), 0x54)

                // Prepare final components of message data: lockTag, token, amount & witness.
                // Deconstruct id into lockTag + token by inserting an empty word.
                mstore(add(m, 0xa0), calldataload(add(claimPointer, 0xe0))) // lockTag
                mstore(add(m, 0xac), 0) // last 20 bytes of lockTag and first 12 of token
                calldatacopy(add(m, 0xcc), add(claimPointer, 0xec), 0x34) // token + amount

                mstore(add(m, 0x100), calldataload(add(claimPointer, 0xa0))) // witness

                // Derive the message hash from the prepared data.
                claimHash := keccak256(m, 0x120)
                break
            }
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a batch claim with or without a witness.
     * @param claimPointer    Pointer to the batch claim location in calldata.
     * @param commitmentsHash The EIP-712 hash of the Lock[] commitments array.
     * @return claimHash      The EIP-712 compliant message hash.
     * @return typehash       The EIP-712 typehash.
     */
    function toBatchClaimHash(BatchClaim calldata claimPointer, uint256 commitmentsHash)
        internal
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        assembly ("memory-safe") {
            for { } 1 { } {
                // Retrieve the free memory pointer; memory will be left dirtied.
                let m := mload(0x40)

                // Derive the pointer to the witness typestring.
                let witnessTypestringPtr := add(claimPointer, calldataload(add(claimPointer, 0xc0)))

                // Retrieve the length of the witness typestring.
                let witnessTypestringLength := calldataload(witnessTypestringPtr)

                if iszero(witnessTypestringLength) {
                    // Prepare initial components of message data: typehash & arbiter.
                    mstore(m, BATCH_COMPACT_TYPEHASH)
                    mstore(add(m, 0x20), caller()) // arbiter: msg.sender

                    // Clear sponsor memory location as an added precaution so that
                    // upper bits of sponsor do not need to be copied from calldata.
                    mstore(add(m, 0x40), 0)

                    // Next data segment copied from calldata: sponsor, nonce, expires.
                    calldatacopy(add(m, 0x4c), add(claimPointer, 0x4c), 0x54)

                    // Prepare final component of message data: commitmentsHash.
                    mstore(add(m, 0xa0), commitmentsHash)

                    // Derive the message hash from the prepared data.
                    claimHash := keccak256(m, 0xc0)

                    // Set BatchCompact typehash
                    typehash := BATCH_COMPACT_TYPEHASH

                    break
                }

                // Prepare first component of typestring from six one-word fragments.
                mstore(m, BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE)
                mstore(add(m, 0x20), BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO)
                mstore(add(m, 0x40), BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE)
                mstore(add(m, 0x60), BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR)
                mstore(add(m, 0x88), BATCH_COMPACT_TYPESTRING_FRAGMENT_SIX)
                mstore(add(m, 0x80), BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE)

                // Copy remaining typestring data from calldata to memory.
                let witnessStart := add(m, 0xa8)
                calldatacopy(witnessStart, add(0x20, witnessTypestringPtr), witnessTypestringLength)

                // Prepare closing ")" parenthesis at the very end of the memory region.
                mstore8(add(witnessStart, witnessTypestringLength), 0x29)

                // Derive the typehash from the prepared data.
                typehash := keccak256(m, add(0xa9, witnessTypestringLength))

                // Prepare initial components of message data: typehash & arbiter.
                mstore(m, typehash)
                mstore(add(m, 0x20), caller()) // arbiter: msg.sender

                // Clear sponsor memory location as an added precaution so that
                // upper bits of sponsor do not need to be copied from calldata.
                mstore(add(m, 0x40), 0)

                // Next data segment copied from calldata: sponsor, nonce, expires.
                calldatacopy(add(m, 0x4c), add(claimPointer, 0x4c), 0x54)

                // Prepare final components of message data: commitmentsHash & witness.
                mstore(add(m, 0xa0), commitmentsHash)
                mstore(add(m, 0xc0), calldataload(add(claimPointer, 0xa0))) // witness

                // Derive the message hash from the prepared data.
                claimHash := keccak256(m, 0xe0)

                break
            }
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a multichain claim with or without a witness.
     * @param claim                     Pointer to the claim location in calldata.
     * @param additionalOffset          Additional offset from claim pointer to ID from most compact case.
     * @param elementTypehash           The element typehash.
     * @param multichainCompactTypehash The multichain compact typehash.
     * @param commitmentsHash           The EIP-712 hash of the Lock[] commitments array.
     * @return claimHash                The EIP-712 compliant message hash.
     */
    function toMultichainClaimHash(
        uint256 claim,
        uint256 additionalOffset,
        bytes32 elementTypehash,
        bytes32 multichainCompactTypehash,
        uint256 commitmentsHash
    ) internal view returns (bytes32 claimHash) {
        // Derive the element hash for the current element.
        bytes32 elementHash = _toElementHash(claim, elementTypehash, commitmentsHash);

        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Write the derived element hash to memory.
            mstore(m, elementHash)

            // Derive the pointer to the additional chains and retrieve the length.
            let additionalChainsPtr := add(claim, calldataload(add(add(claim, additionalOffset), 0xa0)))
            let additionalChainsLength := shl(5, calldataload(additionalChainsPtr))

            // Copy the element hashes in the additional chains array from calldata to memory.
            calldatacopy(add(m, 0x20), add(0x20, additionalChainsPtr), additionalChainsLength)

            // Derive hash of element hashes from prepared data and write it to memory.
            mstore(add(m, 0x80), keccak256(m, add(0x20, additionalChainsLength)))

            // Prepare next component of message data: multichain compact typehash.
            mstore(m, multichainCompactTypehash)

            // Clear sponsor memory location as an added precaution so that
            // upper bits of sponsor do not need to be copied from calldata.
            mstore(add(m, 0x20), 0)

            // Next data segment copied from calldata: sponsor, nonce, expires.
            calldatacopy(add(m, 0x2c), add(claim, 0x4c), 0x54)

            // Derive the message hash from the prepared data.
            claimHash := keccak256(m, 0xa0)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * an exogenous multichain claim with or without a witness.
     * @param claim                     Pointer to the claim location in calldata.
     * @param additionalOffset          Additional offset from claim pointer to ID from most compact case.
     * @param elementTypehash           The element typehash.
     * @param multichainCompactTypehash The multichain compact typehash.
     * @param commitmentsHash           The EIP-712 hash of the Lock[] commitments array.
     * @return claimHash                The EIP-712 compliant message hash.
     */
    function toExogenousMultichainClaimHash(
        uint256 claim,
        uint256 additionalOffset,
        bytes32 elementTypehash,
        bytes32 multichainCompactTypehash,
        uint256 commitmentsHash
    ) internal view returns (bytes32 claimHash) {
        // Derive the element hash for the current element.
        bytes32 elementHash = _toElementHash(claim, elementTypehash, commitmentsHash);

        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Derive the pointer to the additional chains and retrieve the length.
            let claimWithAdditionalOffset := add(claim, additionalOffset)
            let additionalChainsPtr := add(claim, calldataload(add(claimWithAdditionalOffset, 0xa0)))

            // Retrieve the length of the additional chains array.
            let additionalChainsLength := shl(5, calldataload(additionalChainsPtr))

            // Retrieve the chain index from calldata.
            let chainIndex := shl(5, calldataload(add(claimWithAdditionalOffset, 0xc0)))

            // Initialize an offset indicating whether a matching chain index has been located.
            let extraOffset := 0

            // Move the additional chains pointer forward by a word to begin with data segment.
            additionalChainsPtr := add(0x20, additionalChainsPtr)

            // Iterate over the additional chains array and store each element hash in memory.
            for { let i := 0 } lt(i, additionalChainsLength) { i := add(i, 0x20) } {
                mstore(add(add(m, i), extraOffset), calldataload(add(additionalChainsPtr, i)))
                // If current index matches chain index, store derived hash and increment offset.
                if eq(i, chainIndex) {
                    extraOffset := 0x20
                    mstore(add(m, add(i, extraOffset)), elementHash)
                }
            }

            // Ensure provided chain index & additional chains array applied the current element.
            if iszero(extraOffset) {
                // Revert ChainIndexOutOfRange()
                mstore(0, 0x71515b9a)
                revert(0x1c, 0x04)
            }

            // Derive the hash of the element hashes from the prepared data and write it to memory.
            mstore(add(m, 0x80), keccak256(m, add(0x20, additionalChainsLength)))

            // Prepare next component of message data: multichain compact typehash.
            mstore(m, multichainCompactTypehash)

            // Clear sponsor memory location as an added precaution so that
            // upper bits of sponsor do not need to be copied from calldata.
            mstore(add(m, 0x20), 0)

            // Next data segment copied from calldata: sponsor, nonce, expires.
            calldatacopy(add(m, 0x2c), add(claim, 0x4c), 0x54)

            // Derive the message hash from the prepared data.
            claimHash := keccak256(m, 0xa0)
        }
    }

    /**
     * @notice Internal pure function for deriving the EIP-712 typehashes for
     * multichain claims with or without a witness.
     * @param claimPointer                      Pointer to the claim location in calldata.
     * @return elementTypehash           The element typehash.
     * @return multichainCompactTypehash The multichain compact typehash.
     */
    function toMultichainTypehashes(uint256 claimPointer)
        internal
        pure
        returns (bytes32 elementTypehash, bytes32 multichainCompactTypehash)
    {
        assembly ("memory-safe") {
            for { } 1 { } {
                // Retrieve the free memory pointer; memory will be left dirtied.
                let m := mload(0x40)

                // Derive the pointer to the witness typestring and retrieve the length.
                let witnessTypestringPtr := add(claimPointer, calldataload(add(claimPointer, 0xc0)))
                let witnessTypestringLength := calldataload(witnessTypestringPtr)

                if iszero(witnessTypestringLength) {
                    elementTypehash := ELEMENT_TYPEHASH
                    multichainCompactTypehash := MULTICHAIN_COMPACT_TYPEHASH

                    break
                }
                // Prepare the first five fragments of the multichain compact typehash.
                mstore(m, MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE)
                mstore(add(m, 0x20), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO)
                mstore(add(m, 0x40), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE)
                mstore(add(m, 0x60), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR)
                mstore(add(m, 0x80), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE)
                mstore(add(m, 0xb8), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SEVEN)
                mstore(add(m, 0xa0), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX)

                // Copy remaining witness typestring from calldata to memory.
                let witnessStart := add(m, 0xd8)
                calldatacopy(witnessStart, add(0x20, witnessTypestringPtr), witnessTypestringLength)

                // Prepare closing ")" parenthesis at the very end of the memory region.
                mstore8(add(witnessStart, witnessTypestringLength), 0x29)

                // Derive the element typehash and multichain compact typehash from the prepared data.
                elementTypehash := keccak256(add(m, 0x53), add(0x86, witnessTypestringLength))
                multichainCompactTypehash := keccak256(m, add(0xd9, witnessTypestringLength))
                break
            }
        }
    }

    /**
     * @notice Internal pure function for deriving the EIP-712 message hash for
     * a commitments array when the claim in question contains a single lock.
     * @param claim            Pointer to the claim location in calldata.
     * @return commitmentsHash The EIP-712 hash of the Lock[] commitments array.
     */
    function toCommitmentsHashFromSingleLock(uint256 claim) internal pure returns (uint256 commitmentsHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Place the lock typehash into the start of memory.
            mstore(m, LOCK_TYPEHASH)

            // Deconstruct id into lockTag + token by inserting an empty word.
            mstore(add(m, 0x20), calldataload(add(claim, 0xe0))) // lockTag
            mstore(add(m, 0x2c), 0) // empty word between lockTag & token
            calldatacopy(add(m, 0x4c), add(claim, 0xec), 0x34) // token & amount

            // Derive first lock commitment hash and place in scratch space.
            mstore(0, keccak256(m, 0x80))

            // Hash again to derive commitmentsHash.
            commitmentsHash := keccak256(0, 0x20)
        }
    }

    /**
     * @notice Internal pure function for deriving the commitments hash of a provided
     * idsAndAmounts array.
     * @param idsAndAmounts      An array of ids and amounts.
     * @param replacementAmounts An array of replacement amounts.
     * @return commitmentsHash   The EIP-712 hash of the Lock[] commitments array.
     * @dev This function expects that the calldata of idsAndAmounts will have bounds
     * checked elsewhere; using it without this check occurring elsewhere can result in
     * erroneous hash values. This function also expects that replacementAmounts.length
     * equals idsAndAmounts.length and will break if the invariant is not upheld.
     */
    function toCommitmentsHash(uint256[2][] calldata idsAndAmounts, uint256[] memory replacementAmounts)
        internal
        pure
        returns (bytes32 commitmentsHash)
    {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let ptr := mload(0x40)

            // Temporarily allocate four words of memory.
            let hashesPtr := add(ptr, 0x80)

            // Write lock typehash to first word of memory.
            mstore(ptr, LOCK_TYPEHASH)

            // Cache various memory pointer data locations.
            let replacementDataStart := add(replacementAmounts, 0x20)
            let lockDataStart := add(ptr, 0x20)

            // Iterate over the idsAndAmounts array, splicing in the replacement amounts.
            for { let i := 0 } lt(i, idsAndAmounts.length) { i := add(i, 1) } {
                // Retrieve the id from the relevant segment of calldata.
                let id := calldataload(add(idsAndAmounts.offset, shl(6, i)))

                // Copy id from calldata to next two words of allocated memory region.
                // Deconstruct id into lockTag + token by inserting an empty word.
                mstore(lockDataStart, id) // lockTag
                mstore(add(lockDataStart, 0x20), id) // token
                mstore(add(lockDataStart, 0x0c), 0) // empty word between lockTag & token

                // Copy amount from replacement data to last word of allocated memory region.
                mstore(add(lockDataStart, 0x40), mload(add(replacementDataStart, shl(5, i))))

                // Derive hash of allocated memory & write to next hashes memory region.
                mstore(add(hashesPtr, shl(5, i)), keccak256(ptr, 0x80))
            }

            // Compute hash of derived hashes that have been stored in memory.
            commitmentsHash := keccak256(hashesPtr, shl(5, idsAndAmounts.length))
        }
    }

    /**
     * @notice Internal pure function for deriving the commitments hash based on the
     * ids and amounts of a given batch claim component.
     * @param claims           An array of BatchClaimComponent structs.
     * @return commitmentsHash The EIP-712 hash of the Lock[] commitments array.
     */
    function toCommitmentsHash(BatchClaimComponent[] calldata claims) internal pure returns (uint256 commitmentsHash) {
        // Retrieve the total number of committed locks in the batch claim.
        uint256 totalLocks = claims.length;

        // Allocate working memory for hashing operations.
        (uint256 ptr, uint256 hashesPtr) = _allocateCommitmentsHashingMemory(totalLocks);

        unchecked {
            // Cache lock-specific data start memory pointer location.
            uint256 lockDataStart = ptr + 0x20;

            // Iterate over the claims array.
            for (uint256 i = 0; i < totalLocks; ++i) {
                // Navigate to the current claim component in calldata.
                BatchClaimComponent calldata claimComponent = claims[i];

                assembly ("memory-safe") {
                    // Copy data on committed lock from relevant segment of calldata.
                    // Deconstruct id into lockTag + token by inserting an empty word.
                    mstore(lockDataStart, calldataload(claimComponent)) // lockTag
                    calldatacopy(add(lockDataStart, 0x2c), add(claimComponent, 0x0c), 0x34) // token + amount
                    mstore(add(lockDataStart, 0x0c), 0) // empty word between lockTag & token

                    // Hash the elements in scratch space and store at current position.
                    mstore(add(hashesPtr, shl(5, i)), keccak256(ptr, 0x80))
                }
            }
        }

        assembly ("memory-safe") {
            // Derive the commitments hash using the prepared lock hashes data.
            commitmentsHash := keccak256(hashesPtr, shl(5, totalLocks))
        }
    }

    /**
     * @notice Internal pure function for retrieving an EIP-712 claim hash. Used when a
     * compact is registered with a directly corresponding deposit.
     * @param sponsor    The account sponsoring the registered compact.
     * @param tokenId    Identifier for the associated token & lock.
     * @param amount     The associated number of tokens on the compact.
     * @param arbiter    Account tasked with initiating claims against the compact.
     * @param nonce      Allocator replay protection nonce.
     * @param expires    Timestamp when the claim expires.
     * @param typehash   Typehash of the entire compact, including witness subtypes.
     * @param witness    EIP712 structured hash of witness.
     * @return claimHash The corresponding EIP-712 message hash.
     */
    function toClaimHashFromDeposit(
        address sponsor,
        uint256 tokenId,
        uint256 amount,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) internal pure returns (bytes32 claimHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare the inputs to the message hash.
            mstore(m, typehash)
            mstore(add(m, 0x20), arbiter)
            mstore(add(m, 0x40), sponsor)
            mstore(add(m, 0x60), nonce)
            mstore(add(m, 0x80), expires)
            mstore(add(m, 0xa0), tokenId) // lockTag
            mstore(add(m, 0xc0), tokenId) // token
            mstore(add(m, 0xac), 0) // empty word between lockTag and token
            mstore(add(m, 0xe0), amount)
            mstore(add(m, 0x100), witness)

            // Derive the message hash from the prepared data.
            // Do not include witness hash for no-witness case.
            claimHash := keccak256(m, add(0x100, shl(5, iszero(eq(typehash, COMPACT_TYPEHASH)))))
        }
    }

    /**
     * @notice Internal pure function for retrieving an EIP-712 claim hash for a batch compact.
     * Used when a batch compact is registered with a directly corresponding set of deposits.
     * @param sponsor            The account sponsoring the claimed compact.
     * @param idsAndAmounts      An array with IDs and aggregate transfer amounts.
     * @param arbiter            Account tasked with initiating claims against the compact.
     * @param nonce              Allocator replay protection nonce.
     * @param expires            Timestamp when the compact expires.
     * @param typehash           Typehash of the entire compact, including witness subtypes.
     * @param witness            EIP712 structured hash of witness.
     * @param replacementAmounts An array of replacement amounts.
     * @return messageHash       The corresponding EIP-712 messagehash.
     */
    function toClaimHashFromBatchDeposit(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        uint256[] memory replacementAmounts
    ) internal pure returns (bytes32 messageHash) {
        // Derive the commitments hash using the provided ids and amounts array.
        bytes32 commitmentsHash = idsAndAmounts.toCommitmentsHash(replacementAmounts);

        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare the inputs to the message hash.
            mstore(m, typehash)
            mstore(add(m, 0x20), arbiter)
            mstore(add(m, 0x40), sponsor)
            mstore(add(m, 0x60), nonce)
            mstore(add(m, 0x80), expires)
            mstore(add(m, 0xa0), commitmentsHash)
            mstore(add(m, 0xc0), witness)

            // Derive the message hash from the prepared data.
            // Do not include witness hash for no-witness case.
            messageHash := keccak256(m, add(0xc0, shl(5, iszero(eq(typehash, BATCH_COMPACT_TYPEHASH)))))
        }
    }

    /**
     * @notice Private view function for deriving the EIP-712 message hash for
     * a specific element on a multichain claim with or without a witness.
     * @param claim                     Pointer to the claim location in calldata.
     * @param elementTypehash           The element typehash.
     * @param commitmentsHash           The EIP-712 hash of the Lock[] commitments array.
     * @return elementHash              The EIP-712 compliant element hash.
     */
    function _toElementHash(uint256 claim, bytes32 elementTypehash, uint256 commitmentsHash)
        private
        view
        returns (bytes32 elementHash)
    {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare data: element typehash, arbiter, chainid, commitmentsHash, & witness.
            mstore(m, elementTypehash)
            mstore(add(m, 0x20), caller()) // arbiter
            mstore(add(m, 0x40), chainid())
            mstore(add(m, 0x60), commitmentsHash)
            mstore(add(m, 0x80), calldataload(add(claim, 0xa0))) // witness

            // Derive the element hash from the prepared data and write it to memory.
            // Omit the witness if the default "no-witness" typehash is provided.
            elementHash := keccak256(m, add(0x80, shl(5, iszero(eq(elementTypehash, ELEMENT_TYPEHASH)))))
        }
    }

    /**
     * @notice Private view function for deriving the EIP-712 message hash for
     * a batch transfer or withdrawal once a commitments hash is available.
     * @param transfer        An AllocatedBatchTransfer struct containing the transfer details.
     * @param commitmentsHash A hash of the commitments array.
     * @return claimHash      The EIP-712 compliant message hash.
     */
    function _toBatchTransferClaimHashUsingCommitmentsHash(
        AllocatedBatchTransfer calldata transfer,
        uint256 commitmentsHash
    ) private view returns (bytes32 claimHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare initial components of message data: typehash, arbiter, & sponsor.
            mstore(m, BATCH_COMPACT_TYPEHASH)
            mstore(add(m, 0x20), caller()) // arbiter: msg.sender
            mstore(add(m, 0x40), caller()) // sponsor: msg.sender

            // Next data segment copied from calldata: nonce & expires.
            mstore(add(m, 0x60), calldataload(add(transfer, 0x20))) // nonce
            mstore(add(m, 0x80), calldataload(add(transfer, 0x40))) // expires

            // Prepare final component of message data: commitmentsHash.
            mstore(add(m, 0xa0), commitmentsHash)

            // Derive the message hash from the prepared data.
            claimHash := keccak256(m, 0xc0)
        }
    }

    /**
     * @notice Private pure function for allocating a memory region used to derive both
     * individual commitment hashes (including placing the typehash in memory) as well
     * as an aggregate commitments hash.
     * @param totalLocks The total number of locks used to derive the commitments hash.
     * @return ptr       A pointer to the region where inputs are prepared for each hash.
     * @return hashesPtr A pointer to the region where each derived hash will be prepared.
     */
    function _allocateCommitmentsHashingMemory(uint256 totalLocks)
        private
        pure
        returns (uint256 ptr, uint256 hashesPtr)
    {
        assembly ("memory-safe") {
            // Retrieve the current free memory pointer.
            ptr := mload(0x40)

            // Write lock typehash to first word of memory.
            mstore(ptr, LOCK_TYPEHASH)

            // Allocate four words of memory for deriving hashes.
            hashesPtr := add(ptr, 0x80)

            // Allocate additional memory based on the total committed locks.
            mstore(0x40, add(hashesPtr, shl(5, totalLocks)))
        }
    }
}
