// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocatedBatchTransfer } from "../types/BatchClaims.sol";
import { AllocatedTransfer } from "../types/Claims.sol";
import { TransferComponent, Component, ComponentsById, BatchClaimComponent } from "../types/Components.sol";
import {
    COMPACT_TYPEHASH,
    COMPACT_TYPESTRING_FRAGMENT_ONE,
    COMPACT_TYPESTRING_FRAGMENT_TWO,
    COMPACT_TYPESTRING_FRAGMENT_THREE,
    COMPACT_TYPESTRING_FRAGMENT_FOUR,
    BATCH_COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX,
    PERMIT2_DEPOSIT_WITNESS_FRAGMENT_HASH
} from "../types/EIP712Types.sol";

import { EfficiencyLib } from "./EfficiencyLib.sol";
import { TransferFunctionCastLib } from "./TransferFunctionCastLib.sol";

/**
 * @title HashLib
 * @notice Library contract implementing logic for deriving hashes as part of processing
 * claims, allocated transfers, and withdrawals, including deriving typehashes when
 * witness data is utilized and qualification hashes when claims have been qualified by
 * the allocator.
 */
library HashLib {
    using EfficiencyLib for bool;
    using EfficiencyLib for uint256;
    using HashLib for uint256;
    using HashLib for uint256[2][];
    using HashLib for AllocatedBatchTransfer;

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a transfer or withdrawal.
     * @param transfer     An AllocatedTransfer struct containing the transfer details.
     * @return messageHash The EIP-712 compliant message hash.
     */
    function toTransferMessageHash(AllocatedTransfer calldata transfer) internal view returns (bytes32 messageHash) {
        // Declare variables for tracking, total amount, current amount, and errors.
        uint256 amount = 0;
        uint256 currentAmount;
        uint256 errorBuffer;

        // Navigate to the components array in calldata.
        Component[] calldata recipients = transfer.recipients;

        // Retrieve the length of the array.
        uint256 totalRecipients = recipients.length;

        unchecked {
            // Iterate over each component.
            for (uint256 i = 0; i < totalRecipients; ++i) {
                // Retrieve the current amount of the component.
                currentAmount = recipients[i].amount;

                // Add current amount to total amount and check for overflow.
                amount += currentAmount;
                errorBuffer |= (amount < currentAmount).asUint256();
            }
        }

        assembly ("memory-safe") {
            // Revert if an arithmetic overflow was detected.
            if errorBuffer {
                // Revert Panic(0x11) (arithmetic overflow)
                mstore(0, 0x4e487b71)
                mstore(0x20, 0x11)
                revert(0x1c, 0x24)
            }

            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare initial components of message data: typehash, arbiter, & sponsor.
            mstore(m, COMPACT_TYPEHASH)
            mstore(add(m, 0x20), caller()) // arbiter: msg.sender
            mstore(add(m, 0x40), caller()) // sponsor: msg.sender

            // Subsequent data copied from calldata: nonce, expires & id.
            calldatacopy(add(m, 0x60), add(transfer, 0x20), 0x60)

            // Prepare final component of message data: aggregate amount.
            mstore(add(m, 0xc0), amount)

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0xe0)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a batch transfer or withdrawal.
     * @param transfer     An AllocatedBatchTransfer struct containing the transfer details.
     * @return messageHash The EIP-712 compliant message hash.
     */
    function toBatchTransferMessageHash(AllocatedBatchTransfer calldata transfer) internal view returns (bytes32) {
        // Navigate to the transfer components array in calldata.
        ComponentsById[] calldata transfers = transfer.transfers;

        // Retrieve the length of the array.
        uint256 totalIds = transfers.length;

        // Allocate memory region for ids and amounts.
        bytes memory idsAndAmounts = new bytes(totalIds * 0x40);

        // Declare a buffer for arithmetic errors.
        uint256 errorBuffer;

        unchecked {
            // Iterate over each transfer component.
            for (uint256 i = 0; i < totalIds; ++i) {
                // Navigate to the current transfer component.
                ComponentsById calldata transferComponent = transfers[i];

                // Retrieve the id from the current transfer component.
                uint256 id = transferComponent.id;

                // Declare a variable for the aggregate amount.
                uint256 amount = 0;

                // Declare a variable for the current amount.
                uint256 singleAmount;

                // Navigate to the portions array in the current transfer component.
                Component[] calldata portions = transferComponent.portions;

                // Retrieve the length of the portions array.
                uint256 portionsLength = portions.length;

                // Iterate over each portion.
                for (uint256 j = 0; j < portionsLength; ++j) {
                    // Retrieve the current amount of the portion.
                    singleAmount = portions[j].amount;

                    // Add current amount to aggregate amount and check for overflow.
                    amount += singleAmount;
                    errorBuffer |= (amount < singleAmount).asUint256();
                }

                assembly ("memory-safe") {
                    // Derive offset to id and amount based on total components.
                    let extraOffset := add(add(idsAndAmounts, 0x20), shl(6, i))

                    // Store the id and aggregate amount at the derived offset.
                    mstore(extraOffset, id)
                    mstore(add(extraOffset, 0x20), amount)
                }
            }
        }

        // Declare a variable for the ids and amounts hash.
        uint256 idsAndAmountsHash;
        assembly ("memory-safe") {
            // Revert if an arithmetic overflow was detected.
            if errorBuffer {
                // Revert Panic(0x11) (arithmetic overflow)
                mstore(0, 0x4e487b71)
                mstore(0x20, 0x11)
                revert(0x1c, 0x24)
            }

            // Derive the ids and amounts hash from the stored data.
            idsAndAmountsHash := keccak256(add(idsAndAmounts, 0x20), mload(idsAndAmounts))
        }

        // Derive message hash from transfer data and idsAndAmounts hash.
        return toBatchTransferMessageHashUsingIdsAndAmountsHash(transfer, idsAndAmountsHash);
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a claim with a witness.
     * @param claim               Pointer to the claim location in calldata.
     * @return messageHash        The EIP-712 compliant message hash.
     * @return typehash           The EIP-712 typehash.
     */
    function toMessageHashWithWitness(uint256 claim) internal view returns (bytes32 messageHash, bytes32 typehash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Derive the pointer to the witness typestring.
            let witnessTypestringPtr := add(claim, calldataload(add(claim, 0xc0)))

            // Retrieve the length of the witness typestring.
            let witnessTypestringLength := calldataload(witnessTypestringPtr)

            // Prepare first component of typestring from four one-word fragments.
            mstore(m, COMPACT_TYPESTRING_FRAGMENT_ONE)
            mstore(add(m, 0x20), COMPACT_TYPESTRING_FRAGMENT_TWO)
            mstore(add(m, 0x58), COMPACT_TYPESTRING_FRAGMENT_FOUR)
            mstore(add(m, 0x40), COMPACT_TYPESTRING_FRAGMENT_THREE)

            // Copy remaining typestring data from calldata to memory.
            let witnessStart := add(m, 0x78)
            calldatacopy(witnessStart, add(0x20, witnessTypestringPtr), witnessTypestringLength)

            // Prepare closing ")" parenthesis at the very end of the memory region.
            mstore8(add(witnessStart, witnessTypestringLength), 0x29)

            // Derive the typehash from the prepared data.
            typehash := keccak256(m, add(0x79, witnessTypestringLength))

            // Prepare initial components of message data: typehash & arbiter.
            mstore(m, typehash)
            mstore(add(m, 0x20), caller()) // arbiter: msg.sender

            // Next data segment copied from calldata: sponsor, nonce, expires.
            calldatacopy(add(m, 0x40), add(claim, 0x40), 0x60)

            // Prepare final components of message data: id, amount, & witness.
            mstore(add(m, 0xa0), calldataload(add(claim, 0xe0))) // id
            mstore(add(m, 0xc0), calldataload(add(claim, 0x100))) // amount
            mstore(add(m, 0xe0), calldataload(add(claim, 0xa0))) // witness

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0x100)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a batch transfer or withdrawal once an idsAndAmounts hash is available.
     * @param transfer          An AllocatedBatchTransfer struct containing the transfer details.
     * @param idsAndAmountsHash A hash of the ids and amounts.
     * @return messageHash      The EIP-712 compliant message hash.
     */
    function toBatchTransferMessageHashUsingIdsAndAmountsHash(
        AllocatedBatchTransfer calldata transfer,
        uint256 idsAndAmountsHash
    ) internal view returns (bytes32 messageHash) {
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

            // Prepare final component of message data: idsAndAmountsHash.
            mstore(add(m, 0xa0), idsAndAmountsHash)

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0xc0)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a batch transfer or withdrawal.
     * @param claim             Pointer to the claim location in calldata.
     * @param idsAndAmountsHash A hash of the ids and amounts.
     * @return messageHash      The EIP-712 compliant message hash.
     */
    function toBatchMessageHash(uint256 claim, uint256 idsAndAmountsHash) internal view returns (bytes32 messageHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare initial components of message data: typehash & arbiter.
            mstore(m, BATCH_COMPACT_TYPEHASH)
            mstore(add(m, 0x20), caller()) // arbiter: msg.sender

            // Next data segment copied from calldata: sponsor, nonce, expires.
            calldatacopy(add(m, 0x40), add(claim, 0x40), 0x60) // sponsor, nonce, expires

            // Prepare final component of message data: idsAndAmountsHash.
            mstore(add(m, 0xa0), idsAndAmountsHash)

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0xc0)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a batch claim with a witness.
     * @param claim             Pointer to the claim location in calldata.
     * @param idsAndAmountsHash A hash of the ids and amounts.
     * @return messageHash      The EIP-712 compliant message hash.
     * @return typehash         The EIP-712 typehash.
     */
    function toBatchClaimWithWitnessMessageHash(uint256 claim, uint256 idsAndAmountsHash)
        internal
        view
        returns (bytes32 messageHash, bytes32 typehash)
    {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Derive the pointer to the witness typestring.
            let witnessTypestringPtr := add(claim, calldataload(add(claim, 0xc0)))

            // Retrieve the length of the witness typestring.
            let witnessTypestringLength := calldataload(witnessTypestringPtr)

            // Prepare first component of typestring from four one-word fragments.
            mstore(m, BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE)
            mstore(add(m, 0x20), BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO)
            mstore(add(m, 0x5e), BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR)
            mstore(add(m, 0x40), BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE)

            // Copy remaining typestring data from calldata to memory.
            let witnessStart := add(m, 0x7e)
            calldatacopy(witnessStart, add(0x20, witnessTypestringPtr), witnessTypestringLength)

            // Prepare closing ")" parenthesis at the very end of the memory region.
            mstore8(add(witnessStart, witnessTypestringLength), 0x29)

            // Derive the typehash from the prepared data.
            typehash := keccak256(m, add(0x7f, witnessTypestringLength))

            // Prepare initial components of message data: typehash & arbiter.
            mstore(m, typehash)
            mstore(add(m, 0x20), caller()) // arbiter: msg.sender

            // Next data segment copied from calldata: sponsor, nonce, expires.
            calldatacopy(add(m, 0x40), add(claim, 0x40), 0x60)

            // Prepare final components of message data: idsAndAmountsHash & witness.
            mstore(add(m, 0xa0), idsAndAmountsHash)
            mstore(add(m, 0xc0), calldataload(add(claim, 0xa0))) // witness

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0xe0)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a multichain claim.
     * @param claim                     Pointer to the claim location in calldata.
     * @param additionalOffset          Additional offset from claim pointer to ID from most compact case.
     * @param elementTypehash           The element typehash.
     * @param multichainCompactTypehash The multichain compact typehash.
     * @param idsAndAmountsHash         A hash of the ids and amounts.
     * @return messageHash              The EIP-712 compliant message hash.
     */
    function toMultichainClaimMessageHash(
        uint256 claim,
        uint256 additionalOffset,
        bytes32 elementTypehash,
        bytes32 multichainCompactTypehash,
        uint256 idsAndAmountsHash
    ) internal view returns (bytes32 messageHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Store the idsAndAmounts hash at the beginning of the memory region.
            mstore(add(m, 0x60), idsAndAmountsHash)

            // Prepare initial components of element data: element typehash, arbiter, & chainid.
            mstore(m, elementTypehash)
            mstore(add(m, 0x20), caller()) // arbiter
            mstore(add(m, 0x40), chainid())

            // Store the witness in memory.
            mstore(add(m, 0x80), calldataload(add(claim, 0xa0))) // witness

            // Derive the first element hash from the prepared data and write it to memory.
            mstore(m, keccak256(m, 0xa0))

            // Derive the pointer to the additional chains and retrieve the length.
            let additionalChainsPtr := add(claim, calldataload(add(add(claim, additionalOffset), 0xa0)))
            let additionalChainsLength := shl(5, calldataload(additionalChainsPtr))

            // Copy the element hashes in the additional chains array from calldata to memory.
            calldatacopy(add(m, 0x20), add(0x20, additionalChainsPtr), additionalChainsLength)

            // Derive hash of element hashes from prepared data and write it to memory.
            mstore(add(m, 0x80), keccak256(m, add(0x20, additionalChainsLength)))

            // Prepare next component of message data: multichain compact typehash.
            mstore(m, multichainCompactTypehash)

            // Copy final message data components from calldata: sponsor, nonce & expires.
            calldatacopy(add(m, 0x20), add(claim, 0x40), 0x60)

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0xa0)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * an exogenous multichain claim.
     * @param claim                     Pointer to the claim location in calldata.
     * @param additionalOffset          Additional offset from claim pointer to ID from most compact case.
     * @param elementTypehash           The element typehash.
     * @param multichainCompactTypehash The multichain compact typehash.
     * @param idsAndAmountsHash         A hash of the ids and amounts.
     * @return messageHash              The EIP-712 compliant message hash.
     */
    function toExogenousMultichainClaimMessageHash(
        uint256 claim,
        uint256 additionalOffset,
        bytes32 elementTypehash,
        bytes32 multichainCompactTypehash,
        uint256 idsAndAmountsHash
    ) internal view returns (bytes32 messageHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Store the idsAndAmounts hash at the beginning of the memory region.
            mstore(add(m, 0x60), idsAndAmountsHash)

            // Prepare initial components of element data: element typehash, arbiter, & chainid.
            mstore(m, elementTypehash)
            mstore(add(m, 0x20), caller()) // arbiter
            mstore(add(m, 0x40), chainid())

            // Store the witness in memory.
            mstore(add(m, 0x80), calldataload(add(claim, 0xa0))) // witness

            // Derive the element hash from the prepared data and write it to memory.
            let elementHash := keccak256(m, 0xa0)

            // Derive the pointer to the additional chains and retrieve the length.
            let claimWithAdditionalOffset := add(claim, additionalOffset)
            let additionalChainsPtr := add(claim, calldataload(add(claimWithAdditionalOffset, 0xa0)))

            // Retrieve the length of the additional chains array.
            let additionalChainsLength := shl(5, calldataload(additionalChainsPtr))

            // Derive the pointer to the additional chains data array in calldata.
            let additionalChainsData := add(0x20, additionalChainsPtr)

            // Retrieve the chain index from calldata.
            let chainIndex := shl(5, calldataload(add(claimWithAdditionalOffset, 0xc0)))

            // NOTE: rather than using extraOffset, consider breaking into two distinct
            // loops or potentially even two calldatacopy operations based on chainIndex
            let extraOffset := 0

            // Iterate over the additional chains array and store each element hash in memory.
            for { let i := 0 } lt(i, additionalChainsLength) { i := add(i, 0x20) } {
                mstore(add(add(m, i), extraOffset), calldataload(add(additionalChainsData, i)))
                // If current index matches chain index, store derived hash and increment offset.
                if eq(i, chainIndex) {
                    extraOffset := 0x20
                    mstore(add(m, add(i, extraOffset)), elementHash)
                }
            }

            // Derive the hash of the element hashes from the prepared data and write it to memory.
            mstore(add(m, 0x80), keccak256(m, add(0x20, additionalChainsLength)))

            // Prepare next component of message data: multichain compact typehash.
            mstore(m, multichainCompactTypehash)

            // Copy final message data components from calldata: sponsor, nonce & expires.
            calldatacopy(add(m, 0x20), add(claim, 0x40), 0x60)

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0xa0)
        }
    }

    /**
     * @notice Internal pure function for deriving the EIP-712 typehashes for
     * multichain claims.
     * @param claim                      Pointer to the claim location in calldata.
     * @return elementTypehash           The element typehash.
     * @return multichainCompactTypehash The multichain compact typehash.
     */
    function toMultichainTypehashes(uint256 claim)
        internal
        pure
        returns (bytes32 elementTypehash, bytes32 multichainCompactTypehash)
    {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Derive the pointer to the witness typestring and retrieve the length.
            let witnessTypestringPtr := add(claim, calldataload(add(claim, 0xc0)))
            let witnessTypestringLength := calldataload(witnessTypestringPtr)

            // Prepare the first five fragments of the multichain compact typehash.
            mstore(m, MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE)
            mstore(add(m, 0x20), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO)
            mstore(add(m, 0x40), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE)
            mstore(add(m, 0x60), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR)
            mstore(add(m, 0x8e), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX)
            mstore(add(m, 0x80), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE)

            // Copy remaining witness typestring from calldata to memory.
            let witnessStart := add(m, 0xae)
            calldatacopy(witnessStart, add(0x20, witnessTypestringPtr), witnessTypestringLength)

            // Prepare closing ")" parenthesis at the very end of the memory region.
            mstore8(add(witnessStart, witnessTypestringLength), 0x29)

            // Derive the element typehash and multichain compact typehash from the prepared data.
            elementTypehash := keccak256(add(m, 0x53), add(0x5c, witnessTypestringLength))
            multichainCompactTypehash := keccak256(m, add(0xaf, witnessTypestringLength))
        }
    }

    /**
     * @notice Internal pure function for deriving the EIP-712 message hash for
     * a single id and amount.
     * @param claim              Pointer to the claim location in calldata.
     * @param additionalOffset   Additional offset from claim pointer to ID from most compact case.
     * @return idsAndAmountsHash The hash of the id and amount.
     */
    function toSingleIdAndAmountHash(uint256 claim, uint256 additionalOffset)
        internal
        pure
        returns (uint256 idsAndAmountsHash)
    {
        assembly ("memory-safe") {
            // Derive the pointer to the claim with additional offset.
            let claimWithAdditionalOffset := add(claim, additionalOffset)

            // Store the id and amount at the beginning of the memory region.
            mstore(0, calldataload(add(claimWithAdditionalOffset, 0xc0)))
            mstore(0x20, calldataload(add(claimWithAdditionalOffset, 0xe0)))

            // Derive the idsAndAmounts hash from the stored data.
            idsAndAmountsHash := keccak256(0, 0x40)
        }
    }

    /**
     * @notice Internal pure function for deriving the hash of ids and amounts provided.
     * @param idsAndAmounts      An array of ids and amounts.
     * @param replacementAmounts An optional array of replacement amounts.
     * @return idsAndAmountsHash The hash of the ids and amounts.
     * @dev This function expects that the calldata of idsAndAmounts will have bounds
     * checked elsewhere; using it without this check occurring elsewhere can result in
     * erroneous hash values. This function also assumes that replacementAmounts.length
     * does not exceed replacementAmounts.length and will break if the invariant is not
     * upheld.
     */
    function toIdsAndAmountsHash(uint256[2][] calldata idsAndAmounts, uint256[] memory replacementAmounts)
        internal
        pure
        returns (bytes32 idsAndAmountsHash)
    {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let ptr := mload(0x40)

            // Get the total length of the calldata slice.
            // Each element of the array consists of 2 words.
            let len := shl(6, idsAndAmounts.length)

            // Copy calldata into memory at the free memory pointer.
            calldatacopy(ptr, idsAndAmounts.offset, len)

            let amountDataStart := add(ptr, 0x20)
            let replacementDataStart := add(replacementAmounts, 0x20)
            let amountsToReplace := mload(replacementAmounts)

            // Iterate over the replacementAmounts array, splicing in the updated amounts.
            for { let i := 0 } lt(i, amountsToReplace) { i := add(i, 1) } {
                mstore(add(amountDataStart, shl(6, i)), mload(add(replacementDataStart, shl(5, i))))
            }

            // Compute the hash of the calldata that has been copied into memory.
            idsAndAmountsHash := keccak256(ptr, len)
        }
    }

    /**
     * @notice Internal pure function for deriving the hash of the ids and amounts.
     * @param claims             An array of BatchClaimComponent structs.
     * @return idsAndAmountsHash The hash of the ids and amounts.
     */
    function toIdsAndAmountsHash(BatchClaimComponent[] calldata claims)
        internal
        pure
        returns (uint256 idsAndAmountsHash)
    {
        // Retrieve the total number of ids in the claims array.
        uint256 totalIds = claims.length;

        // Prepare a memory region for storing the ids and amounts.
        bytes memory idsAndAmounts = new bytes(totalIds << 6);

        unchecked {
            // Iterate over the claims array.
            for (uint256 i = 0; i < totalIds; ++i) {
                // Navigate to the current claim component in calldata.
                BatchClaimComponent calldata claimComponent = claims[i];

                assembly ("memory-safe") {
                    // Derive the offset to the current position in the memory region,
                    // then retrieve and store the id and amount at the current position.
                    calldatacopy(add(add(idsAndAmounts, 0x20), shl(6, i)), claimComponent, 0x40)
                }
            }
        }

        assembly ("memory-safe") {
            // Derive the hash of the ids and amounts from the prepared data.
            idsAndAmountsHash := keccak256(add(idsAndAmounts, 0x20), mload(idsAndAmounts))
        }
    }

    //// Registration Hashes ////

    /**
     * @notice Internal pure function for retrieving an EIP-712 claim hash.
     * @param sponsor      The account sponsoring the claimed compact.
     * @param tokenId      Identifier for the associated token & lock.
     * @param amount       Claim's associated number of tokens.
     * @param arbiter      Account verifying and initiating the settlement of the claim.
     * @param nonce        Allocator replay protection nonce.
     * @param expires      Timestamp when the claim expires.
     * @param typehash     Typehash of the entire compact. Including the subtypes.
     * @param witness      EIP712 structured hash of witness.
     * @return messageHash The corresponding EIP-712 messagehash.
     */
    function toFlatMessageHashWithWitness(
        address sponsor,
        uint256 tokenId,
        uint256 amount,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) internal pure returns (bytes32 messageHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            mstore(m, typehash)
            mstore(add(m, 0x20), arbiter)
            mstore(add(m, 0x40), sponsor)
            mstore(add(m, 0x60), nonce)
            mstore(add(m, 0x80), expires)
            mstore(add(m, 0xa0), tokenId)
            mstore(add(m, 0xc0), amount)
            mstore(add(m, 0xe0), witness)

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0x100)
        }
    }

    /**
     * @notice Internal pure function for retrieving an EIP-712 claim hash.
     * @param sponsor            The account sponsoring the claimed compact.
     * @param idsAndAmounts      An array with IDs and aggregate transfer amounts.
     * @param arbiter            Account verifying and initiating the settlement of the claim.
     * @param nonce              Allocator replay protection nonce.
     * @param expires            Timestamp when the claim expires.
     * @param typehash           Typehash of the entire compact. Including the subtypes.
     * @param witness            EIP712 structured hash of witness.
     * @param replacementAmounts An optional array of replacement amounts.
     * @return messageHash       The corresponding EIP-712 messagehash.
     */
    function toFlatBatchClaimWithWitnessMessageHash(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        uint256[] memory replacementAmounts
    ) internal pure returns (bytes32 messageHash) {
        bytes32 idsAndAmountsHash = idsAndAmounts.toIdsAndAmountsHash(replacementAmounts);
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            mstore(m, typehash)
            mstore(add(m, 0x20), arbiter)
            mstore(add(m, 0x40), sponsor)
            mstore(add(m, 0x60), nonce)
            mstore(add(m, 0x80), expires)
            mstore(add(m, 0xa0), idsAndAmountsHash)
            mstore(add(m, 0xc0), witness)

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0xe0)
        }
    }
}
