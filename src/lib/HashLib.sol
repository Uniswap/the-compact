// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BatchTransfer, SplitBatchTransfer } from "../types/BatchClaims.sol";
import { BasicTransfer, SplitTransfer } from "../types/Claims.sol";
import { TransferComponent, SplitComponent, SplitByIdComponent, SplitBatchClaimComponent } from "../types/Components.sol";
import {
    COMPACT_TYPEHASH,
    COMPACT_TYPESTRING_FRAGMENT_ONE,
    COMPACT_TYPESTRING_FRAGMENT_TWO,
    COMPACT_TYPESTRING_FRAGMENT_THREE,
    BATCH_COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    SEGMENT_TYPEHASH,
    MULTICHAIN_COMPACT_TYPEHASH,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE,
    TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO,
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
    using TransferFunctionCastLib for function(BatchTransfer calldata, uint256) internal view returns (bytes32);
    using HashLib for uint256;
    using HashLib for BatchTransfer;

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a basic transfer or withdrawal where the arbiter is the sponsor.
     * @param transfer     A BasicTransfer struct containing the transfer details.
     * @return messageHash The EIP-712 compliant message hash.
     */
    function toBasicTransferMessageHash(BasicTransfer calldata transfer) internal view returns (bytes32 messageHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare initial components of message data: typehash, arbiter, & sponsor.
            mstore(m, COMPACT_TYPEHASH)
            mstore(add(m, 0x20), caller()) // arbiter: msg.sender
            mstore(add(m, 0x40), caller()) // sponsor: msg.sender

            // Remaining data copied from calldata: nonce, expires, id & amount.
            calldatacopy(add(m, 0x60), add(transfer, 0x20), 0x80)

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0xe0)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a split transfer or withdrawal.
     * @param transfer     A SplitTransfer struct containing the transfer details.
     * @return messageHash The EIP-712 compliant message hash.
     */
    function toSplitTransferMessageHash(SplitTransfer calldata transfer) internal view returns (bytes32 messageHash) {
        // Declare variables for tracking, total amount, current amount, and errors.
        uint256 amount = 0;
        uint256 currentAmount;
        uint256 errorBuffer;

        // Navigate to the split components array in calldata.
        SplitComponent[] calldata recipients = transfer.recipients;

        // Retrieve the length of the array.
        uint256 totalRecipients = recipients.length;

        unchecked {
            // Iterate over each split component.
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
     * @param transfer     A BatchTransfer struct containing the transfer details.
     * @return messageHash The EIP-712 compliant message hash.
     */
    function toBatchTransferMessageHash(BatchTransfer calldata transfer) internal view returns (bytes32) {
        // Navigate to the transfer components array in calldata.
        TransferComponent[] calldata transfers = transfer.transfers;

        // Declare a variable for the ids and amounts hash.
        uint256 idsAndAmountsHash;

        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Calculate the total size of the transfer data.
            let totalTransferData := mul(transfers.length, 0x40)

            // Copy the transfer data from calldata to memory.
            calldatacopy(m, transfers.offset, totalTransferData)

            // Derive the ids and amounts hash from the transfer data.
            idsAndAmountsHash := keccak256(m, totalTransferData)
        }

        // Derive message hash from transfer data and idsAndAmounts hash.
        return transfer.toBatchTransferMessageHashUsingIdsAndAmountsHash(idsAndAmountsHash);
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a split batch transfer or withdrawal.
     * @param transfer     A SplitBatchTransfer struct containing the transfer details.
     * @return messageHash The EIP-712 compliant message hash.
     */
    function toSplitBatchTransferMessageHash(SplitBatchTransfer calldata transfer) internal view returns (bytes32) {
        // Navigate to the transfer components array in calldata.
        SplitByIdComponent[] calldata transfers = transfer.transfers;

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
                SplitByIdComponent calldata transferComponent = transfers[i];

                // Retrieve the id from the current transfer component.
                uint256 id = transferComponent.id;

                // Declare a variable for the aggregate amount.
                uint256 amount = 0;

                // Declare a variable for the current amount.
                uint256 singleAmount;

                // Navigate to the portions array in the current transfer component.
                SplitComponent[] calldata portions = transferComponent.portions;

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
                    // Derive offset to id and amount based on total split components.
                    let extraOffset := add(add(idsAndAmounts, 0x20), mul(i, 0x40))

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
        return toBatchTransferMessageHashUsingIdsAndAmountsHash.usingSplitBatchTransfer()(transfer, idsAndAmountsHash);
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a claim.
     * @param claim            Pointer to the claim location in calldata.
     * @param additionalOffset Additional offset from claim pointer to ID from most compact case.
     * @return messageHash     The EIP-712 compliant message hash.
     */
    function toClaimMessageHash(uint256 claim, uint256 additionalOffset) internal view returns (bytes32 messageHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Derive the calldata pointer for the offset values.
            let claimWithAdditionalOffset := add(claim, additionalOffset)

            // Prepare initial components of message data: typehash & arbiter.
            mstore(m, COMPACT_TYPEHASH)
            mstore(add(m, 0x20), caller()) // arbiter: msg.sender

            // Next data segment copied from calldata: sponsor, nonce & expires.
            calldatacopy(add(m, 0x40), add(claim, 0x40), 0x60)

            // Prepare final components of message data: id and amount.
            mstore(add(m, 0xa0), calldataload(add(claimWithAdditionalOffset, 0xa0))) // id
            mstore(add(m, 0xc0), calldataload(add(claimWithAdditionalOffset, 0xc0))) // amount

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0xe0)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a claim with a witness.
     * @param claim               Pointer to the claim location in calldata.
     * @param qualificationOffset Additional offset from claim pointer to ID from most compact case.
     * @return messageHash        The EIP-712 compliant message hash.
     * @return typehash           The EIP-712 typehash.
     */
    function toMessageHashWithWitness(uint256 claim, uint256 qualificationOffset) internal view returns (bytes32 messageHash, bytes32 typehash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Derive the pointer to the witness typestring.
            let witnessTypestringPtr := add(claim, calldataload(add(claim, 0xc0)))

            // Retrieve the length of the witness typestring.
            let witnessTypestringLength := calldataload(witnessTypestringPtr)

            // Prepare first component of typestring from three one-word fragments.
            mstore(m, COMPACT_TYPESTRING_FRAGMENT_ONE)
            mstore(add(m, 0x20), COMPACT_TYPESTRING_FRAGMENT_TWO)
            mstore(add(m, 0x40), COMPACT_TYPESTRING_FRAGMENT_THREE)

            // Copy remaining typestring data from calldata to memory.
            calldatacopy(add(m, 0x60), add(0x20, witnessTypestringPtr), witnessTypestringLength)

            // Derive the typehash from the prepared data.
            typehash := keccak256(m, add(0x60, witnessTypestringLength))

            // Prepare initial components of message data: typehash & arbiter.
            mstore(m, typehash)
            mstore(add(m, 0x20), caller()) // arbiter: msg.sender

            // Next data segment copied from calldata: sponsor, nonce, expires.
            calldatacopy(add(m, 0x40), add(claim, 0x40), 0x60)

            // Prepare final components of message data: id, amount, & witness.
            mstore(add(m, 0xa0), calldataload(add(claim, add(0xe0, qualificationOffset)))) // id
            mstore(add(m, 0xc0), calldataload(add(claim, add(0x100, qualificationOffset)))) // amount
            mstore(add(m, 0xe0), calldataload(add(claim, 0xa0))) // witness

            // Derive the message hash from the prepared data.
            messageHash := keccak256(m, 0x100)
        }
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a batch transfer or withdrawal once an idsAndAmounts hash is available.
     * @param transfer          A BatchTransfer struct containing the transfer details.
     * @param idsAndAmountsHash A hash of the ids and amounts.
     * @return messageHash      The EIP-712 compliant message hash.
     */
    function toBatchTransferMessageHashUsingIdsAndAmountsHash(BatchTransfer calldata transfer, uint256 idsAndAmountsHash) internal view returns (bytes32 messageHash) {
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
    function toBatchClaimWithWitnessMessageHash(uint256 claim, uint256 idsAndAmountsHash) internal view returns (bytes32 messageHash, bytes32 typehash) {
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
            mstore(add(m, 0x46), BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR)
            mstore(add(m, 0x40), BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE)

            // Copy remaining typestring data from calldata to memory.
            calldatacopy(add(m, 0x66), add(0x20, witnessTypestringPtr), witnessTypestringLength)

            // Derive the typehash from the prepared data.
            typehash := keccak256(m, add(0x66, witnessTypestringLength))

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
     * @param segmentTypehash           The segment typehash.
     * @param multichainCompactTypehash The multichain compact typehash.
     * @param idsAndAmountsHash         A hash of the ids and amounts.
     * @return messageHash              The EIP-712 compliant message hash.
     */
    function toMultichainClaimMessageHash(uint256 claim, uint256 additionalOffset, bytes32 segmentTypehash, bytes32 multichainCompactTypehash, uint256 idsAndAmountsHash)
        internal
        view
        returns (bytes32 messageHash)
    {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Store the idsAndAmounts hash at the beginning of the memory region.
            mstore(add(m, 0x60), idsAndAmountsHash)

            // Prepare initial components of segment data: segment typehash, arbiter, & chainid.
            mstore(m, segmentTypehash)
            mstore(add(m, 0x20), caller()) // arbiter
            mstore(add(m, 0x40), chainid())

            // Determine if the segment typestring has a witness.
            let hasWitness := iszero(eq(segmentTypehash, SEGMENT_TYPEHASH))

            // If the segment has a witness, store the witness in memory.`
            if hasWitness { mstore(add(m, 0x80), calldataload(add(claim, 0xa0))) } // witness

            // Derive the first segment hash from the prepared data and write it to memory.
            mstore(m, keccak256(m, add(0x80, mul(0x20, hasWitness)))) // first segment hash

            // Derive the pointer to the additional chains and retrieve the length.
            let additionalChainsPtr := add(claim, calldataload(add(add(claim, additionalOffset), 0xa0)))
            let additionalChainsLength := shl(5, calldataload(additionalChainsPtr))

            // Copy the segment hashes in the additional chains array from calldata to memory.
            calldatacopy(add(m, 0x20), add(0x20, additionalChainsPtr), additionalChainsLength)

            // Derive hash of segment hashes from prepared data and write it to memory.
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
     * @param segmentTypehash           The segment typehash.
     * @param multichainCompactTypehash The multichain compact typehash.
     * @param idsAndAmountsHash         A hash of the ids and amounts.
     * @return messageHash              The EIP-712 compliant message hash.
     */
    function toExogenousMultichainClaimMessageHash(uint256 claim, uint256 additionalOffset, bytes32 segmentTypehash, bytes32 multichainCompactTypehash, uint256 idsAndAmountsHash)
        internal
        view
        returns (bytes32 messageHash)
    {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Store the idsAndAmounts hash at the beginning of the memory region.
            mstore(add(m, 0x60), idsAndAmountsHash)

            // Prepare initial components of segment data: segment typehash, arbiter, & chainid.
            mstore(m, segmentTypehash)
            mstore(add(m, 0x20), caller()) // arbiter
            mstore(add(m, 0x40), chainid())

            // Determine if the segment typestring has a witness.
            let hasWitness := iszero(eq(segmentTypehash, SEGMENT_TYPEHASH))

            // If the segment has a witness, store the witness in memory.
            if hasWitness { mstore(add(m, 0x80), calldataload(add(claim, 0xa0))) } // witness

            // Derive the segment hash from the prepared data and write it to memory.
            let segmentHash := keccak256(m, add(0x80, mul(0x20, hasWitness)))

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

            // Iterate over the additional chains array and store each segment hash in memory.
            for { let i := 0 } lt(i, additionalChainsLength) { i := add(i, 0x20) } {
                mstore(add(m, i), calldataload(add(additionalChainsData, add(i, extraOffset))))
                // If current index matches chain index, store derived hash and increment offset.
                if eq(i, chainIndex) {
                    extraOffset := 0x20
                    mstore(add(m, add(i, extraOffset)), segmentHash)
                }
            }

            // Derive the hash of the segment hashes from the prepared data and write it to memory.
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
     * a simple multichain claim.
     * @param claim             Pointer to the claim location in calldata.
     * @param idsAndAmountsHash A hash of the ids and amounts (formatted as a uint256).
     * @return messageHash      The EIP-712 compliant message hash.
     */
    function toSimpleMultichainClaimMessageHash(uint256 claim, uint256 idsAndAmountsHash) internal view returns (bytes32 messageHash) {
        // Derive the message hash from the claim and idsAndAmounts hash.
        return claim.toMultichainClaimMessageHash(uint256(0).asStubborn(), SEGMENT_TYPEHASH, MULTICHAIN_COMPACT_TYPEHASH, idsAndAmountsHash);
    }

    /**
     * @notice Internal view function for deriving the EIP-712 message hash for
     * a simple exogenous multichain claim.
     * @param claim             Pointer to the claim location in calldata.
     * @param idsAndAmountsHash A hash of the ids and amounts.
     * @return messageHash      The EIP-712 compliant message hash.
     */
    function toSimpleExogenousMultichainClaimMessageHash(uint256 claim, uint256 idsAndAmountsHash) internal view returns (bytes32 messageHash) {
        // Derive the message hash from the claim and idsAndAmounts hash.
        return claim.toExogenousMultichainClaimMessageHash(uint256(0).asStubborn(), SEGMENT_TYPEHASH, MULTICHAIN_COMPACT_TYPEHASH, idsAndAmountsHash);
    }

    /**
     * @notice Internal pure function for deriving the EIP-712 typehashes for
     * multichain claims.
     * @param claim                      Pointer to the claim location in calldata.
     * @return segmentTypehash           The segment typehash.
     * @return multichainCompactTypehash The multichain compact typehash.
     */
    function toMultichainTypehashes(uint256 claim) internal pure returns (bytes32 segmentTypehash, bytes32 multichainCompactTypehash) {
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
            mstore(add(m, 0x76), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE)
            mstore(add(m, 0x60), MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR)

            // Copy remaining witness typestring from calldata to memory.
            calldatacopy(add(m, 0x96), add(0x20, witnessTypestringPtr), witnessTypestringLength)

            // Derive the segment typehash and multichain compact typehash from the prepared data.
            segmentTypehash := keccak256(add(m, 0x53), add(0x43, witnessTypestringLength))
            multichainCompactTypehash := keccak256(m, add(0x96, witnessTypestringLength))
        }
    }

    /**
     * @notice Internal pure function for deriving the EIP-712 message hash for
     * a single id and amount.
     * @param claim              Pointer to the claim location in calldata.
     * @param additionalOffset   Additional offset from claim pointer to ID from most compact case.
     * @return idsAndAmountsHash The hash of the id and amount.
     */
    function toSingleIdAndAmountHash(uint256 claim, uint256 additionalOffset) internal pure returns (uint256 idsAndAmountsHash) {
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
     * @notice Internal pure function for deriving the hash of the ids and amounts.
     * @param claims             An array of SplitBatchClaimComponent structs.
     * @return idsAndAmountsHash The hash of the ids and amounts.
     */
    function toSplitIdsAndAmountsHash(SplitBatchClaimComponent[] calldata claims) internal pure returns (uint256 idsAndAmountsHash) {
        // Retrieve the total number of ids in the claims array.
        uint256 totalIds = claims.length;

        // Prepare a memory region for storing the ids and amounts.
        bytes memory idsAndAmounts = new bytes(totalIds * 0x40);

        unchecked {
            // Iterate over the claims array.
            for (uint256 i = 0; i < totalIds; ++i) {
                // Navigate to the current claim component in calldata.
                SplitBatchClaimComponent calldata claimComponent = claims[i];

                assembly ("memory-safe") {
                    // Derive the offset to the current position in the memory region.
                    let extraOffset := add(add(idsAndAmounts, 0x20), mul(i, 0x40))

                    // Retrieve and store the id and amount at the current position.
                    mstore(extraOffset, calldataload(claimComponent)) // id
                    mstore(add(extraOffset, 0x20), calldataload(add(claimComponent, 0x20))) // amount
                }
            }
        }

        assembly ("memory-safe") {
            // Derive the hash of the ids and amounts from the prepared data.
            idsAndAmountsHash := keccak256(add(idsAndAmounts, 0x20), mload(idsAndAmounts))
        }
    }

    /**
     * @notice Internal pure function for retrieving EIP-712 typehashes where no witness data is
     * provided, returning the corresponding typehash based on the index provided. The available
     * typehashes are:
     *  - 0: COMPACT_TYPEHASH
     *  - 1: BATCH_COMPACT_TYPEHASH
     *  - 2: MULTICHAIN_COMPACT_TYPEHASH
     * @param i         The index of the EIP-712 typehash to retrieve.
     * @return typehash The corresponding EIP-712 typehash.
     */
    function typehashes(uint256 i) internal pure returns (bytes32 typehash) {
        assembly ("memory-safe") {
            // Retrieve and cache the free memory pointer.
            let m := mload(0x40)

            // Prepare the typehashes in memory.
            mstore(0, COMPACT_TYPEHASH)
            mstore(0x20, BATCH_COMPACT_TYPEHASH)
            mstore(0x40, MULTICHAIN_COMPACT_TYPEHASH)

            // Retrieve the typehash from memory based on the provided index.
            typehash := mload(shl(5, i))

            // Restore the free memory pointer.
            mstore(0x40, m)
        }
    }
}
