// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IAllocator } from "./IAllocator.sol";
import { Lock } from "../types/EIP712Types.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { DepositDetails } from "../types/DepositDetails.sol";

interface IOnChainAllocation is IAllocator {
    error InvalidPreparation();
    error InvalidRegistration(address sponsor, bytes32 claimHash);

    /**
     * @notice Emitted when a tokens are successfully allocated
     * @param sponsor The address of the sponsor
     * @param commitments The commitments of the allocations
     * @param nonce The nonce of the allocation
     * @param expires The expiration of the allocation
     * @param claimHash The hash of the allocation
     */
    event Allocated(address indexed sponsor, Lock[] commitments, uint256 nonce, uint256 expires, bytes32 claimHash);

    /**
     * @notice Deposits, registers and allocates a claim via Permit2 signature transfer
     * @dev Deposits the tokens subject to the order and registers the claim directly with the compact, then allocates the claim
     * @param arbiter The arbiter of the allocation
     * @param depositor The address depositing tokens and the sponsor of the claim (must sign the Permit2 message)
     * @param permitted The token permissions for the Permit2 transfer. Must match the commitments in the claim
     * @param additionalCommitmentAmounts Additional commitment amounts to allocate. Allocator must verify those tokens are unallocated.
     * @param details The deposit details including nonce, deadline, and lock tag
     *                Nonce must match the nonce structure expected by the allocator
     *                Deadline will be used as the expiration of the claim
     * @param claimHash The hash of the claim to register. Must match the claim hash recreated by the allocator
     * @param witness The witness typestring for the Permit2 signature (empty string if no witness)
     * @param witnessHash The hash of the witness data (bytes32(0) if no witness)
     * @param signature The Permit2 signature from the depositor, will be verified by the compact
     * @param context Additional context for the allocation
     * @return commitments The lock commitments created by the allocation
     */
    function permit2Allocation(
        address arbiter,
        address depositor,
        uint256 expires,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        uint256[] calldata additionalCommitmentAmounts,
        DepositDetails calldata details,
        bytes32 claimHash,
        string calldata witness,
        bytes32 witnessHash,
        bytes calldata signature,
        bytes calldata context
    ) external returns (Lock[] memory commitments);

    /**
     * @notice Allows to create an allocation on behalf of a recipient without the contract being in control over the funds.
     * @notice Will typically be used in combination with `batchDepositAndRegisterFor` on the compact.
     * @dev Must be called before `executeAllocation` to ensure a valid balance change has occurred for the recipient.
     * @param recipient The account to receive the tokens.
     * @param idsAndAmounts The ids and amounts to allocate.
     * @param additionalCommitmentAmounts Additional commitment amounts to allocate. Allocator must verify those tokens are unallocated.
     * @param arbiter The account tasked with verifying and submitting the claim.
     * @param expires The time at which the claim expires.
     * @param typehash The typehash of the claim.
     * @param witness The witness of the claim.
     * @param context Additional context for the allocation
     * @return nonce The next valid nonce. It is only guaranteed that the nonce is valid within the same transaction..
     */
    function prepareAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        uint256[] calldata additionalCommitmentAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata context
    ) external returns (uint256 nonce);

    /**
     * @notice Executes an allocation on behalf of a recipient.
     * @dev Must be called after `prepareAllocation` to ensure a valid balance change has occurred for the recipient.
     * @param recipient The account to receive the tokens.
     * @param idsAndAmounts The ids and amounts to allocate.
     * @param additionalCommitmentAmounts Additional commitment amounts to allocate. Allocator must verify those tokens are unallocated.
     * @param arbiter The account tasked with verifying and submitting the claim.
     * @param expires The time at which the claim expires.
     * @param typehash The typehash of the claim.
     * @param witness The witness of the claim.
     * @param context Additional context for the allocation
     */
    function executeAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        uint256[] calldata additionalCommitmentAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata context
    ) external;
}
