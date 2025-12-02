// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IAllocator } from "./IAllocator.sol";
import { Lock } from "../types/EIP712Types.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { DepositDetails } from "../types/DepositDetails.sol";

interface IOnChainAllocation is IAllocator {
    error InvalidPreparation();
    error InvalidRegistration(address sponsor, bytes32 claimHash);

    /// @notice Emitted when a tokens are successfully allocated
    /// @param sponsor The address of the sponsor
    /// @param commitments The commitments of the allocations
    /// @param nonce The nonce of the allocation
    /// @param expires The expiration of the allocation
    /// @param claimHash The hash of the allocation
    event Allocated(address indexed sponsor, Lock[] commitments, uint256 nonce, uint256 expires, bytes32 claimHash);

    /**
     * @notice Deposits multiple tokens using Permit2 authorization and creates an on-chain
     * allocation in a single transaction. The depositor must approve Permit2 to transfer
     * the tokens on its behalf unless the tokens automatically grant approval to Permit2.
     * The ERC6909 token amounts received by the depositor are derived from the differences
     * between starting and ending balances held in the resource locks, which may differ
     * from the amounts transferred depending on the implementation details of the respective
     * tokens. The Permit2 authorization signed by the depositor must contain a witness
     * matching the provided claim hash.
     * @dev The deadline of the permit2 approval MUST match the claim expiration.
     * @param depositor    The account signing the permit2 authorization and depositing the tokens.
     * @param permitted    Array of token permissions specifying the deposited tokens and amounts.
     * @param details      The deposit details containing nonce, deadline, and lock tag.
     * @param claimHash    A bytes32 hash derived from the details of the compact.
     * @param witness      Additional data used in generating the claim hash.
     * @param signature    The Permit2 signature from the depositor authorizing the deposits.
     * @return commitments Array of resource locks containing the ERC6909 token identifiers
     *                       and the actual amounts deposited for each associated resource lock.
     */
    function permit2Allocation(
        address depositor,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        DepositDetails calldata details,
        bytes32 claimHash,
        string calldata witness,
        bytes calldata signature
    ) external returns (Lock[] memory commitments);

    /**
     * @notice Allows to create an allocation on behalf of a recipient without the contract being in control over the funds.
     * @notice Will typically be used in combination with `batchDepositAndRegisterFor` on the compact.
     * @dev Must be called before `executeAllocation` to ensure a valid balance change has occurred for the recipient.
     * @param recipient The account to receive the tokens.
     * @param idsAndAmounts The ids and amounts to allocate.
     * @param arbiter The account tasked with verifying and submitting the claim.
     * @param expires The time at which the claim expires.
     * @param typehash The typehash of the claim.
     * @param witness The witness of the claim.
     * @return nonce The next valid nonce. It is only guaranteed that the nonce is valid within the same transaction..
     */
    function prepareAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata orderData
    ) external returns (uint256 nonce);

    /**
     * @notice Executes an allocation on behalf of a recipient.
     * @dev Must be called after `prepareAllocation` to ensure a valid balance change has occurred for the recipient.
     * @param recipient The account to receive the tokens.
     * @param idsAndAmounts The ids and amounts to allocate.
     * @param arbiter The account tasked with verifying and submitting the claim.
     * @param expires The time at which the claim expires.
     * @param typehash The typehash of the claim.
     * @param witness The witness of the claim.
     */
    function executeAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata orderData
    ) external;
}
