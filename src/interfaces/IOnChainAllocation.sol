// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IAllocator } from "./IAllocator.sol";
import { Lock } from "../types/EIP712Types.sol";

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
