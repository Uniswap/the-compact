// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { IAllocator } from "src/interfaces/IAllocator.sol";

interface IServerAllocator is IAllocator {
    struct RegisterAttest {
        // The address of the signer who must sign the attest
        address signer;
        // The hash of the attest information, consistent of sponsor, id and amount
        bytes32 attestHash;
        // The expiration date after which the attest is no longer valid
        uint256 expiration;
        // A nonce for that specific attest hash to prevent replay attacks
        uint256 nonce;
    }

    struct NonceConsumption {
        // The address of the signer who must sign the attests
        address signer;
        // The array of nonces that should be consumed
        uint256[] nonces;
        // The array of previously registered attests that should be consumed
        bytes32[] attests;
    }

    /// @notice Thrown if no attest was registered for the given transfer
    error UnregisteredAttest(bytes32 attest_);

    /// @notice Thrown if the expiration date to register an attest is in the past
    error Expired(uint256 expiration_, uint256 currentTimestamp_);

    /// @notice Thrown if all of the registered attests have expired
    error ExpiredAttests(bytes32 attest_);

    /// @notice Thrown if the caller of attest is not the compact contract
    error InvalidCaller(address caller_, address expected_);

    /// @notice Thrown if the address is not a registered signer
    error InvalidSigner(address signer_);

    /// @notice Thrown if a signature is invalid
    error InvalidSignature(bytes signature_, address signer_);

    /// @notice Thrown if the same signature is used multiple times
    error AlreadyUsedSig(bytes32 attest_, uint256 nonce);

    /// @notice Thrown if the input array lengths are not matching
    error InvalidInput();

    /// @notice Emitted when a signer is added
    /// @param signer_ The address of the signer
    event SignerAdded(address signer_);

    /// @notice Emitted when a signer is removed
    /// @param signer_ The address of the signer
    event SignerRemoved(address signer_);

    /// @notice Emitted when an attest is registered
    /// @param attest_ The hash of the attest, consistent of sponsor, id and amount
    /// @param expiration_ The expiration date of the attest
    event AttestRegistered(bytes32 attest_, uint256 expiration_);

    /// @notice Emitted when nonces on the compact contract are consumed successfully
    /// @param nonces_ The array of nonces that were consumed
    event NoncesConsumed(uint256[] nonces_);

    /// @notice Emitted when an attest was consumed for a transfer
    /// @param from_ The address of the sponsor
    /// @param id_ The id of the token that was transferred
    /// @param amount_ The amount of the token that was transferred
    event Attested(address from_, uint256 id_, uint256 amount_);

    /// @notice Add a signer to the allocator
    /// @dev Only the owner can add a signer
    /// @param signer_ The address of the signer to add
    function addSigner(address signer_) external;

    /// @notice Remove a signer from the allocator
    /// @dev Only the owner can remove a signer
    /// @param signer_ The address of the signer to remove
    function removeSigner(address signer_) external;

    /// @notice Register an attest for a transfer
    /// @dev There is no way to uniquely identify a transfer, so the contract relies on its own accounting of registered attests.
    /// @param attest_ The hash of the attest to whitelist, consistent of sponsor, id and amount
    /// @param expiration_ The expiration date of the attest
    function registerAttest(bytes32 attest_, uint256 expiration_) external;

    /// @notice Register an attest for a transfer via a signature
    /// @dev Nonce management in the RegisterAttest is only required for multiple registers of the same attest with the same expiration.
    /// @param attest_ The RegisterAttest struct containing the signer, the hash of the attest, the expiration and the nonce
    /// @param signature_ The signature of the signer
    function registerAttestViaSignature(RegisterAttest calldata attest_, bytes calldata signature_) external;

    /// @notice Consume nonces on the compact contract and attests on the allocator
    /// @dev The hashes array needs to be of the same length as the nonces array.
    /// @dev If no hash was yet registered for the respective nonce, provide a bytes32(0) for the index.
    /// @dev All signers can override nonces of other signers.
    /// @param nonces_ The array of all nonces to consume on the compact contract
    /// @param attests_ The array of all attests to consume on the allocator
    function consume(uint256[] calldata nonces_, bytes32[] calldata attests_) external;

    /// @notice Consume nonces on the compact contract and attests on the allocator via a signature
    /// @param data_ The NonceConsumption struct containing the signer, the array of nonces and the array of attests
    /// @param signature_ The signature of the signer
    function consumeViaSignature(NonceConsumption calldata data_, bytes calldata signature_) external;

    /// @notice Check if an address is a registered signer
    /// @param signer_ The address to check
    /// @return bool Whether the address is a registered signer
    function checkIfSigner(address signer_) external view returns (bool);

    /// @notice Get all registered signers
    /// @return The array of all registered signers
    function getAllSigners() external view returns (address[] memory);

    /// @notice Check the expiration dates of an attest
    /// @dev If no attest was registered for the provided hash, the function will revert
    /// @param attest_ The hash of the attest to check
    /// @return The array of expiration dates for the registered attests
    function checkAttestExpirations(bytes32 attest_) external view returns (uint256[] memory);

    /// @notice Check the expiration dates of an attest by its components
    /// @dev If no attest was registered for the provided components, the function will revert
    /// @param sponsor_ The address of the sponsor
    /// @param id_ The id of the token
    /// @param amount_ The amount of the token
    /// @return The array of expiration dates for the registered attests
    function checkAttestExpirations(address sponsor_, uint256 id_, uint256 amount_) external view returns (uint256[] memory);

    /// @notice Get the address of the compact contract
    /// @dev Only the compact contract can call the attest function
    /// @return The address of the compact contract
    function getCompactContract() external view returns (address);
}
