// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { IAllocator } from "src/interfaces/IAllocator.sol";

interface IServerAllocator is IAllocator {
    struct RegisterAttestation {
        // The address of the signer who must sign the attestation
        address signer;
        // The hash of the attestation information, consistent of sponsor, id and amount
        bytes32 attestationHash;
        // The expiration date after which the attestation is no longer valid
        uint256 expiration;
        // A nonce for that specific attestation hash to prevent replay attacks
        uint256 nonce;
    }

    struct NonceConsumption {
        // The address of the signer who must sign the attestations
        address signer;
        // The array of nonces that should be consumed
        uint256[] nonces;
        // The array of previously registered attestations that should be consumed
        bytes32[] attestations;
    }

    /// @notice Thrown if no attestation was registered for the given transfer
    error UnregisteredAttestation(bytes32 attestation_);

    /// @notice Thrown if the expiration date to register an attestation is in the past
    error Expired(uint256 expiration_, uint256 currentTimestamp_);

    /// @notice Thrown if all of the registered attestations have expired
    error ExpiredAttestations(bytes32 attestation_);

    /// @notice Thrown if the caller of attest is not the compact contract
    error InvalidCaller(address caller_, address expected_);

    /// @notice Thrown if the address is not a registered signer
    error InvalidSigner(address signer_);

    /// @notice Thrown if a signature is invalid
    error InvalidSignature(bytes signature_, address signer_);

    /// @notice Thrown if the same signature is used multiple times
    error AlreadyUsedSig(bytes32 attestation_, uint256 nonce);

    /// @notice Thrown if the input array lengths are not matching
    error InvalidInput();

    /// @notice Emitted when a signer is added
    /// @param signer_ The address of the signer
    event SignerAdded(address signer_);

    /// @notice Emitted when a signer is removed
    /// @param signer_ The address of the signer
    event SignerRemoved(address signer_);

    /// @notice Emitted when an attestation is registered
    /// @param attestation_ The hash of the attestation, consistent of sponsor, id and amount
    /// @param expiration_ The expiration date of the attestation
    event AttestationRegistered(bytes32 attestation_, uint256 expiration_);

    /// @notice Emitted when nonces on the compact contract are consumed successfully
    /// @param nonces_ The array of nonces that were consumed
    event NoncesConsumed(uint256[] nonces_);

    /// @notice Emitted when an attestation was consumed for a transfer
    /// @param from_ The address of the sponsor
    /// @param id_ The id of the token that was transferred
    /// @param amount_ The amount of the token that was transferred
    event AttestationConsumed(address from_, uint256 id_, uint256 amount_);

    /// @notice Add a signer to the allocator
    /// @dev Only the owner can add a signer
    /// @param signer_ The address of the signer to add
    function addSigner(address signer_) external;

    /// @notice Remove a signer from the allocator
    /// @dev Only the owner can remove a signer
    /// @param signer_ The address of the signer to remove
    function removeSigner(address signer_) external;

    /// @notice Register an attestation for a transfer
    /// @dev There is no way to uniquely identify a transfer, so the contract relies on its own accounting of registered attestations.
    /// @param attestation_ The hash of the attestation to whitelist, consistent of sponsor, id and amount
    /// @param expiration_ The expiration date of the attestation
    function registerAttestation(bytes32 attestation_, uint256 expiration_) external;

    /// @notice Register an attestation for a transfer via a signature
    /// @dev Nonce management in the RegisterAttestation is only required for multiple registers of the same attestation with the same expiration.
    /// @param attestation_ The RegisterAttestation struct containing the signer, the hash of the attestation, the expiration and the nonce
    /// @param signature_ The signature of the signer
    function registerAttestationViaSignature(RegisterAttestation calldata attestation_, bytes calldata signature_) external;

    /// @notice Consume nonces on the compact contract and attestations on the allocator
    /// @dev The hashes array needs to be of the same length as the nonces array.
    /// @dev If no hash was yet registered for the respective nonce, provide a bytes32(0) for the index.
    /// @dev All signers can override nonces of other signers.
    /// @param nonces_ The array of all nonces to consume on the compact contract
    /// @param attestations_ The array of all attestations to consume on the allocator
    function consume(uint256[] calldata nonces_, bytes32[] calldata attestations_) external;

    /// @notice Consume nonces on the compact contract and attestations on the allocator via a signature
    /// @param data_ The NonceConsumption struct containing the signer, the array of nonces and the array of attestations
    /// @param signature_ The signature of the signer
    function consumeViaSignature(NonceConsumption calldata data_, bytes calldata signature_) external;

    /// @notice Check if an address is a registered signer
    /// @param signer_ The address to check
    /// @return bool Whether the address is a registered signer
    function checkIfSigner(address signer_) external view returns (bool);

    /// @notice Get all registered signers
    /// @return The array of all registered signers
    function getAllSigners() external view returns (address[] memory);

    /// @notice Check the expiration dates of an attestation
    /// @dev If no attestation was registered for the provided hash, the function will revert
    /// @param attestation_ The hash of the attestation to check
    /// @return The array of expiration dates for the registered attestations
    function checkAttestationExpirations(bytes32 attestation_) external view returns (uint256[] memory);

    /// @notice Check the expiration dates of an attestation by its components
    /// @dev If no attestation was registered for the provided components, the function will revert
    /// @param sponsor_ The address of the sponsor
    /// @param id_ The id of the token
    /// @param amount_ The amount of the token
    /// @return The array of expiration dates for the registered attestations
    function checkAttestationExpirations(address sponsor_, uint256 id_, uint256 amount_) external view returns (uint256[] memory);

    /// @notice Get the address of the compact contract
    /// @dev Only the compact contract can call the attest function
    /// @return The address of the compact contract
    function getCompactContract() external view returns (address);
}
