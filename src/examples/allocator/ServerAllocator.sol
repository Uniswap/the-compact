// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { Compact } from "src/types/EIP712Types.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import { IAllocator } from "src/interfaces/IAllocator.sol";
import { IServerAllocator } from "src/interfaces/IServerAllocator.sol";
import { Compact, COMPACT_TYPEHASH } from "src/types/EIP712Types.sol";
import { Ownable, Ownable2Step } from "lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import { ECDSA } from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import { IERC1271 } from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";

contract ServerAllocator is Ownable2Step, EIP712, IServerAllocator {
    using ECDSA for bytes32;

    // bytes4(keccak256("attest(address,address,address,uint256,uint256)")).
    bytes4 private constant _ATTEST_SELECTOR = 0x1a808f91;

    // keccak256("RegisterAttestation(address signer,bytes32 attestationHash,uint256 expiration,uint256 nonce)")
    bytes32 private constant _ATTESTATION_TYPE_HASH = 0x6017ed71e505719876ff40d1e87ed2a0a078883c87bd2902ea9988c117f7ca7f;

    // keccak256("NonceConsumption(address signer,uint256[] nonces,bytes32[] attestations)")
    bytes32 private constant _NONCE_CONSUMPTION_TYPE_HASH = 0x626e2c6c331510cafaa5cc323e6ac1e87f32c48cba2a61d81c86b50534f7cc91;

    address private immutable _COMPACT_CONTRACT;

    /// @dev mapping of a signer to their index (incremented to skip 0) in _activeSigners
    mapping(address signer => uint256 index) private _signers;
    address[] private _activeSigners;

    mapping(bytes32 => uint256) private _attestationExpirations;
    mapping(bytes32 => uint256) private _attestationCounts;
    mapping(bytes32 => bool) private _attestationSignatures;

    modifier isSigner(address signer_) {
        if (!_containsSigner(signer_)) {
            revert InvalidSigner(signer_);
        }
        _;
    }

    constructor(address owner_, address compactContract_) Ownable(owner_) EIP712("Allocator", "1") {
        _COMPACT_CONTRACT = compactContract_;
        ITheCompact(_COMPACT_CONTRACT).__registerAllocator(address(this), "");
    }

    /// @inheritdoc IServerAllocator
    function addSigner(address signer_) external onlyOwner {
        if (_containsSigner(signer_)) {
            return;
        }

        _activeSigners.push(signer_);
        _signers[signer_] = _activeSigners.length;

        emit SignerAdded(signer_);
    }

    /// @inheritdoc IServerAllocator
    function removeSigner(address signer_) external onlyOwner {
        if (!_containsSigner(signer_)) {
            return;
        }

        uint256 index = _signers[signer_] - 1;
        _activeSigners[index] = _activeSigners[_activeSigners.length - 1];
        _activeSigners.pop();

        _signers[signer_] = 0;

        emit SignerRemoved(signer_);
    }

    /// @inheritdoc IServerAllocator
    function registerAttestation(bytes32 attestation_, uint256 expiration_) external isSigner(msg.sender) {
        _registerAttestation(attestation_, expiration_);
    }

    /// @inheritdoc IServerAllocator
    function registerAttestationViaSignature(RegisterAttestation calldata attestation_, bytes calldata signature_) external {
        bytes32 _attestationWithNonce = keccak256(abi.encode(attestation_.attestationHash, attestation_.expiration, attestation_.nonce));
        if (_attestationSignatures[_attestationWithNonce]) {
            revert AlreadyUsedSig(attestation_.attestationHash, attestation_.nonce);
        }
        address signer = _validateSignedAttestation(attestation_.signer, attestation_.attestationHash, attestation_.expiration, attestation_.nonce, signature_);
        if (signer != attestation_.signer || !_containsSigner(signer)) {
            revert InvalidSignature(signature_, signer);
        }

        // Invalidate signature
        _attestationSignatures[_attestationWithNonce] = true;
        _registerAttestation(attestation_.attestationHash, attestation_.expiration);
    }

    /// @inheritdoc IAllocator
    function attest(
        address, // operator_
        address from_,
        address, // to_
        uint256 id_,
        uint256 amount_
    ) external returns (bytes4) {
        if (msg.sender != _COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, _COMPACT_CONTRACT);
        }
        bytes32 registeredAttestation = keccak256(abi.encode(from_, id_, amount_));
        uint256 count = _attestationCounts[registeredAttestation];

        if (count == 0) {
            revert UnregisteredAttestation(registeredAttestation);
        }
        for (uint256 i = count; i > 0; --i) {
            bytes32 countedAttestation = keccak256(abi.encode(registeredAttestation, i));
            if (_attestationExpirations[countedAttestation] >= block.timestamp) {
                // Found a valid registered attestation
                if (i == count) {
                    // Last attestation, delete
                    delete _attestationExpirations[countedAttestation];
                } else {
                    // Shift attestation and delete from the end
                    bytes32 lastAttestation = keccak256(abi.encode(registeredAttestation, count));
                    _attestationExpirations[countedAttestation] = _attestationExpirations[lastAttestation];
                    delete _attestationExpirations[lastAttestation];
                }
                _attestationCounts[registeredAttestation] = --count;

                emit AttestationConsumed(from_, id_, amount_);
                return _ATTEST_SELECTOR;
            }
        }

        revert ExpiredAttestations(registeredAttestation);
    }

    /// @inheritdoc IServerAllocator
    function consume(uint256[] calldata nonces_, bytes32[] calldata attestations_) external isSigner(msg.sender) {
        if (attestations_.length != nonces_.length) {
            revert InvalidInput();
        }
        _consumeNonces(nonces_, attestations_);
    }

    /// @inheritdoc IServerAllocator
    function consumeViaSignature(NonceConsumption calldata data_, bytes calldata signature_) external {
        if (data_.attestations.length != data_.nonces.length) {
            revert InvalidInput();
        }
        address signer = _validateNonceConsumption(data_, signature_);
        if (signer != data_.signer || !_containsSigner(signer)) {
            // first check is optional, can be deleted for gas efficiency
            revert InvalidSignature(signature_, signer);
        }
        _consumeNonces(data_.nonces, data_.attestations);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash_, bytes calldata signature_) external view returns (bytes4 magicValue) {
        address signer = _validateSignedHash(hash_, signature_);
        if (!_containsSigner(signer)) {
            revert InvalidSignature(signature_, signer);
        }
        return IERC1271.isValidSignature.selector;
    }

    /// @inheritdoc IServerAllocator
    function checkIfSigner(address signer_) external view returns (bool) {
        return _containsSigner(signer_);
    }

    /// @inheritdoc IServerAllocator
    function getAllSigners() external view returns (address[] memory) {
        return _activeSigners;
    }

    /// @inheritdoc IServerAllocator
    function checkAttestationExpirations(bytes32 attestation_) external view returns (uint256[] memory) {
        return _checkAttestationExpirations(attestation_);
    }

    /// @inheritdoc IServerAllocator
    function checkAttestationExpirations(address sponsor_, uint256 id_, uint256 amount_) external view returns (uint256[] memory) {
        return _checkAttestationExpirations(keccak256(abi.encode(sponsor_, id_, amount_)));
    }

    /// @inheritdoc IServerAllocator
    function getCompactContract() external view returns (address) {
        return _COMPACT_CONTRACT;
    }

    function _registerAttestation(bytes32 attestation_, uint256 expiration_) internal {
        if (expiration_ < block.timestamp) {
            revert Expired(expiration_, block.timestamp);
        }
        uint256 count = ++_attestationCounts[attestation_];
        bytes32 countedAttestation = keccak256(abi.encode(attestation_, count));

        _attestationExpirations[countedAttestation] = expiration_;

        emit AttestationRegistered(attestation_, expiration_);
    }

    /// Todo: This will lead to always the last registered hash being consumed.
    function _consumeNonces(uint256[] calldata nonces_, bytes32[] calldata attestations_) internal {
        ITheCompact(_COMPACT_CONTRACT).consume(nonces_);
        uint256 nonceLength = attestations_.length;
        for (uint256 i = 0; i < nonceLength; ++i) {
            bytes32 hashToConsume = attestations_[i];
            if (hashToConsume != bytes32(0)) {
                uint256 count = _attestationCounts[attestations_[i]];
                if (count != 0) {
                    // Consume the latest registered attestation
                    delete _attestationExpirations[
                        keccak256(abi.encode(attestations_[i], count))
                    ];
                    _attestationCounts[attestations_[i]] = --count;
                }
            }
        }
        emit NoncesConsumed(nonces_);
    }

    function _validateSignedAttestation(address signer_, bytes32 hash_, uint256 expiration_, uint256 nonce, bytes calldata signature_) internal view returns (address) {
        bytes32 message = _hashAttestation(signer_, hash_, expiration_, nonce);
        return message.recover(signature_);
    }

    function _hashAttestation(address signer_, bytes32 hash_, uint256 expiration_, uint256 nonce_) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_ATTESTATION_TYPE_HASH, signer_, hash_, expiration_, nonce_)));
    }

    function _validateSignedHash(bytes32 digest_, bytes calldata signature_) internal pure returns (address) {
        return digest_.recover(signature_);
    }

    function _validateNonceConsumption(NonceConsumption calldata data_, bytes calldata signature_) internal view returns (address) {
        bytes32 message = _hashNonceConsumption(data_);
        return message.recover(signature_);
    }

    function _hashNonceConsumption(NonceConsumption calldata data_) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_NONCE_CONSUMPTION_TYPE_HASH, data_.signer, data_.nonces, data_.attestations)));
    }

    function _containsSigner(address signer_) internal view returns (bool) {
        return _signers[signer_] != 0;
    }

    function _checkAttestationExpirations(bytes32 attestation_) internal view returns (uint256[] memory) {
        uint256 count = _attestationCounts[attestation_];
        if (count == 0) {
            revert UnregisteredAttestation(attestation_);
        }
        uint256[] memory expirations = new uint256[](count);
        for (uint256 i = count; i > 0; --i) {
            expirations[i - 1] = _attestationExpirations[keccak256(abi.encode(attestation_, i))];
        }
        return expirations;
    }
}
