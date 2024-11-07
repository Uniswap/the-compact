// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title DomainLib
 * @notice Library contract implementing logic for deriving domain hashes.
 */
library DomainLib {
    /// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
    bytes32 internal constant _DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /// @dev `keccak256(bytes("The Compact"))`.
    bytes32 internal constant _NAME_HASH = 0x5e6f7b4e1ac3d625bac418bc955510b3e054cb6cc23cc27885107f080180b292;

    /// @dev `keccak256("0")`.
    bytes32 internal constant _VERSION_HASH = 0x044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d;

    function toLatest(bytes32 initialDomainSeparator, uint256 initialChainId) internal view returns (bytes32 domainSeparator) {
        // Set the initial domain separator as the default domain separator.
        domainSeparator = initialDomainSeparator;

        assembly ("memory-safe") {
            // Rederive the domain separator if the initial chain ID differs from the current one.
            if xor(chainid(), initialChainId) {
                // Retrieve the free memory pointer.
                let m := mload(0x40)

                // Prepare domain data: EIP-712 typehash, name hash, version hash, chain ID, and verifying contract.
                mstore(m, _DOMAIN_TYPEHASH)
                mstore(add(m, 0x20), _NAME_HASH)
                mstore(add(m, 0x40), _VERSION_HASH)
                mstore(add(m, 0x60), chainid())
                mstore(add(m, 0x80), address())

                // Derive the domain separator.
                domainSeparator := keccak256(m, 0xa0)
            }
        }
    }

    function toNotarizedDomainSeparator(uint256 notarizedChainId) internal view returns (bytes32 notarizedDomainSeparator) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer.
            let m := mload(0x40)

            // Prepare domain data: EIP-712 typehash, name hash, version hash, notarizing chain ID, and verifying contract.
            mstore(m, _DOMAIN_TYPEHASH)
            mstore(add(m, 0x20), _NAME_HASH)
            mstore(add(m, 0x40), _VERSION_HASH)
            mstore(add(m, 0x60), notarizedChainId)
            mstore(add(m, 0x80), address())

            // Derive the domain separator.
            notarizedDomainSeparator := keccak256(m, 0xa0)
        }
    }

    function withDomain(bytes32 messageHash, bytes32 domainSeparator) internal pure returns (bytes32 domainHash) {
        assembly ("memory-safe") {
            // Retrieve and cache the free memory pointer.
            let m := mload(0x40)

            // Prepare the 712 prefix.
            mstore(0, 0x1901)

            // Prepare the domain separator.
            mstore(0x20, domainSeparator)

            // Prepare the message hash and compute the domain hash.
            mstore(0x40, messageHash)
            domainHash := keccak256(0x1e, 0x42)

            // Restore the free memory pointer.
            mstore(0x40, m)
        }
    }
}
