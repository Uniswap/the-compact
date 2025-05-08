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

    /// @dev `keccak256("1")`.
    bytes32 internal constant _VERSION_HASH = 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;

    /**
     * @notice Internal view function that returns the current domain separator, deriving a new one
     * if the chain ID has changed from the initial chain ID.
     * @param initialDomainSeparator The domain separator derived at deployment time.
     * @param initialChainId         The chain ID at the time of deployment.
     * @return domainSeparator       The current domain separator.
     */
    function toLatest(bytes32 initialDomainSeparator, uint256 initialChainId)
        internal
        view
        returns (bytes32 domainSeparator)
    {
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

    /**
     * @notice Internal view function that derives a domain separator for a specific chain ID.
     * Used for notarizing multichain claims with segments that will be executed on a different chain.
     * @param notarizedChainId          The chain ID to derive the domain separator for.
     * @return notarizedDomainSeparator The domain separator for the specified chain ID.
     */
    function toNotarizedDomainSeparator(uint256 notarizedChainId)
        internal
        view
        returns (bytes32 notarizedDomainSeparator)
    {
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

    /**
     * @notice Internal pure function that combines a message hash with a domain separator
     * to create a domain-specific hash according to EIP-712.
     * @param messageHash     The EIP-712 hash of the message data.
     * @param domainSeparator The domain separator to combine with the message hash.
     * @return domainHash     The domain-specific hash.
     */
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
