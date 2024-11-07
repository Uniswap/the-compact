// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title ConsumerLib
 * @notice Libray contract implementing logic for consuming bitpacked nonces scoped to
 * specific accounts and for querying for the state of those nonces. Note that only the
 * allocator nonce scope is currently in use in The Compact.
 */
library ConsumerLib {
    // Storage scope identifiers for nonce buckets.
    uint256 private constant _ALLOCATOR_NONCE_SCOPE = 0x03f37b1a;
    uint256 private constant _SPONSOR_NONCE_SCOPE = 0x8ccd9613;

    // Error thrown when attempting to consume an already-consumed nonce.
    error InvalidNonce(address account, uint256 nonce);

    /**
     * @notice Internal function for consuming a nonce in the allocator's scope.
     * @param nonce     The nonce to consume.
     * @param allocator The address of the allocator whose scope to consume the nonce in.
     */
    function consumeNonceAsAllocator(uint256 nonce, address allocator) internal {
        _consumeNonce(nonce, allocator, _ALLOCATOR_NONCE_SCOPE);
    }

    /**
     * @notice Internal view function for checking if a nonce has been consumed in the
     * allocator's scope.
     * @param nonceToCheck The nonce to check.
     * @param allocator    The address of the allocator whose scope to check.
     * @return consumed    Whether the nonce has been consumed.
     */
    function isConsumedByAllocator(uint256 nonceToCheck, address allocator) internal view returns (bool consumed) {
        return _isConsumedBy(nonceToCheck, allocator, _ALLOCATOR_NONCE_SCOPE);
    }

    /**
     * @notice Internal function for consuming a nonce in the sponsor's scope.
     * @param nonce   The nonce to consume.
     * @param sponsor The address of the sponsor whose scope to consume the nonce in.
     */
    function consumeNonceAsSponsor(uint256 nonce, address sponsor) internal {
        _consumeNonce(nonce, sponsor, _SPONSOR_NONCE_SCOPE);
    }

    /**
     * @notice Internal view function for checking if a nonce has been consumed in the
     * sponsor's scope.
     * @param nonceToCheck The nonce to check.
     * @param sponsor      The address of the sponsor whose scope to check.
     * @return consumed    Whether the nonce has been consumed.
     */
    function isConsumedBySponsor(uint256 nonceToCheck, address sponsor) internal view returns (bool consumed) {
        return _isConsumedBy(nonceToCheck, sponsor, _SPONSOR_NONCE_SCOPE);
    }

    /**
     * @notice Private function implementing nonce consumption logic. Uses the last byte
     * of the nonce to determine which bit to set in a 256-bit storage bucket unique to
     * the account and scope. Reverts if the nonce has already been consumed.
     * @param nonce   The nonce to consume.
     * @param account The address of the account whose scope to consume the nonce in.
     * @param scope   The scope identifier to consume the nonce in.
     */
    function _consumeNonce(uint256 nonce, address account, uint256 scope) private {
        // The last byte of the nonce is used to assign a bit in a 256-bit bucket;
        // specific nonces are consumed for each account and can only be used once.
        // NOTE: this function temporarily overwrites the free memory pointer, but
        // restores it before returning.
        assembly ("memory-safe") {
            // Store free memory pointer; its memory location will be overwritten.
            let freeMemoryPointer := mload(0x40)

            // derive the nonce bucket slot:
            // keccak256(_CONSUMER_NONCE_SCOPE ++ account ++ nonce[0:31])
            mstore(0x20, account)
            mstore(0x0c, scope)
            mstore(0x40, nonce)
            let bucketSlot := keccak256(0x28, 0x37)

            // Retrieve nonce bucket and check if nonce has been consumed.
            let bucketValue := sload(bucketSlot)
            let bit := shl(and(0xff, nonce), 1)
            if and(bit, bucketValue) {
                // `InvalidNonce(address,uint256)` with padding for `account`.
                mstore(0x0c, 0xdbc205b1000000000000000000000000)
                revert(0x1c, 0x44)
            }

            // Invalidate the nonce by setting its bit.
            sstore(bucketSlot, or(bucketValue, bit))

            // Restore the free memory pointer.
            mstore(0x40, freeMemoryPointer)
        }
    }

    /**
     * @notice Private view function implementing nonce consumption checking logic.
     * Uses the last byte of the nonce to determine which bit to check in a 256-bit
     * storage bucket unique to the account and scope.
     * @param nonceToCheck The nonce to check.
     * @param account      The address of the account whose scope to check.
     * @param scope        The scope identifier to check.
     * @return consumed    Whether the nonce has been consumed.
     */
    function _isConsumedBy(uint256 nonceToCheck, address account, uint256 scope) private view returns (bool consumed) {
        assembly ("memory-safe") {
            // Store free memory pointer; its memory location will be overwritten.
            let freeMemoryPointer := mload(0x40)

            // derive the nonce bucket slot:
            // keccak256(_CONSUMER_NONCE_SCOPE ++ account ++ nonce[0:31])
            mstore(0x20, account)
            mstore(0x0c, scope)
            mstore(0x40, nonceToCheck)

            // Retrieve nonce bucket value and determine whether the nonce is set.
            consumed := and(shl(and(0xff, nonceToCheck), 1), sload(keccak256(0x28, 0x37)))

            // Restore the free memory pointer.
            mstore(0x40, freeMemoryPointer)
        }
    }
}
