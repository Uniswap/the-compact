// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title EventLib
 * @notice Library contract implementing logic for internal functions to
 * emit various events.
 * @dev Note that most events are still emitted using inline logic; this
 * library only implements a few events.
 */
library EventLib {
    // keccak256(bytes("Claim(address,address,address,bytes32)")).
    uint256 private constant _CLAIM_EVENT_SIGNATURE = 0x770c32a2314b700d6239ee35ba23a9690f2fceb93a55d8c753e953059b3b18d4;

    // keccak256(bytes("ForcedWithdrawalStatusUpdated(address,uint256,bool,uint256)")).
    uint256 private constant _FORCED_WITHDRAWAL_STATUS_UPDATED_SIGNATURE =
        0xe27f5e0382cf5347965fc81d5c81cd141897fe9ce402d22c496b7c2ddc84e5fd;

    /**
     * @notice Internal function for emitting claim events. The sponsor and allocator
     * addresses are sanitized before emission.
     * @param sponsor   The account sponsoring the compact that the claim is for.
     * @param claimHash The EIP-712 hash of the claim message.
     * @param allocator The account mediating the claim.
     * @param nonce     The nonce on the claimed compact.
     */
    function emitClaim(address sponsor, bytes32 claimHash, address allocator, uint256 nonce) internal {
        assembly ("memory-safe") {
            // Emit the Claim event:
            //  - topic1: Claim event signature
            //  - topic2: sponsor address (sanitized)
            //  - topic3: allocator address (sanitized)
            //  - topic4: caller address
            //  - data: messageHash, nonce
            mstore(0, claimHash)
            mstore(0x20, nonce)
            log4(
                0,
                0x40,
                _CLAIM_EVENT_SIGNATURE,
                shr(0x60, shl(0x60, sponsor)),
                shr(0x60, shl(0x60, allocator)),
                caller()
            )
        }
    }

    /**
     * @notice Internal function for emitting forced withdrawal status update events.
     * @param id             The ERC6909 token identifier of the resource lock.
     * @param withdrawableAt The timestamp when withdrawal becomes possible.
     */
    function emitForcedWithdrawalStatusUpdatedEvent(uint256 id, uint256 withdrawableAt) internal {
        assembly ("memory-safe") {
            // Emit ForcedWithdrawalStatusUpdated event:
            //  - topic1: Event signature
            //  - topic2: Caller address
            //  - topic3: Token id
            //  - data: [activating flag, withdrawableAt timestamp]
            mstore(0, iszero(iszero(withdrawableAt)))
            mstore(0x20, withdrawableAt)
            log3(0, 0x40, _FORCED_WITHDRAWAL_STATUS_UPDATED_SIGNATURE, caller(), id)
        }
    }
}
