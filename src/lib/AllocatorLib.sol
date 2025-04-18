// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IAllocator } from "../interfaces/IAllocator.sol";

library AllocatorLib {
    error InvalidAllocation(address allocator);

    // bytes4(keccak256("authorizeClaim(bytes32,address,address,uint256,uint256,uint256[2][],bytes)")).
    uint32 private constant _AUTHORIZE_CLAIM_SELECTOR = 0x7bb023f7;
    uint256 private constant _AUTHORIZE_CLAIM_IDS_AND_AMOUNTS_CALLDATA_POINTER = 0xe0;

    function callAuthorizeClaim(
        address allocator,
        bytes32 claimHash,
        address sponsor,
        uint256 nonce,
        uint256 expires,
        uint256[2][] memory idsAndAmounts,
        bytes calldata allocatorData
    ) internal {
        assembly ("memory-safe") {
            // Sanitize sponsor.
            sponsor := shr(0x60, shl(0x60, sponsor))

            // Retrieve the free memory pointer; memory will be left dirtieed.
            let m := mload(0x40)

            // Get length of idsAndAmounts array, both in elements and as data.
            let totalIdsAndAmounts := mload(idsAndAmounts)
            let totalIdsAndAmountsDataLength := shl(6, totalIdsAndAmounts)

            // Prepare fixed-location components of calldata.
            mstore(m, _AUTHORIZE_CLAIM_SELECTOR)
            mstore(add(m, 0x20), claimHash)
            mstore(add(m, 0x40), caller())
            mstore(add(m, 0x60), sponsor)
            mstore(add(m, 0x80), nonce)
            mstore(add(m, 0xa0), expires)
            mstore(add(m, 0xc0), _AUTHORIZE_CLAIM_IDS_AND_AMOUNTS_CALLDATA_POINTER)
            mstore(add(m, 0xe0), add(totalIdsAndAmountsDataLength, 0x100))
            mstore(add(m, 0x100), totalIdsAndAmounts)

            {
                // Copy each element from idsAndAmounts array in memory.
                let dstStart := add(m, 0x120)
                let totalIdsAndAmountsTimesOneWord := shl(5, totalIdsAndAmounts)
                for { let i := 0 } lt(i, totalIdsAndAmountsTimesOneWord) { i := add(i, 0x20) } {
                    let dstPos := add(dstStart, shl(1, i))
                    let srcPos := mload(add(idsAndAmounts, add(i, 0x20)))
                    mstore(dstPos, mload(srcPos))
                    mstore(add(dstPos, 0x20), mload(add(srcPos, 0x20)))
                }

                // Copy allocator data from calldata.
                let allocatorDataMemoryOffset := add(dstStart, totalIdsAndAmountsDataLength)
                mstore(allocatorDataMemoryOffset, allocatorData.length)
                calldatacopy(add(allocatorDataMemoryOffset, 0x20), allocatorData.offset, allocatorData.length)
            }

            // Ensure sure initial scratch space is cleared as an added precaution.
            mstore(0, 0)

            // Perform call to allocator and write response to scratch space.
            let success :=
                call(
                    gas(),
                    allocator,
                    0,
                    add(m, 0x1c),
                    add(0x124, add(totalIdsAndAmountsDataLength, allocatorData.length)),
                    0,
                    0x20
                )

            // Revert if the required magic value was not received back or really huge idsAndAmounts was supplied.
            if or(gt(totalIdsAndAmounts, 0xffffffff), iszero(eq(mload(0), shl(224, _AUTHORIZE_CLAIM_SELECTOR)))) {
                // Bubble up revert if the call failed and there's data.
                // NOTE: consider evaluating remaining gas to protect against revert bombing.
                if iszero(or(success, iszero(returndatasize()))) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }

                // revert InvalidAllocation(allocator)
                mstore(0, 0x2ce89d2a)
                mstore(0x20, shr(0x60, shl(0x60, allocator)))
                revert(0x1c, 0x24)
            }
        }
    }
}
