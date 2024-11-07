// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title Extsload
 * @notice Contract implementing external functions for reading values from
 * storage or transient storage directly.
 */
contract Extsload {
    function exttload(bytes32 slot) external view returns (bytes32) {
        assembly ("memory-safe") {
            mstore(0, tload(slot))
            return(0, 0x20)
        }
    }

    function extsload(bytes32 slot) external view returns (bytes32) {
        assembly ("memory-safe") {
            mstore(0, sload(slot))
            return(0, 0x20)
        }
    }

    function extsload(bytes32[] calldata slots) external view returns (bytes32[] memory) {
        assembly ("memory-safe") {
            let memptr := mload(0x40)
            let start := memptr
            // for abi encoding the response - the array will be found at 0x20
            mstore(memptr, 0x20)
            // next we store the length of the return array
            mstore(add(memptr, 0x20), slots.length)
            // update memptr to the first location to hold an array entry
            memptr := add(memptr, 0x40)
            // A left bit-shift of 5 is equivalent to multiplying by 32 but costs less gas.
            let end := add(memptr, shl(5, slots.length))
            let calldataptr := slots.offset
            for { } 1 { } {
                mstore(memptr, sload(calldataload(calldataptr)))
                memptr := add(memptr, 0x20)
                calldataptr := add(calldataptr, 0x20)
                if iszero(lt(memptr, end)) { break }
            }
            return(start, sub(end, start))
        }
    }
}
