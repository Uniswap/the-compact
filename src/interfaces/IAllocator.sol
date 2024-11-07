// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// NOTE: Allocators with smart contract implementations should also implement EIP1271.
interface IAllocator {
    // Called on standard transfers; must return this function selector (0x1a808f91).
    function attest(address operator, address from, address to, uint256 id, uint256 amount) external returns (bytes4);
}
