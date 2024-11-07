// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC1271 } from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";

interface IAllocator is IERC1271 {
    // Called on standard transfers; must return this function selector (0x1a808f91).
    function attest(address operator, address from, address to, uint256 id, uint256 amount) external returns (bytes4);

    // isValidSignature of IERC1271 will be called during a claim and must verify the signature of the allocation.
}
