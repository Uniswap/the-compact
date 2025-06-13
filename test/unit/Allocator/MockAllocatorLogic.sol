// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "src/lib/TheCompactLogic.sol";
import "src/lib/AllocatorLogic.sol";
import "src/lib/IdLib.sol";
import "src/lib/ConsumerLib.sol";
import "src/lib/ValidityLib.sol";

contract MockAllocatorLogic is TheCompactLogic {
    using IdLib for address;
    using IdLib for uint96;
    using ConsumerLib for uint256;
    using ValidityLib for address;

    // Expose internal functions for testing
    function registerAllocator(address allocator, bytes calldata proof) external returns (uint96) {
        return _registerAllocator(allocator, proof);
    }

    function consume(uint256[] calldata nonces) external returns (bool) {
        return _consume(nonces);
    }

    function hasConsumedAllocatorNonce(uint256 nonce, address allocator) external view returns (bool) {
        return _hasConsumedAllocatorNonce(nonce, allocator);
    }

    function getLockDetails(uint256 id)
        external
        view
        returns (address token, address allocator, ResetPeriod resetPeriod, Scope scope, bytes12 lockTag)
    {
        return _getLockDetails(id);
    }
}
