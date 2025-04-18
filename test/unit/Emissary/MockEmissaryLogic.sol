// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "src/lib/TheCompactLogic.sol";
import "src/lib/ValidityLib.sol";
import "src/lib/EmissaryLib.sol";
import "src/lib/DomainLib.sol";
import "src/lib/IdLib.sol";

contract MockEmissaryLogic is TheCompactLogic {
    using EmissaryLib for bytes32;
    using DomainLib for bytes32;
    using IdLib for address;
    using IdLib for uint96;

    function registerAllocator(address allocator, bytes calldata proof) external returns (uint96) {
        return _registerAllocator(allocator, proof);
    }

    function scheduleEmissaryAssignment(bytes12 lockTag) external returns (uint256) {
        return _scheduleEmissaryAssignment(lockTag);
    }

    function assignEmissary(bytes12 lockTag, address emissary) external returns (bool) {
        return _assignEmissary(lockTag, emissary);
    }

    function verifyWithEmissary(
        address sponsor,
        bytes calldata signature,
        bytes32 messageHash,
        address allocator,
        ResetPeriod resetPeriod,
        Scope scope
    ) external view returns (bool) {
        bytes32 domainSeparator = _domainSeparator();
        bytes32 claimHash = messageHash.withDomain(domainSeparator);

        bytes12 lockTag = allocator.toAllocatorIdIfRegistered().toLockTag(scope, resetPeriod);
        claimHash.verifyWithEmissary(sponsor, lockTag, signature);
        return true;
    }

    function getEmissaryStatus(address sponsor, bytes12 lockTag)
        external
        view
        returns (EmissaryStatus status, uint256 assignableAt, address currentEmissary)
    {
        return _getEmissaryStatus(sponsor, lockTag);
    }
}
