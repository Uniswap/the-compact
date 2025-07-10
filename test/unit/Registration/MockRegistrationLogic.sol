// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "src/lib/TheCompactLogic.sol";
import "src/lib/RegistrationLogic.sol";
import "src/lib/RegistrationLib.sol";
import "src/lib/HashLib.sol";
import "src/types/EIP712Types.sol";

contract MockRegistrationLogic is TheCompactLogic {
    using RegistrationLib for address;
    using RegistrationLib for bytes32;
    using RegistrationLib for bytes32[2][];

    function register(address sponsor, bytes32 claimHash, bytes32 typehash) external {
        _register(sponsor, claimHash, typehash);
    }

    function registerBatch(bytes32[2][] calldata claimHashesAndTypehashes) external returns (bool) {
        return _registerBatch(claimHashesAndTypehashes);
    }

    function isRegistered(address sponsor, bytes32 claimHash, bytes32 typehash) external view returns (bool) {
        return _isRegistered(sponsor, claimHash, typehash);
    }

    function registerUsingCompact(
        address sponsor,
        uint256 tokenId,
        uint256 amount,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external returns (bytes32) {
        return _registerUsingCompact(sponsor, tokenId, amount, arbiter, nonce, expires, typehash, witness);
    }

    function registerUsingBatchCompact(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external returns (bytes32 claimHash) {
        uint256[] memory replacementAmounts = new uint256[](idsAndAmounts.length);
        for (uint256 i = 0; i < idsAndAmounts.length; ++i) {
            replacementAmounts[i] = idsAndAmounts[i][1];
        }
        return _registerUsingBatchCompact(
            sponsor, idsAndAmounts, arbiter, nonce, expires, typehash, witness, replacementAmounts
        );
    }
}
