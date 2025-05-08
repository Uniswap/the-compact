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

    function getRegistrationStatus(address sponsor, bytes32 claimHash, bytes32 typehash)
        external
        view
        returns (uint256)
    {
        return _getRegistrationStatus(sponsor, claimHash, typehash);
    }

    function registerUsingClaimWithWitness(
        address sponsor,
        uint256 tokenId,
        uint256 amount,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external returns (bytes32) {
        return _registerUsingClaimWithWitness(sponsor, tokenId, amount, arbiter, nonce, expires, typehash, witness);
    }

    function registerUsingBatchClaimWithWitness(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external returns (bytes32 claimHash) {
        return _registerUsingBatchClaimWithWitness(
            sponsor, idsAndAmounts, arbiter, nonce, expires, typehash, witness, new uint256[](0)
        );
    }
}
