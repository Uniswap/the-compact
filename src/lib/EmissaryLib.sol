// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ConsumerLib } from "./ConsumerLib.sol";
import { ValidityLib } from "./ValidityLib.sol";
import { EMISSARY_ASSIGNMENT_TYPEHASH } from "../types/EIP712Types.sol";

// An emissary can register claims on behalf of a sponsor that has assigned them.
// It works kind of like setApprovalForAll and applies to all locks. One caveat
// is that allocators still have to authorize any claims, which reduces the risk
// of a fully rogue emissary depending on the allocator in question.
// NOTE: this idea is inherently risky; think about whether it's worth it! Right
// now this functionality is not included in The Compact.
abstract contract EmissaryLib {
    using ValidityLib for uint256;
    using ValidityLib for address;
    using ConsumerLib for uint256;

    event EmissaryAssignment(address indexed sponsor, address indexed emissary, bool assigned);

    error InvalidEmissary(address sponsor, address emissary);

    // TODO: optimize
    mapping(address => mapping(address => bool)) private _emissaries;

    // TODO: this mapping already exists on The Compact; just use one of them!
    mapping(address => mapping(bytes32 => bytes32)) private _registeredClaimHashes;

    function registerFor(address sponsor, bytes32 claimHash, bytes32 typehash) external returns (bool) {
        // TODO: optimize
        if (!_emissaries[sponsor][msg.sender]) {
            revert InvalidEmissary(sponsor, msg.sender);
        }
        _registeredClaimHashes[sponsor][claimHash] = typehash;
        return true;
    }

    function registerFor(address sponsor, bytes32[2][] calldata claimHashesAndTypehashes) external returns (bool) {
        // TODO: optimize
        if (!_emissaries[sponsor][msg.sender]) {
            revert InvalidEmissary(sponsor, msg.sender);
        }

        return _registerFor(sponsor, claimHashesAndTypehashes);
    }

    function assignEmissary(address sponsor, address emissary, uint256 nonce, uint256 expires, bool assigned, bytes calldata /*sponsorSignature*/ ) external returns (bool) {
        expires.later();

        bytes32 messageHash;
        assembly ("memory-safe") {
            let m := mload(0x40) // Grab the free memory pointer; memory will be left dirtied.
            mstore(m, EMISSARY_ASSIGNMENT_TYPEHASH)
            mstore(add(m, 0x20), emissary)
            mstore(add(m, 0x40), nonce)
            mstore(add(m, 0x60), expires)
            mstore(add(m, 0x80), assigned)
            messageHash := keccak256(m, 0xa0)
        }

        // TODO: this function should be colocated with the rest of The Compact as it has the immutable args here
        // messageHash.signedBy(sponsor, sponsorSignature, _INITIAL_DOMAIN_SEPARATOR.toLatest(_INITIAL_CHAIN_ID));

        nonce.consumeNonceAsSponsor(sponsor);

        return _assignEmissary(sponsor, emissary, assigned);
    }

    function assignEmissary(address emissary, bool assigned) external returns (bool) {
        return _assignEmissary(msg.sender, emissary, assigned);
    }

    function hasConsumedEmissaryAssignmentNonce(uint256 nonce, address sponsor) external view returns (bool consumed) {
        consumed = nonce.isConsumedBySponsor(sponsor);
    }

    function _assignEmissary(address sponsor, address emissary, bool assigned) internal returns (bool) {
        _emissaries[sponsor][emissary] = assigned;

        emit EmissaryAssignment(sponsor, emissary, assigned);

        return true;
    }

    // TODO: this is already on the compact, just use one of them
    function _registerFor(address sponsor, bytes32[2][] calldata claimHashesAndTypehashes) internal returns (bool) {
        unchecked {
            uint256 totalClaimHashes = claimHashesAndTypehashes.length;
            for (uint256 i = 0; i < totalClaimHashes; ++i) {
                bytes32[2] calldata claimHashAndTypehash = claimHashesAndTypehashes[i];
                _registeredClaimHashes[sponsor][claimHashAndTypehash[0]] = claimHashAndTypehash[1];
            }
        }

        return true;
    }
}
