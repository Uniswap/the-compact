// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IAllocator, ResetPeriod } from "../../interfaces/IAllocator.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

interface EIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

contract QualifiedAllocator is IAllocator {
    using SignatureCheckerLib for address;

    address public signer;
    EIP712 internal immutable COMPACT;

    constructor(address _signer, address compact) {
        signer = _signer;
        COMPACT = EIP712(compact);
    }

    function attest(address, address, address, uint256, uint256) external pure returns (bytes4) {
        revert("unimplemented");
    }

    function authorizeClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address arbiter, // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256 nonce, // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) external view returns (bytes4) {
        require(isClaimAuthorized(claimHash, arbiter, sponsor, nonce, expires, idsAndAmounts, allocatorData), "Invalid Sig");

        return this.authorizeClaim.selector;
    }

    function isClaimAuthorized(
        bytes32 claimHash, // The message hash representing the claim.
        address arbiter, // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256 nonce, // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) public view returns (bool) {
        arbiter;
        sponsor;
        nonce;
        expires;
        idsAndAmounts;

        (bytes memory signature, bytes32 qualificationArg) = abi.decode(allocatorData, (bytes, bytes32));

        bytes32 qualifiedHash = keccak256(abi.encode(keccak256("QualifiedClaim(bytes32 claimHash,bytes32 qualificationArg)"), claimHash, qualificationArg));
        // pulling the domain separator for every authorizeClaim call is inefficient, and should not be used in prod.
        // this is just for test purposes, since TheCompact.t.sol is using vm.chainId().
        // @dev Consider inheriting EIP712 in the Allocator or caching the compact domain separator as an immutable
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), COMPACT.DOMAIN_SEPARATOR(), qualifiedHash));

        return signer.isValidSignatureNow(digest, signature);
    }
}
