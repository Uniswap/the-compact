// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test } from "forge-std/Test.sol";
import { TheCompact } from "../../src/TheCompact.sol";
import { MockERC20 } from "../../lib/solady/test/utils/mocks/MockERC20.sol";
import { Compact, BatchCompact, Element } from "../../src/types/EIP712Types.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { CompactCategory } from "../../src/types/CompactCategory.sol";
import { DepositDetails } from "../../src/types/DepositDetails.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

import { HashLib } from "../../src/lib/HashLib.sol";
import { IdLib } from "../../src/lib/IdLib.sol";

import { AlwaysOKAllocator } from "../../src/test/AlwaysOKAllocator.sol";
import { AlwaysOKEmissary } from "../../src/test/AlwaysOKEmissary.sol";
import { SimpleAllocator } from "../../src/examples/allocator/SimpleAllocator.sol";
import { QualifiedAllocator } from "../../src/examples/allocator/QualifiedAllocator.sol";

import { AllocatedTransfer, Claim } from "../../src/types/Claims.sol";
import { AllocatedBatchTransfer, BatchClaim } from "../../src/types/BatchClaims.sol";

import { MultichainClaim, ExogenousMultichainClaim } from "../../src/types/MultichainClaims.sol";

import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../../src/types/BatchMultichainClaims.sol";

import { Component, TransferComponent, ComponentsById, BatchClaimComponent } from "../../src/types/Components.sol";

import { Lock } from "../../src/types/EIP712Types.sol";

import {
    TestParams,
    LockDetails,
    CreateClaimHashWithWitnessArgs,
    CreateBatchClaimHashWithWitnessArgs,
    CreatePermitBatchWitnessDigestArgs,
    CreateMultichainClaimHashWithWitnessArgs,
    SetupPermitCallExpectationArgs
} from "./TestHelperStructs.sol";

contract TestHelpers is Test {
    function _countLeadingZeroes(address a) internal pure returns (uint256) {
        address flag = address(0x0fffFFFFFfFfffFfFfFFffFffFffFFfffFfFFFFf);

        // addresses have a maximum of 40 leading 0s
        for (uint256 i = 0; i < 40; i++) {
            if (uint160(a) > uint160(uint160(flag) >> (4 * i))) return i;
        }
        // if the loop exits, the address is the 0 address
        return 40;
    }

    /**
     * Helper function to create a lock tag with the given parameters
     */
    function _createLockTag(ResetPeriod resetPeriod, Scope scope, uint96 allocatorId) internal pure returns (bytes12) {
        return bytes12(bytes32((uint256(scope) << 255) | (uint256(resetPeriod) << 252) | (uint256(allocatorId) << 160)));
    }

    /**
     * Helper function to create a witness hash for a compact witness
     */
    function _createCompactWitness(uint256 _witnessArgument) internal pure returns (bytes32 witness) {
        witness = keccak256(abi.encode(keccak256("Mandate(uint256 witnessArgument)"), _witnessArgument));
        return witness;
    }

    /**
     * Helper function to create a claim hash with a CreateClaimHashWithWitnessArgs struct
     */
    function _createClaimHash(CreateClaimHashWithWitnessArgs memory args) internal pure returns (bytes32) {
        bytes12 lockTag = bytes12(bytes32(args.id));
        address token = address(uint160(args.id));
        return keccak256(
            abi.encode(args.typehash, args.arbiter, args.sponsor, args.nonce, args.expires, lockTag, token, args.amount)
        );
    }

    /**
     * Helper function to create a claim hash
     */
    function _createClaimHash(
        bytes32 typehash,
        address arbiter,
        address sponsor,
        uint256 nonce,
        uint256 expires,
        uint256 id,
        uint256 amount
    ) internal pure returns (bytes32) {
        bytes12 lockTag = bytes12(bytes32(id));
        address token = address(uint160(id));
        return keccak256(abi.encode(typehash, arbiter, sponsor, nonce, expires, lockTag, token, amount));
    }

    /**
     * Helper function to create a claim hash with witness
     */
    function _createClaimHashWithWitness(CreateClaimHashWithWitnessArgs memory args) internal pure returns (bytes32) {
        bytes12 lockTag = bytes12(bytes32(args.id));
        address token = address(uint160(args.id));
        return keccak256(
            abi.encode(
                args.typehash,
                args.arbiter,
                args.sponsor,
                args.nonce,
                args.expires,
                lockTag,
                token,
                args.amount,
                args.witness
            )
        );
    }

    /**
     * Helper function to create a batch claim hash
     */
    function _createBatchClaimHash(CreateBatchClaimHashWithWitnessArgs memory args) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(args.typehash, args.arbiter, args.sponsor, args.nonce, args.expires, args.idsAndAmountsHash)
        );
    }

    /**
     * Helper function to create a batch claim hash with witness
     */
    function _createBatchClaimHashWithWitness(CreateBatchClaimHashWithWitnessArgs memory args)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                args.typehash,
                args.arbiter,
                args.sponsor,
                args.nonce,
                args.expires,
                args.idsAndAmountsHash,
                args.witness
            )
        );
    }

    function _createMultichainClaimHashWithWitness(CreateMultichainClaimHashWithWitnessArgs memory args)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(args.typehash, args.sponsor, args.nonce, args.expires, args.elementsHash));
    }

    function _createMultichainElementsHash(bytes32 typeHash, Element[] memory elements, bytes32[] memory witnessHashes)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory elementHashes = new bytes32[](elements.length);
        for (uint256 i = 0; i < elements.length; ++i) {
            elementHashes[i] = _createMultichainElementHash(
                typeHash, elements[i].arbiter, elements[i].chainId, elements[i].commitments, witnessHashes[i]
            );
        }
        return keccak256(abi.encode(elementHashes));
    }

    function _createMultichainElementHash(
        bytes32 typeHash,
        address arbiter,
        uint256 chainId,
        Lock[] memory commitments,
        bytes32 witnessHash
    ) internal pure returns (bytes32) {
        bytes32 lockTypehash = keccak256(bytes("Lock(bytes12 lockTag,address token,uint256 amount)"));
        bytes32[] memory lockHashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; ++i) {
            Lock memory lock = commitments[i];
            lockHashes[i] = keccak256(abi.encode(lockTypehash, lock.lockTag, lock.token, lock.amount));
        }

        return keccak256(abi.encode(typeHash, arbiter, chainId, keccak256(abi.encode(lockHashes)), witnessHash));
    }

    function _createDigest(bytes32 domainSeparator, bytes32 hashValue) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, hashValue));
    }

    /**
     * Helper function to create a permit batch digest
     */
    function _createPermitBatchDigest(CreatePermitBatchWitnessDigestArgs memory args) internal pure returns (bytes32) {
        bytes32 activationHash =
            keccak256(abi.encode(args.activationTypehash, address(1010), args.idsHash, args.claimHash));

        bytes32 permitBatchHash = keccak256(
            abi.encode(
                keccak256(
                    "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,BatchActivation witness)BatchActivation(address activator,uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments)Lock(bytes12 lockTag,address token,uint256 amount)TokenPermissions(address token,uint256 amount)"
                ),
                args.tokenPermissionsHash,
                args.spender,
                args.nonce,
                args.deadline,
                activationHash
            )
        );

        return keccak256(abi.encodePacked(bytes2(0x1901), args.domainSeparator, permitBatchHash));
    }

    /**
     * Helper function to create a permit batch witness digest
     */
    function _createPermitBatchWitnessDigest(CreatePermitBatchWitnessDigestArgs memory args)
        internal
        pure
        returns (bytes32)
    {
        bytes32 activationHash =
            keccak256(abi.encode(args.activationTypehash, address(1010), args.idsHash, args.claimHash));

        bytes32 permitBatchHash = keccak256(
            abi.encode(
                keccak256(
                    "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,BatchActivation witness)BatchActivation(address activator,uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint256 witnessArgument)TokenPermissions(address token,uint256 amount)"
                ),
                args.tokenPermissionsHash,
                args.spender,
                args.nonce,
                args.deadline,
                activationHash
            )
        );

        return keccak256(abi.encodePacked(bytes2(0x1901), args.domainSeparator, permitBatchHash));
    }

    function _createPermitWitnessDigest(
        bytes32 domainSeparator,
        address permitToken,
        uint256 amount,
        address spender,
        uint256 nonce,
        uint256 deadline,
        bytes32 witnessHash
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256(
                            "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,CompactDeposit witness)CompactDeposit(bytes12 lockTag,address recipient)TokenPermissions(address token,uint256 amount)"
                        ),
                        keccak256(
                            abi.encode(keccak256("TokenPermissions(address token,uint256 amount)"), permitToken, amount)
                        ),
                        spender,
                        nonce,
                        deadline,
                        witnessHash
                    )
                )
            )
        );
    }
}
