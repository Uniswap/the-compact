// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Compact, BatchCompact, Element } from "../../src/types/EIP712Types.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { CompactCategory } from "../../src/types/CompactCategory.sol";
import { DepositDetails } from "../../src/types/DepositDetails.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

import { Component, BatchClaimComponent } from "../../src/types/Components.sol";
import { Claim } from "../../src/types/Claims.sol";
import { BatchClaim } from "../../src/types/BatchClaims.sol";
import { MultichainClaim, ExogenousMultichainClaim } from "../../src/types/MultichainClaims.sol";
import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../../src/types/BatchMultichainClaims.sol";

struct CreateClaimHashWithWitnessArgs {
    bytes32 typehash;
    address arbiter;
    address sponsor;
    uint256 nonce;
    uint256 expires;
    uint256 id;
    uint256 amount;
    bytes32 witness;
}

struct CreateBatchClaimHashWithWitnessArgs {
    bytes32 typehash;
    address arbiter;
    address sponsor;
    uint256 nonce;
    uint256 expires;
    bytes32 idsAndAmountsHash;
    bytes32 witness;
}

struct CreatePermitBatchWitnessDigestArgs {
    bytes32 domainSeparator;
    bytes32 tokenPermissionsHash;
    address spender;
    uint256 nonce;
    uint256 deadline;
    bytes32 activationTypehash;
    bytes32 idsHash;
    bytes32 claimHash;
}

struct SetupPermitCallExpectationArgs {
    bytes32 activationTypehash;
    uint256[] ids;
    bytes32 claimHash;
    uint256 nonce;
    uint256 deadline;
    bytes signature;
}

struct TestParams {
    address recipient;
    ResetPeriod resetPeriod;
    Scope scope;
    uint256 amount;
    uint256 nonce;
    uint256 deadline;
    uint256 id;
}

struct LockDetails {
    address token;
    address allocator;
    ResetPeriod resetPeriod;
    Scope scope;
    bytes12 lockTag;
}

struct BatchMultichainClaimArgs {
    TestParams params;
    BatchMultichainClaim claim;
    uint256 anotherChainId;
    uint256[] ids;
    uint256[2][] idsAndAmountsOne;
    uint256[2][] idsAndAmountsTwo;
    bytes32 allocationHashOne;
    bytes32 allocationHashTwo;
    bytes32 claimHash;
    bytes32 initialDomainSeparator;
    ExogenousBatchMultichainClaim anotherClaim;
}
