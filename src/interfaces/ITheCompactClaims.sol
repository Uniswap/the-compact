// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BasicClaim, QualifiedClaim, ClaimWithWitness, QualifiedClaimWithWitness, SplitClaim, SplitClaimWithWitness, QualifiedSplitClaim, QualifiedSplitClaimWithWitness } from "../types/Claims.sol";

import {
    BatchClaim,
    QualifiedBatchClaim,
    BatchClaimWithWitness,
    QualifiedBatchClaimWithWitness,
    SplitBatchClaim,
    SplitBatchClaimWithWitness,
    QualifiedSplitBatchClaim,
    QualifiedSplitBatchClaimWithWitness
} from "../types/BatchClaims.sol";

import {
    MultichainClaim,
    QualifiedMultichainClaim,
    MultichainClaimWithWitness,
    QualifiedMultichainClaimWithWitness,
    SplitMultichainClaim,
    SplitMultichainClaimWithWitness,
    QualifiedSplitMultichainClaim,
    QualifiedSplitMultichainClaimWithWitness,
    ExogenousMultichainClaim,
    ExogenousQualifiedMultichainClaim,
    ExogenousMultichainClaimWithWitness,
    ExogenousQualifiedMultichainClaimWithWitness,
    ExogenousSplitMultichainClaim,
    ExogenousSplitMultichainClaimWithWitness,
    ExogenousQualifiedSplitMultichainClaim,
    ExogenousQualifiedSplitMultichainClaimWithWitness
} from "../types/MultichainClaims.sol";

import {
    BatchMultichainClaim,
    QualifiedBatchMultichainClaim,
    BatchMultichainClaimWithWitness,
    QualifiedBatchMultichainClaimWithWitness,
    SplitBatchMultichainClaim,
    SplitBatchMultichainClaimWithWitness,
    QualifiedSplitBatchMultichainClaim,
    QualifiedSplitBatchMultichainClaimWithWitness,
    ExogenousBatchMultichainClaim,
    ExogenousQualifiedBatchMultichainClaim,
    ExogenousBatchMultichainClaimWithWitness,
    ExogenousQualifiedBatchMultichainClaimWithWitness,
    ExogenousSplitBatchMultichainClaim,
    ExogenousSplitBatchMultichainClaimWithWitness,
    ExogenousQualifiedSplitBatchMultichainClaim,
    ExogenousQualifiedSplitBatchMultichainClaimWithWitness
} from "../types/BatchMultichainClaims.sol";

/**
 * @title The Compact — Claims Interface
 * @custom:version 0 (early-stage proof-of-concept)
 * @author 0age (0age.eth)
 * @notice Claim endpoints can only be called by the arbiter indicated on the associated
 * compact, and are used to settle the compact in question. There are 96 endpoints in total,
 * based on all the various possible combinations of a number of factors:
 *  - transfer vs. withdrawal: whether to transfer the claimed ERC6909 tokens directly, or to
 *    withdraw the underlying claimed tokens (e.g. calling `claim` or `claimAndWithdraw`)
 *  - unqualified vs qualified: whether the allocator is cosigning the same claim hash as the
 *    sponsor, or if they are signing for additional data. This can be an arbitrary EIP-712
 *    payload, with one exception: the first element must be the claim hash, which will be
 *    provided by The Compact directly as part of signature verification. These claims take
 *    two additional arguments: the EIP-712 typehash used in the qualification, and the data
 *    payload (not including the first claim hash argument). This data can then be utilized
 *    by the arbiter to inform and constrain the claim.
 *  - no witness vs. witness: whether or not the sponsor has elected to extend the Compact
 *    EIP-712 payload with an additional witness argument (generally using a new struct).
 *    When witness data is utilized, the call takes two additional arguments: one
 *    representing the EIP-712 hash of the witness data (or the direct data if it is a single
 *    value) and one representing the additional EIP-712 typestring that will extend the
 *    default arguments to include the witness.
 *  - whether or not to perform a "split": with no split, the caller specifies a single
 *    recipient, whereas with a split the caller specifies multiple recipients and respective
 *    amounts.
 *  - whether or not to utilize a "batch" of resource locks on a specific chain: When the
 *    sponsor is utilizing multiple resource locks on a specific chain, they will sign or
 *    register a `BatchCompact` EIP-712 payload. (Single-chain claims sign or register a
 *    `Compact` EIP-712 payload).
 *  - whether or not to include resource locks on a single chain or multiple chains; in
 *    the event of a multichain compact, there are _two_ additional endpoints per option,
 *    one for claims against the first referenced chain where the domain matches the one
 *    signed for or registered against (the "notarized" chain) and one for claims against
 *    other chains where the resource locks indicate a multichain scope (the "exogenous"
 *    chains). When the sponsor is utilizing multiple resource locks across multiple chains,
 *    they will sign a `MultichainCompact` EIP-712 payload. When claiming these for the
 *    notarized chain, an array of bytes32 values representing additional chain "segments"
 *    is provided. When claiming against an exogenous chain, the additional chains array
 *    begins with the notarized chain and then includes values for all exogenous chains
 *    excluding the one being claimed against, and a chain index is supplied indicating the
 *    location in the list of segments of the current chain (a value of 0 means that it is)
 *    the first exogenous chain) as well as a `notarizedChainId` representing the chainId
 *    for the domain that the multichain claim was signed against.
 */
interface ITheCompactClaims {
    function claim(BasicClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BasicClaim calldata claimPayload) external returns (bool);

    function claim(QualifiedClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedClaim calldata claimPayload) external returns (bool);

    function claim(ClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(QualifiedClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(SplitClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitClaim calldata claimPayload) external returns (bool);

    function claim(QualifiedSplitClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedSplitClaim calldata claimPayload) external returns (bool);

    function claim(SplitClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(QualifiedSplitClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedSplitClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(BatchClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchClaim calldata claimPayload) external returns (bool);

    function claim(QualifiedBatchClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedBatchClaim calldata claimPayload) external returns (bool);

    function claim(BatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(QualifiedBatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedBatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(SplitBatchClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitBatchClaim calldata claimPayload) external returns (bool);

    function claim(QualifiedSplitBatchClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedSplitBatchClaim calldata claimPayload) external returns (bool);

    function claim(SplitBatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitBatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(QualifiedSplitBatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedSplitBatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(MultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(MultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousMultichainClaim calldata claimPayload) external returns (bool);

    function claim(QualifiedMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousQualifiedMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousQualifiedMultichainClaim calldata claimPayload) external returns (bool);

    function claim(MultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(MultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(QualifiedMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousQualifiedMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousQualifiedMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(SplitMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousSplitMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousSplitMultichainClaim calldata claimPayload) external returns (bool);

    function claim(QualifiedSplitMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedSplitMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousQualifiedSplitMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousQualifiedSplitMultichainClaim calldata claimPayload) external returns (bool);

    function claim(SplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(QualifiedSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousQualifiedSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousQualifiedSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(BatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(QualifiedBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousQualifiedBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousQualifiedBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(BatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(QualifiedBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousQualifiedBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousQualifiedBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(SplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousSplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousSplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(QualifiedSplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedSplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousQualifiedSplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousQualifiedSplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(SplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(QualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(QualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousQualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousQualifiedSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);
}
