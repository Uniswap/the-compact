// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BasicClaim, ClaimWithWitness, SplitClaim, SplitClaimWithWitness } from "../types/Claims.sol";

import { BatchClaim, BatchClaimWithWitness, SplitBatchClaim, SplitBatchClaimWithWitness } from "../types/BatchClaims.sol";

import {
    MultichainClaim,
    MultichainClaimWithWitness,
    SplitMultichainClaim,
    SplitMultichainClaimWithWitness,
    ExogenousMultichainClaim,
    ExogenousMultichainClaimWithWitness,
    ExogenousSplitMultichainClaim,
    ExogenousSplitMultichainClaimWithWitness
} from "../types/MultichainClaims.sol";

import {
    BatchMultichainClaim,
    BatchMultichainClaimWithWitness,
    SplitBatchMultichainClaim,
    SplitBatchMultichainClaimWithWitness,
    ExogenousBatchMultichainClaim,
    ExogenousBatchMultichainClaimWithWitness,
    ExogenousSplitBatchMultichainClaim,
    ExogenousSplitBatchMultichainClaimWithWitness
} from "../types/BatchMultichainClaims.sol";

/**
 * @title The Compact — Claims Interface
 * @custom:version 1 (early-stage proof-of-concept)
 * @author 0age (0age.eth)
 * @notice Claim endpoints can only be called by the arbiter indicated on the associated
 * compact, and are used to settle the compact in question. There are 48 endpoints in total,
 * based on all the various possible combinations of a number of factors:
 *  - transfer vs. withdrawal: whether to transfer the claimed ERC6909 tokens directly, or to
 *    withdraw the underlying claimed tokens (e.g. calling `claim` or `claimAndWithdraw`)
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

    function claim(ClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(SplitClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitClaim calldata claimPayload) external returns (bool);

    function claim(SplitClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(BatchClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchClaim calldata claimPayload) external returns (bool);

    function claim(BatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(SplitBatchClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitBatchClaim calldata claimPayload) external returns (bool);

    function claim(SplitBatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitBatchClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(MultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(MultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousMultichainClaim calldata claimPayload) external returns (bool);

    function claim(MultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(MultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(SplitMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousSplitMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousSplitMultichainClaim calldata claimPayload) external returns (bool);

    function claim(SplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousSplitMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(BatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(BatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(SplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousSplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousSplitBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(SplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(SplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claim(ExogenousSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousSplitBatchMultichainClaimWithWitness calldata claimPayload) external returns (bool);
}
