// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Claim } from "../types/Claims.sol";

import { BatchClaim } from "../types/BatchClaims.sol";

import { MultichainClaim, ExogenousMultichainClaim } from "../types/MultichainClaims.sol";

import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "../types/BatchMultichainClaims.sol";

/**
 * @title The Compact — Claims Interface
 * @custom:version 1 (early-stage proof-of-concept)
 * @author 0age (0age.eth)
 * @notice Claim endpoints can only be called by the arbiter indicated on the associated
 * compact, and are used to settle the compact in question. There are 12 endpoints in total,
 * based on all the various possible combinations of a number of factors:
 *  - transfer vs. withdrawal: whether to transfer the claimed ERC6909 tokens directly, or to
 *    withdraw the underlying claimed tokens (e.g. calling `claim` or `claimAndWithdraw`)
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
    function claim(Claim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(Claim calldata claimPayload) external returns (bool);

    function claim(BatchClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchClaim calldata claimPayload) external returns (bool);

    function claim(MultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(MultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousMultichainClaim calldata claimPayload) external returns (bool);

    function claim(BatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(BatchMultichainClaim calldata claimPayload) external returns (bool);

    function claim(ExogenousBatchMultichainClaim calldata claimPayload) external returns (bool);

    function claimAndWithdraw(ExogenousBatchMultichainClaim calldata claimPayload) external returns (bool);
}
