// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

struct SplitComponent {
    address claimant; // The recipient of the transfer or withdrawal.
    uint256 amount; // The amount of tokens to transfer or withdraw.
}

struct SplitByIdComponent {
    uint256 id; // The token ID of the ERC6909 token to transfer or withdraw.
    SplitComponent[] portions; // claimants and amounts.
}

struct TransferComponent {
    uint256 id; // The token ID of the ERC6909 token to transfer or withdraw.
    uint256 amount; // The token amount to transfer or withdraw.
}

struct BatchClaimComponent {
    uint256 id; // The token ID of the ERC6909 token to allocate.
    uint256 allocatedAmount; // The original allocated amount of ERC6909 tokens.
    uint256 amount; // The claimed token amount; specified by the arbiter.
}

struct SplitBatchClaimComponent {
    uint256 id; // The token ID of the ERC6909 token to allocate.
    uint256 allocatedAmount; // The original allocated amount of ERC6909 tokens.
    SplitComponent[] portions; // claimants and amounts.
}
