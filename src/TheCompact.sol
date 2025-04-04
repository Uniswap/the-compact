// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITheCompact } from "./interfaces/ITheCompact.sol";

import { BatchTransfer, SplitBatchTransfer } from "./types/BatchClaims.sol";
import { BasicTransfer, SplitTransfer } from "./types/Claims.sol";
import { CompactCategory } from "./types/CompactCategory.sol";
import { Lock } from "./types/Lock.sol";
import { Scope } from "./types/Scope.sol";
import { ResetPeriod } from "./types/ResetPeriod.sol";
import { ForcedWithdrawalStatus } from "./types/ForcedWithdrawalStatus.sol";

import { TheCompactLogic } from "./lib/TheCompactLogic.sol";

import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

/**
 * @title The Compact
 * @custom:version 0 (early-stage proof-of-concept)
 * @author 0age (0age.eth)
 * @notice The Compact is an ownerless ERC6909 contract that facilitates the voluntary
 *         formation and mediation of reusable "resource locks."
 *         This contract has not yet been properly tested, audited, or reviewed.
 */
contract TheCompact is ITheCompact, ERC6909, TheCompactLogic {
    function deposit(bytes12 locktag) external payable returns (uint256) {
        return _performCustomNativeTokenDeposit(locktag, msg.sender);
    }

    function deposit(bytes12 locktag, address recipient) external payable returns (uint256) {
        return _performCustomNativeTokenDeposit(locktag, recipient);
    }

    function deposit(address token, bytes12 locktag, uint256 amount) external returns (uint256) {
        return _performCustomERC20Deposit(token, locktag, amount, msg.sender);
    }

    function deposit(address token, bytes12 locktag, uint256 amount, address recipient) external returns (uint256) {
        return _performCustomERC20Deposit(token, locktag, amount, recipient);
    }

    function deposit(uint256[2][] calldata idsAndAmounts, address recipient) external payable returns (bool) {
        _processBatchDeposit(idsAndAmounts, recipient);

        return true;
    }

    function depositAndRegister(uint256[2][] calldata idsAndAmounts, bytes32[2][] calldata claimHashesAndTypehashes, uint256 duration) external payable returns (bool) {
        _processBatchDeposit(idsAndAmounts, msg.sender);

        return _registerBatch(claimHashesAndTypehashes, duration);
    }

    function deposit(
        address token,
        uint256, // amount
        uint256, // nonce
        uint256, // deadline
        address, // depositor
        bytes12 locktag,
        address recipient,
        bytes calldata signature
    ) external returns (uint256) {
        return _depositViaPermit2(token, locktag, recipient, signature);
    }

    function depositAndRegister(
        address token,
        uint256, // amount
        uint256, // nonce
        uint256, // deadline
        address depositor, // also recipient
        bytes12 locktag,
        bytes32 claimHash,
        CompactCategory compactCategory,
        string calldata witness,
        bytes calldata signature
    ) external returns (uint256) {
        return _depositAndRegisterViaPermit2(token, depositor, locktag, claimHash, compactCategory, witness, signature);
    }

    function deposit(
        address, // depositor
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        uint256, // nonce
        uint256, // deadline
        bytes12, // locktag,
        address recipient,
        bytes calldata signature
    ) external payable returns (uint256[] memory) {
        return _depositBatchViaPermit2(permitted, recipient, signature);
    }

    function depositAndRegister(
        address depositor,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        uint256, // nonce
        uint256, // deadline
        bytes12 locktag,
        bytes32 claimHash,
        CompactCategory compactCategory,
        string calldata witness,
        bytes calldata signature
    ) external payable returns (uint256[] memory) {
        return _depositBatchAndRegisterViaPermit2(depositor, permitted, locktag, claimHash, compactCategory, witness, signature);
    }

    function allocatedTransfer(SplitTransfer calldata transfer) external returns (bool) {
        return _processSplitTransfer(transfer);
    }

    function allocatedTransfer(SplitBatchTransfer calldata transfer) external returns (bool) {
        return _processSplitBatchTransfer(transfer);
    }

    function enableForcedWithdrawal(uint256 id) external returns (uint256) {
        return _enableForcedWithdrawal(id);
    }

    function disableForcedWithdrawal(uint256 id) external returns (bool) {
        _disableForcedWithdrawal(id);

        return true;
    }

    function forcedWithdrawal(uint256 id, address recipient, uint256 amount) external returns (bool) {
        _processForcedWithdrawal(id, recipient, amount);

        return true;
    }

    function register(bytes32 claimHash, bytes32 typehash, uint256 duration) external returns (bool) {
        _register(msg.sender, claimHash, typehash, duration);

        return true;
    }

    function getRegistrationStatus(address sponsor, bytes32 claimHash, bytes32 typehash) external view returns (bool isActive, uint256 expires) {
        expires = _getRegistrationStatus(sponsor, claimHash, typehash);
        isActive = expires > block.timestamp;
    }

    function register(bytes32[2][] calldata claimHashesAndTypehashes, uint256 duration) external returns (bool) {
        return _registerBatch(claimHashesAndTypehashes, duration);
    }

    function consume(uint256[] calldata nonces) external returns (bool) {
        return _consume(nonces);
    }

    function __registerAllocator(address allocator, bytes calldata proof) external returns (uint96) {
        return _registerAllocator(allocator, proof);
    }

    function getForcedWithdrawalStatus(address account, uint256 id) external view returns (ForcedWithdrawalStatus, uint256) {
        return _getForcedWithdrawalStatus(account, id);
    }

    function getLockDetails(uint256 id) external view returns (address, address, ResetPeriod, Scope) {
        return _getLockDetails(id);
    }

    function hasConsumedAllocatorNonce(uint256 nonce, address allocator) external view returns (bool) {
        return _hasConsumedAllocatorNonce(nonce, allocator);
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /// @dev Returns the symbol for token `id`.
    function name(uint256 id) public view virtual override returns (string memory) {
        return _name(id);
    }

    /// @dev Returns the symbol for token `id`.
    function symbol(uint256 id) public view virtual override returns (string memory) {
        return _symbol(id);
    }

    /// @dev Returns the Uniform Resource Identifier (URI) for token `id`.
    function tokenURI(uint256 id) public view virtual override returns (string memory) {
        return _tokenURI(id);
    }

    /// @dev Returns the name for the contract.
    function name() external pure returns (string memory) {
        // Return the name of the contract.
        assembly ("memory-safe") {
            mstore(0x20, 0x20)
            mstore(0x4b, 0x0b54686520436f6d70616374)
            return(0x20, 0x60)
        }
    }

    function _beforeTokenTransfer(address from, address to, uint256 id, uint256 amount) internal virtual override {
        _ensureAttested(from, to, id, amount);
    }
}
