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
import { EmissaryStatus } from "./types/EmissaryStatus.sol";

import { TheCompactLogic } from "./lib/TheCompactLogic.sol";

import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// TODO: refactor these into logic files
import { EfficiencyLib } from "./lib/EfficiencyLib.sol";
import { HashLib } from "./lib/HashLib.sol";
import { ValidityLib } from "./lib/ValidityLib.sol";
import { IdLib } from "./lib/IdLib.sol";
import { RegistrationLib } from "./lib/RegistrationLib.sol";

/**
 * @title The Compact
 * @custom:version 1
 * @author 0age (0age.eth)
 * @notice The Compact is an ownerless ERC6909 contract that facilitates the voluntary
 *         formation and mediation of reusable "resource locks."
 *         This contract has not yet been properly tested, audited, or reviewed.
 */
contract TheCompact is ITheCompact, ERC6909, TheCompactLogic {
    using ValidityLib for address;
    using ValidityLib for bytes32;
    using IdLib for address;
    using IdLib for uint96;
    using IdLib for uint256;
    using RegistrationLib for address;
    using EfficiencyLib for bool;
    using EfficiencyLib for uint256;

    function deposit(bytes12 lockTag) external payable returns (uint256) {
        return _performCustomNativeTokenDeposit(lockTag, msg.sender);
    }

    function deposit(bytes12 lockTag, address recipient) external payable returns (uint256) {
        return _performCustomNativeTokenDeposit(lockTag, recipient);
    }

    function depositAndRegister(bytes12 lockTag, bytes32 claimHash, bytes32 typehash)
        external
        payable
        returns (uint256 id)
    {
        id = _performCustomNativeTokenDeposit(lockTag, msg.sender);

        _register(msg.sender, claimHash, typehash);
    }

    function depositAndRegisterFor(
        address recipient,
        bytes12 lockTag,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external payable returns (uint256 id, bytes32 claimhash) {
        id = _performCustomNativeTokenDeposit(lockTag, recipient);

        claimhash = _registerUsingClaimWithWitness(recipient, id, msg.value, arbiter, nonce, expires, typehash, witness);
    }

    function deposit(address token, bytes12 lockTag, uint256 amount) external returns (uint256) {
        return _performCustomERC20Deposit(token, lockTag, amount, msg.sender);
    }

    function deposit(address token, bytes12 lockTag, uint256 amount, address recipient) external returns (uint256) {
        return _performCustomERC20Deposit(token, lockTag, amount, recipient);
    }

    function depositAndRegister(address token, bytes12 lockTag, uint256 amount, bytes32 claimHash, bytes32 typehash)
        external
        returns (uint256 id)
    {
        id = _performCustomERC20Deposit(token, lockTag, amount, msg.sender);

        _register(msg.sender, claimHash, typehash);
    }

    function depositAndRegisterFor(
        address recipient,
        address token,
        bytes12 lockTag,
        uint256 amount,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external returns (uint256 id, bytes32 claimhash) {
        id = _performCustomERC20Deposit(token, lockTag, amount, recipient);

        claimhash = _registerUsingClaimWithWitness(recipient, id, amount, arbiter, nonce, expires, typehash, witness);
    }

    function deposit(uint256[2][] calldata idsAndAmounts, address recipient) external payable returns (bool) {
        _processBatchDeposit(idsAndAmounts, recipient, false);

        return true;
    }

    function depositAndRegister(uint256[2][] calldata idsAndAmounts, bytes32[2][] calldata claimHashesAndTypehashes)
        external
        payable
        returns (bool)
    {
        _processBatchDeposit(idsAndAmounts, msg.sender, false);

        return _registerBatch(claimHashesAndTypehashes);
    }

    function depositAndRegisterFor(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external payable returns (bytes32 claimhash) {
        _processBatchDeposit(idsAndAmounts, recipient, true);

        claimhash =
            _registerUsingBatchClaimWithWitness(recipient, idsAndAmounts, arbiter, nonce, expires, typehash, witness);
    }

    function deposit(
        address token,
        uint256, // amount
        uint256, // nonce
        uint256, // deadline
        address, // depositor
        bytes12, // lockTag
        address recipient,
        bytes calldata signature
    ) external returns (uint256) {
        return _depositViaPermit2(token, recipient, signature);
    }

    function depositAndRegister(
        address token,
        uint256, // amount
        uint256, // nonce
        uint256, // deadline
        address depositor, // also recipient
        bytes12, // lockTag
        bytes32 claimHash,
        CompactCategory compactCategory,
        string calldata witness,
        bytes calldata signature
    ) external returns (uint256) {
        return _depositAndRegisterViaPermit2(token, depositor, claimHash, compactCategory, witness, signature);
    }

    function deposit(
        address, // depositor
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        uint256, // nonce
        uint256, // deadline
        bytes12, // lockTag
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
        bytes12, // lockTag,
        bytes32 claimHash,
        CompactCategory compactCategory,
        string calldata witness,
        bytes calldata signature
    ) external payable returns (uint256[] memory) {
        return _depositBatchAndRegisterViaPermit2(depositor, permitted, claimHash, compactCategory, witness, signature);
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

    function register(bytes32 claimHash, bytes32 typehash) external returns (bool) {
        _register(msg.sender, claimHash, typehash);

        return true;
    }

    function register(bytes32[2][] calldata claimHashesAndTypehashes) external returns (bool) {
        return _registerBatch(claimHashesAndTypehashes);
    }

    function registerFor(
        address sponsor,
        address token,
        bytes12 lockTag,
        uint256 amount,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata sponsorSignature
    ) external returns (uint256 id, bytes32 claimHash) {
        // Derive resource lock ID using provided token, parameters, and allocator.
        id = token.excludingNative().toIdIfRegistered(lockTag);

        claimHash =
            HashLib.toFlatMessageHashWithWitness(sponsor, id, amount, arbiter, nonce, expires, typehash, witness);

        // Initialize idsAndAmounts array.
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0] = [id, amount];

        // TOOD: support registering exogenous domain separators by passing notarized chainId
        claimHash.hasValidSponsor(sponsor, sponsorSignature, _domainSeparator(), idsAndAmounts);

        sponsor.registerCompact(claimHash, typehash);
    }

    function registerFor(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata sponsorSignature
    ) external returns (bytes32 claimHash) {
        // Retrieve the total number of IDs and amounts in the batch.
        uint256 totalIds = idsAndAmounts.length;

        if (totalIds == 0) {
            revert InconsistentAllocators();
        }

        // Derive current allocator ID from first resource lock ID.
        uint96 initialAllocatorId = idsAndAmounts[0][0].toRegisteredAllocatorId();

        // Declare error buffer for tracking allocator ID consistency.
        uint256 errorBuffer;

        // Iterate over remaining IDs.
        unchecked {
            for (uint256 i = 1; i < totalIds; ++i) {
                // Determine if new allocator ID differs from current allocator ID.
                errorBuffer |= (idsAndAmounts[i][0].toAllocatorId() != initialAllocatorId).asUint256();
            }
        }

        if (errorBuffer.asBool()) {
            revert InconsistentAllocators();
        }

        claimHash = HashLib.toFlatBatchClaimWithWitnessMessageHash(
            sponsor, idsAndAmounts, arbiter, nonce, expires, typehash, witness
        );

        // TOOD: support registering exogenous domain separators by passing notarized chainId
        claimHash.hasValidSponsor(sponsor, sponsorSignature, _domainSeparator(), idsAndAmounts);

        sponsor.registerCompact(claimHash, typehash);
    }

    function assignEmissary(bytes12 lockTag, address emissary) external returns (bool) {
        return _assignEmissary(lockTag, emissary);
    }

    function scheduleEmissaryAssignment(bytes12 lockTag) external returns (uint256 emissaryAssignmentAvailableAt) {
        return _scheduleEmissaryAssignment(lockTag);
    }

    function consume(uint256[] calldata nonces) external returns (bool) {
        return _consume(nonces);
    }

    function __registerAllocator(address allocator, bytes calldata proof) external returns (uint96) {
        return _registerAllocator(allocator, proof);
    }

    function getForcedWithdrawalStatus(address account, uint256 id)
        external
        view
        returns (ForcedWithdrawalStatus, uint256)
    {
        return _getForcedWithdrawalStatus(account, id);
    }

    function getRegistrationStatus(address sponsor, bytes32 claimHash, bytes32 typehash)
        external
        view
        returns (bool isActive, uint256 registrationTimestamp)
    {
        registrationTimestamp = _getRegistrationStatus(sponsor, claimHash, typehash);
        isActive = registrationTimestamp != 0;
    }

    function getEmissaryStatus(address sponsor, bytes12 lockTag)
        external
        view
        returns (EmissaryStatus status, uint256 emissaryAssignmentAvailableAt, address currentEmissary)
    {
        return _getEmissaryStatus(sponsor, lockTag);
    }

    function getLockDetails(uint256 id) external view returns (address, address, ResetPeriod, Scope, bytes12) {
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
