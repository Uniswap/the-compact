// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { BatchTransfer, SplitBatchTransfer } from "../types/BatchClaims.sol";
import { BasicTransfer, SplitTransfer } from "../types/Claims.sol";
import { CompactCategory } from "../types/CompactCategory.sol";
import { SplitComponent, TransferComponent, SplitByIdComponent } from "../types/Components.sol";
import { ForcedWithdrawalStatus } from "../types/ForcedWithdrawalStatus.sol";
import { Lock } from "../types/Lock.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";

import { ConsumerLib } from "./ConsumerLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { FunctionCastLib } from "./FunctionCastLib.sol";
import { HashLib } from "./HashLib.sol";
import { IdLib } from "./IdLib.sol";
import { MetadataRenderer } from "./MetadataRenderer.sol";
import { ValidityLib } from "./ValidityLib.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { Tstorish } from "tstorish/Tstorish.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

contract InternalLogic is Tstorish {
    using HashLib for address;
    using HashLib for bytes32;
    using HashLib for uint256;
    using HashLib for BasicTransfer;
    using HashLib for SplitTransfer;
    using HashLib for BatchTransfer;
    using HashLib for SplitBatchTransfer;
    using IdLib for uint96;
    using IdLib for uint256;
    using IdLib for address;
    using IdLib for Lock;
    using IdLib for ResetPeriod;
    using SafeTransferLib for address;
    using ConsumerLib for uint256;
    using EfficiencyLib for bool;
    using EfficiencyLib for bytes32;
    using EfficiencyLib for uint256;
    using ValidityLib for address;
    using ValidityLib for uint96;
    using ValidityLib for uint256;
    using ValidityLib for bytes32;
    using FunctionCastLib for function(bytes32, address, BasicTransfer calldata) internal;

    address private constant _PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    uint256 private constant _ERC6909_MASTER_SLOT_SEED = 0xedcaa89a82293940;

    uint256 private constant _REENTRANCY_GUARD_SLOT = 0x929eee149b4bd21268;

    /// @dev `keccak256(bytes("Transfer(address,address,address,uint256,uint256)"))`.
    uint256 private constant _TRANSFER_EVENT_SIGNATURE = 0x1b3d7edb2e9c0b0e7c525b20aaaef0f5940d2ed71663c7d39266ecafac728859;

    /// @dev `keccak256(bytes("Claim(address,address,address,bytes32)"))`.
    uint256 private constant _CLAIM_EVENT_SIGNATURE = 0x770c32a2314b700d6239ee35ba23a9690f2fceb93a55d8c753e953059b3b18d4;

    /// @dev `keccak256(bytes("CompactRegistered(address,bytes32,bytes32,uint256)"))`.
    uint256 private constant _COMPACT_REGISTERED_SIGNATURE = 0xf78a2f33ff80ef4391f7449c748dc2d577a62cd645108f4f4069f4a7e0635b6a;

    /// @dev `keccak256(bytes("ForcedWithdrawalStatusUpdated(address,uint256,bool,uint256)"))`.
    uint256 private constant _FORCED_WITHDRAWAL_STATUS_UPDATED_SIGNATURE = 0xe27f5e0382cf5347965fc81d5c81cd141897fe9ce402d22c496b7c2ddc84e5fd;

    uint32 private constant _ATTEST_SELECTOR = 0x1a808f91;

    // slot: keccak256(_FORCED_WITHDRAWAL_ACTIVATIONS_SCOPE ++ account ++ id) => activates
    uint256 private constant _FORCED_WITHDRAWAL_ACTIVATIONS_SCOPE = 0x41d0e04b;

    // slot: keccak256(_ACTIVE_REGISTRATIONS_SCOPE ++ sponsor ++ claimHash ++ typehash) => expires
    uint256 private constant _ACTIVE_REGISTRATIONS_SCOPE = 0x68a30dd0;

    uint256 private immutable _INITIAL_CHAIN_ID;
    bytes32 private immutable _INITIAL_DOMAIN_SEPARATOR;
    MetadataRenderer private immutable _METADATA_RENDERER;
    bool private immutable _PERMIT2_INITIALLY_DEPLOYED;

    constructor() {
        _INITIAL_CHAIN_ID = block.chainid;
        _INITIAL_DOMAIN_SEPARATOR = block.chainid.toNotarizedDomainSeparator();
        _METADATA_RENDERER = new MetadataRenderer();
        _PERMIT2_INITIALLY_DEPLOYED = _checkPermit2Deployment();
    }

    function _setReentrancyGuard() internal {
        _setTstorish(_REENTRANCY_GUARD_SLOT, 1);
    }

    function _clearReentrancyGuard() internal {
        _clearTstorish(_REENTRANCY_GUARD_SLOT);
    }

    function _isPermit2Deployed() internal view returns (bool) {
        if (_PERMIT2_INITIALLY_DEPLOYED) {
            return true;
        }

        return _checkPermit2Deployment();
    }

    function _checkPermit2Deployment() internal view returns (bool permit2Deployed) {
        assembly ("memory-safe") {
            permit2Deployed := iszero(iszero(extcodesize(_PERMIT2)))
        }
    }

    function _domainSeparator() internal view returns (bytes32) {
        return _INITIAL_DOMAIN_SEPARATOR.toLatest(_INITIAL_CHAIN_ID);
    }

    /// @dev Returns the symbol for token `id`.
    function _name(uint256 id) internal view returns (string memory) {
        return _METADATA_RENDERER.name(id);
    }

    /// @dev Returns the symbol for token `id`.
    function _symbol(uint256 id) internal view returns (string memory) {
        return _METADATA_RENDERER.symbol(id);
    }

    /// @dev Returns the Uniform Resource Identifier (URI) for token `id`.
    function _tokenURI(uint256 id) internal view returns (string memory) {
        return _METADATA_RENDERER.uri(id.toLock(), id);
    }
}
