// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { DepositViaPermit2Logic } from "src/lib/DepositViaPermit2Logic.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { IdLib } from "src/lib/IdLib.sol";
import { EfficiencyLib } from "src/lib/EfficiencyLib.sol";
import { CompactCategory } from "src/types/CompactCategory.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { Scope } from "src/types/Scope.sol";
import { DepositDetails } from "src/types/DepositDetails.sol";

/**
 * @title MockDepositViaPermit2Logic
 * @notice A pass-through mock implementation that exposes internal functions from DepositViaPermit2Logic for testing.
 */
contract MockDepositViaPermit2Logic is DepositViaPermit2Logic {
    using IdLib for address;
    using IdLib for uint96;
    using IdLib for uint256;
    using EfficiencyLib for uint256;

    function depositERC20ViaPermit2(
        ISignatureTransfer.PermitTransferFrom calldata permit,
        address, // depositor
        bytes12, // lockTag
        address recipient,
        bytes calldata signature
    ) external returns (uint256) {
        return _depositViaPermit2(permit.permitted.token, recipient, signature);
    }

    function batchDepositViaPermit2(
        address, // depositor
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        DepositDetails calldata,
        address recipient,
        bytes calldata signature
    ) external payable returns (uint256[] memory) {
        return _depositBatchViaPermit2(permitted, recipient, signature);
    }

    function registerAllocator(address allocator) external returns (uint96 id, bytes12 tag) {
        id = allocator.register();
        tag = id.toLockTag(Scope.Multichain, ResetPeriod.OneDay);
        return (id, tag);
    }

    function toIdIfRegistered(address token, bytes12 lockTag) external view returns (uint256) {
        return token.toIdIfRegistered(lockTag);
    }

    function getLockDetails(uint256 id) external view returns (address, address, ResetPeriod, Scope, bytes12) {
        address token = id.toAddress();
        address allocator = id.toAllocatorId().toRegisteredAllocator();
        ResetPeriod resetPeriod = id.toResetPeriod();
        Scope scope = id.toScope();
        bytes12 lockTag = id.toLockTag();
        return (token, allocator, resetPeriod, scope, lockTag);
    }
}
