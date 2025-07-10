// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "src/lib/TheCompactLogic.sol";
import "src/lib/TransferLogic.sol";
import "src/lib/ComponentLib.sol";
import "src/lib/ClaimHashLib.sol";
import "src/lib/EfficiencyLib.sol";
import "src/lib/IdLib.sol";
import "src/test/AlwaysOKAllocator.sol";
import { AllocatedTransfer } from "src/types/Claims.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { Scope } from "src/types/Scope.sol";
import { AllocatedBatchTransfer } from "src/types/BatchClaims.sol";
import { Component } from "src/types/Components.sol";

contract MockTransferLogic is TheCompactLogic {
    using ClaimHashLib for AllocatedTransfer;
    using ClaimHashLib for AllocatedBatchTransfer;
    using ComponentLib for AllocatedTransfer;
    using ComponentLib for AllocatedBatchTransfer;
    using ComponentLib for Component[];
    using IdLib for address;
    using IdLib for uint96;
    using IdLib for uint256;
    using EfficiencyLib for address;

    function registerAllocator(address allocator) external returns (uint96 id, bytes12 tag) {
        id = allocator.register();
        tag = id.toLockTag(Scope.Multichain, ResetPeriod.OneDay);
        return (id, tag);
    }

    function toIdIfRegistered(address token, bytes12 tag) external view returns (uint256) {
        return token.toIdIfRegistered(tag);
    }

    function depositERC20(address token, bytes12 lockTag, uint256 amount, address recipient)
        external
        returns (uint256 id)
    {
        (id,) = _performCustomERC20Deposit(token, lockTag, amount, recipient.usingCallerIfNull());
    }

    function processTransfer(AllocatedTransfer calldata transfer) external returns (bool) {
        return _processTransfer(transfer);
    }

    function processBatchTransfer(AllocatedBatchTransfer calldata transfer) external returns (bool) {
        return _processBatchTransfer(transfer);
    }

    function ensureAttested(address from, address to, uint256 id, uint256 amount) external {
        _ensureAttested(from, to, id, amount);
    }
}
