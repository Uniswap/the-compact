// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

enum ForcedWithdrawalStatus {
    Disabled, // Not pending or enabled for forced withdrawal
    Pending, // Not yet available, but initiated
    Enabled // Available for forced withdrawal on demand

}
