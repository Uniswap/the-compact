// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResetPeriod } from "./ResetPeriod.sol";
import { Scope } from "./Scope.sol";

struct Lock {
    address token;
    address allocator;
    ResetPeriod resetPeriod;
    Scope scope;
}
