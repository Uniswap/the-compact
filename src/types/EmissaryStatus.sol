// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResetPeriod } from "./ResetPeriod.sol";

enum EmissaryStatus {
    Disabled, // Not pending or enabled for forced withdrawal
    Scheduled, // Available but scheduled
    Enabled // Available for forced withdrawal on demand

}

struct EmissaryConfig {
    // 20 bytes
    address emissary; // address of the sponsor's emissary
    // 1 byte
    ResetPeriod resetPeriod; // period after which a set emissary can be re-assigned
    // 11 bytes
    uint88 assignableAt; // timestamp after which an emissary can be re-assigned
}
