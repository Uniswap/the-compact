// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract CalldataDebugger {
    error Debug(bytes);

    fallback() external payable {
        revert Debug(msg.data);
    }
}
