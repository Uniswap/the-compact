// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract MaliciousBenchmarkTarget {
    error RevertOnFallback();

    fallback() external payable {
        revert RevertOnFallback();
    }
}
