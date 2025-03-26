// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocatorLogic } from "./AllocatorLogic.sol";
import { ClaimProcessor } from "./ClaimProcessor.sol";
import { DepositViaPermit2Logic } from "./DepositViaPermit2Logic.sol";
import { DirectDepositLogic } from "./DirectDepositLogic.sol";
import { Extsload } from "./Extsload.sol";
import { RegistrationLogic } from "./RegistrationLogic.sol";
import { TransferLogic } from "./TransferLogic.sol";
import { WithdrawalLogic } from "./WithdrawalLogic.sol";
import { SignDelegatorLogic } from "./SignDelegatorLogic.sol";

/**
 * @title TheCompactLogic
 * @notice Inherited contract that aggregates a number of other inherited contracts.
 */
contract TheCompactLogic is AllocatorLogic, ClaimProcessor, DepositViaPermit2Logic, DirectDepositLogic, Extsload, RegistrationLogic, TransferLogic, WithdrawalLogic, SignDelegatorLogic { }
