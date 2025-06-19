// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { EfficiencyLib } from "./EfficiencyLib.sol";

contract Tstorish {
    using EfficiencyLib for bool;
    using EfficiencyLib for address;

    // Declare an immutable function type variable for the _setTstorish function
    // based on chain support for tstore at time of deployment.
    function(uint256,uint256) internal immutable _setTstorish;

    // Declare an immutable function type variable for the _getTstorish function
    // based on chain support for tstore at time of deployment.
    function(uint256) view returns (uint256) internal immutable _getTstorish;

    // Declare a storage variable indicating when TSTORE support will be
    // activated assuming it was not already active at initial deployment.
    uint256 private _tstoreSupportActiveAt;

    /*
     * ------------------------------------------------------------------------+
     * Opcode      | Mnemonic         | Stack              | Memory            |
     * ------------------------------------------------------------------------|
     * 60 0x02     | PUSH1 0x02       | 0x02               |                   |
     * 60 0x1e     | PUSH1 0x1e       | 0x1e 0x02          |                   |
     * 61 0x3d5c   | PUSH2 0x3d5c     | 0x3d5c 0x1e 0x02   |                   |
     * 3d          | RETURNDATASIZE   | 0 0x3d5c 0x1e 0x02 |                   |
     *                                                                         |
     * :: store deployed bytecode in memory: (3d) RETURNDATASIZE (5c) TLOAD :: |
     * 52          | MSTORE           | 0x1e 0x02          | [0..0x20): 0x3d5c |
     * f3          | RETURN           |                    | [0..0x20): 0x3d5c |
     * ------------------------------------------------------------------------+
     */
    uint80 private constant _TLOAD_TEST_PAYLOAD = 0x6002_601e_613d5c_3d_52_f3;
    uint8 private constant _TLOAD_TEST_PAYLOAD_LENGTH = 0x0a;
    uint8 private constant _TLOAD_TEST_PAYLOAD_OFFSET = 0x16;

    // Declare an immutable variable to store the tstore test contract address.
    address private immutable _tloadTestContract;

    // Declare an immutable variable to store the initial TSTORE support status.
    bool private immutable _tstoreInitialSupport;

    // Declare a few custom revert error types.
    error TStoreAlreadyActivated();
    error TStoreNotSupported();
    error TloadTestContractDeploymentFailed();

    /**
     * @dev Determine TSTORE availability during deployment. This involves
     *      attempting to deploy a contract that utilizes TLOAD as part of the
     *      contract construction bytecode, and configuring initial support for
     *      using TSTORE in place of SSTORE based on the result.
     */
    constructor() {
        // Deploy the contract testing TLOAD support and store the address.
        address tloadTestContract = _prepareTloadTest();

        // Ensure the deployment was successful.
        if (tloadTestContract.isNullAddress()) {
            revert TloadTestContractDeploymentFailed();
        }

        // Determine if TSTORE is supported.
        bool tstoreInitialSupport = _testTload(tloadTestContract);

        if (tstoreInitialSupport) {
            // If TSTORE is supported, set functions to their versions that use
            // tstore/tload directly without support checks.
            _setTstorish = _setTstore;
            _getTstorish = _getTstore;
        } else {
            // If TSTORE is not supported, set functions to their versions that
            // fallback to sstore/sload until _tstoreSupportActiveAt is set to
            // a block number before the current block number.
            _setTstorish = _setTstorishWithSstoreFallback;
            _getTstorish = _getTstorishWithSloadFallback;
        }

        _tstoreInitialSupport = tstoreInitialSupport;

        // Set the address of the deployed TLOAD test contract as an immutable.
        _tloadTestContract = tloadTestContract;
    }

    /**
     * @dev External function to activate TSTORE usage. Does not need to be
     *      called if TSTORE is supported from deployment, and only needs to be
     *      called once. Reverts if TSTORE has already been activated or if the
     *      opcode is not available.
     */
    function __activateTstore() external {
        // Determine if TSTORE can potentially be activated.
        if (_tstoreInitialSupport.or(_tstoreSupportActiveAt != 0)) {
            assembly ("memory-safe") {
                mstore(0, 0xf45b98b0) // `TStoreAlreadyActivated()`.
                revert(0x1c, 0x04)
            }
        }

        // Determine if TSTORE can be activated and revert if not.
        if (!_testTload(_tloadTestContract)) {
            assembly ("memory-safe") {
                mstore(0, 0x70a4078f) // `TStoreNotSupported()`.
                revert(0x1c, 0x04)
            }
        }

        // Mark TSTORE as activated as of the next block.
        unchecked {
            _tstoreSupportActiveAt = block.number + 1;
        }
    }

    /**
     * @dev Internal view function to determine if TSTORE/TLOAD are supported by
     *      the current EVM implementation by attempting to call the test
     *      contract, which utilizes TLOAD as part of its fallback logic.
     *      Marked as virtual to facilitate overriding as part of tests.
     */
    function _testTload(address tloadTestContract) internal view virtual returns (bool ok) {
        // Call the test contract, which will perform a TLOAD test. If the call
        // does not revert, then TLOAD/TSTORE is supported. Do not forward all
        // available gas, as all forwarded gas will be consumed on revert.
        // Note that this assumes that the contract was successfully deployed.
        assembly ("memory-safe") {
            ok := staticcall(div(gas(), 10), tloadTestContract, 0, 0, 0, 0)
        }
    }

    /**
     * @dev Private function to deploy a test contract that utilizes TLOAD as
     *      part of its fallback logic.
     */
    function _prepareTloadTest() private returns (address contractAddress) {
        // Utilize assembly to deploy a contract testing TLOAD support.
        assembly ("memory-safe") {
            // Write the contract deployment code payload to scratch space.
            mstore(0, _TLOAD_TEST_PAYLOAD)

            // Deploy the contract.
            contractAddress := create(0, _TLOAD_TEST_PAYLOAD_OFFSET, _TLOAD_TEST_PAYLOAD_LENGTH)
        }
    }

    /**
     * @dev Private function to set a TSTORISH value. Assigned to _setTstorish
     *      internal function variable at construction if chain has tstore support.
     *
     * @param storageSlot The slot to write the TSTORISH value to.
     * @param value       The value to write to the given storage slot.
     */
    function _setTstore(uint256 storageSlot, uint256 value) private {
        assembly ("memory-safe") {
            tstore(storageSlot, value)
        }
    }

    /**
     * @dev Private function to set a TSTORISH value with sstore fallback.
     *      Assigned to _setTstorish internal function variable at construction
     *      if chain does not have tstore support.
     *
     * @param storageSlot The slot to write the TSTORISH value to.
     * @param value       The value to write to the given storage slot.
     */
    function _setTstorishWithSstoreFallback(uint256 storageSlot, uint256 value) private {
        if (_useSstoreFallback()) {
            assembly ("memory-safe") {
                sstore(storageSlot, value)
            }
        } else {
            assembly ("memory-safe") {
                tstore(storageSlot, value)
            }
        }
    }

    /**
     * @dev Private function to read a TSTORISH value. Assigned to _getTstorish
     *      internal function variable at construction if chain has tstore support.
     *
     * @param storageSlot The slot to read the TSTORISH value from.
     *
     * @return value The TSTORISH value at the given storage slot.
     */
    function _getTstore(uint256 storageSlot) private view returns (uint256 value) {
        assembly ("memory-safe") {
            value := tload(storageSlot)
        }
    }

    /**
     * @dev Private function to read a TSTORISH value with sload fallback.
     *      Assigned to _getTstorish internal function variable at construction
     *      if chain does not have tstore support.
     *
     * @param storageSlot The slot to read the TSTORISH value from.
     *
     * @return value The TSTORISH value at the given storage slot.
     */
    function _getTstorishWithSloadFallback(uint256 storageSlot) private view returns (uint256 value) {
        if (_useSstoreFallback()) {
            assembly ("memory-safe") {
                value := sload(storageSlot)
            }
        } else {
            assembly ("memory-safe") {
                value := tload(storageSlot)
            }
        }
    }

    /**
     * @dev Private view function to determine whether the sstore fallback must
     *      still be utilized. In cases where tstore is not supported at the time
     *      of initial deployment but becomes supported by the EVM environment,
     *      __activateTstore() can be called to schedule activation as of the
     *      next block. This prevents potential reentrancy during mid-transaction
     *      activations where Tstorish is used to implement a reentrancy guard.
     *
     * @return useSstore A boolean indicating whether to use the sstore fallback.
     */
    function _useSstoreFallback() private view returns (bool useSstore) {
        assembly ("memory-safe") {
            // Load the storage slot tracking the tstore activation block number.
            let tstoreSupportActiveAt := sload(_tstoreSupportActiveAt.slot)

            // Use sstore if no value is set or if value is greater than current block number.
            useSstore := or(iszero(tstoreSupportActiveAt), gt(tstoreSupportActiveAt, number()))
        }
    }
}
