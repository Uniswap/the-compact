// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { EfficiencyLib } from "./EfficiencyLib.sol";

/**
 * @title Tstorish
 * @notice Inheritable contract implementing logic for determining whether or not
 * transient storage is available in the current EVM environment and utilizing it
 * if it has been confirmed to be available (either at time of deployment or by
 * explicitly activating it at a later point).
 */
contract Tstorish {
    using EfficiencyLib for bool;
    using EfficiencyLib for address;

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

    // Declare a storage variable indicating when TSTORE support will be
    // activated assuming it was not already active at initial deployment.
    uint256 private _tstoreSupportActiveAt;

    // Declare a few custom errors.
    error TStoreAlreadyActivated();
    error TStoreNotSupported();
    error TloadTestContractDeploymentFailed();

    /**
     * @notice Determine TSTORE availability during deployment. This involves
     * attempting to deploy a contract that utilizes TLOAD as part of the contract
     * construction bytecode, and configuring initial support for using TSTORE in
     * place of SSTORE based on the result.
     */
    constructor() {
        // Deploy the contract testing TLOAD support and store the address.
        address tloadTestContract = _deployTloadTest();

        // Ensure the deployment was successful.
        if (tloadTestContract.isNullAddress()) {
            revert TloadTestContractDeploymentFailed();
        }

        // Determine if TSTORE is supported.
        _tstoreInitialSupport = _testTload(tloadTestContract);

        // Set the address of the deployed TLOAD test contract as an immutable.
        _tloadTestContract = tloadTestContract;
    }

    /**
     * @notice External function to activate TSTORE usage. Does not need to be called
     * if TSTORE is supported from deployment, and only needs to be called once.
     * Reverts if TSTORE has already been activated or if the opcode is not available.
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
     * @notice Internal function to write a value to a given slot using either transient
     * storage or standard storage depending on the activation status.
     *
     * @param slot  The slot to write the value to.
     * @param value The value to write to the given slot.
     */
    function _setTstorish(uint256 slot, uint256 value) internal {
        // Retrieve initial support status from the immutable variable and place it on the stack.
        bool tstoreInitialSupport = _tstoreInitialSupport;

        assembly ("memory-safe") {
            // Use a faux loop to support breaking early.
            for { } 1 { } {
                if iszero(tstoreInitialSupport) {
                    // Load the storage slot tracking the tstore activation block number.
                    let tstoreSupportActiveAt := sload(_tstoreSupportActiveAt.slot)

                    // Use sstore if no value is set or if value is greater than current block number.
                    let useSstore := or(iszero(tstoreSupportActiveAt), gt(tstoreSupportActiveAt, number()))

                    if useSstore {
                        sstore(slot, value)
                        break
                    }
                }

                tstore(slot, value)
                break
            }
        }
    }

    /**
     * @notice Internal view function to read the value of a given slot using either transient
     * storage or standard storage depending on the activation status.
     *
     * @param slot   The slot to read the value from.
     * @return value The value at the given slot.
     */
    function _getTstorish(uint256 slot) internal view returns (uint256 value) {
        // Retrieve initial support status from the immutable variable and place it on the stack.
        bool tstoreInitialSupport = _tstoreInitialSupport;

        assembly ("memory-safe") {
            // Use a faux loop to support breaking early.
            for { } 1 { } {
                if iszero(tstoreInitialSupport) {
                    // Load the storage slot tracking the tstore activation block number.
                    let tstoreSupportActiveAt := sload(_tstoreSupportActiveAt.slot)

                    // Use sstore if no value is set or if value is greater than current block number.
                    let useSstore := or(iszero(tstoreSupportActiveAt), gt(tstoreSupportActiveAt, number()))

                    if useSstore {
                        value := sload(slot)
                        break
                    }
                }

                value := tload(slot)
                break
            }
        }
    }

    /**
     * @notice Internal view function to determine if TSTORE/TLOAD are supported by
     * the current EVM implementation by attempting to call the test contract, which
     * utilizes TLOAD as part of its fallback logic. The function is marked as
     * *internal virtual* to facilitate overriding as part of tests.
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
     * @notice Private function to deploy a test contract that utilizes TLOAD as
     * part of its fallback logic.
     */
    function _deployTloadTest() private returns (address contractAddress) {
        // Utilize assembly to deploy a contract testing TLOAD support.
        assembly ("memory-safe") {
            // Write the contract deployment code payload to scratch space.
            mstore(0, _TLOAD_TEST_PAYLOAD)

            // Deploy the contract.
            contractAddress := create(0, _TLOAD_TEST_PAYLOAD_OFFSET, _TLOAD_TEST_PAYLOAD_LENGTH)
        }
    }
}
