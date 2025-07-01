// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Tstorish } from "../lib/Tstorish.sol";

contract TstorishMock is Tstorish {
    bool public mockTstoreIsActive;

    function activateMockTstore() external {
        mockTstoreIsActive = true;
    }

    function setMockValue() external {
        _setTstorish(12345, 67890);
    }

    function checkMockValue() external view returns (bool mockValueSet) {
        mockValueSet = _getTstorish(12345) == 67890;
    }

    function clearSstoreSlot() external {
        assembly ("memory-safe") {
            sstore(12345, 0)
        }
    }

    function checkTstoreSlot() external view returns (bool mockValueSet) {
        assembly ("memory-safe") {
            mockValueSet := eq(tload(12345), 67890)
        }
    }

    function checkSstoreSlot() external view returns (bool mockValueSet) {
        assembly ("memory-safe") {
            mockValueSet := eq(sload(12345), 67890)
        }
    }

    function _testTload(address) internal view override returns (bool) {
        return mockTstoreIsActive;
    }
}
