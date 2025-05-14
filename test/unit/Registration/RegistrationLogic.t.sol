// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { Scope } from "src/types/Scope.sol";
import { COMPACT_TYPEHASH, BATCH_COMPACT_TYPEHASH } from "src/types/EIP712Types.sol";
import "src/lib/HashLib.sol";
import "src/lib/RegistrationLib.sol";
import "./MockRegistrationLogic.sol";
import { console2 } from "forge-std/console2.sol";

contract RegistrationLogicTest is Test {
    using RegistrationLib for address;

    MockRegistrationLogic logic;

    address sponsor;
    address arbiter;

    function setUp() public {
        logic = new MockRegistrationLogic();

        sponsor = makeAddr("sponsor");
        arbiter = makeAddr("arbiter");

        vm.warp(1743479729);
    }

    function test_register() public {
        bytes32 claimHash = keccak256("test claim");
        bytes32 typehash = COMPACT_TYPEHASH;

        logic.register(sponsor, claimHash, typehash);

        uint256 registrationTs = logic.getRegistrationStatus(sponsor, claimHash, typehash);
        assertEq(registrationTs, block.timestamp, "Registration timestamp should match block timestamp");
    }

    function test_registerBatch() public {
        bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](3);

        for (uint256 i = 0; i < 3; i++) {
            bytes32 claimHash = keccak256(abi.encode("test claim", i));
            bytes32 typehash = i % 2 == 0 ? COMPACT_TYPEHASH : BATCH_COMPACT_TYPEHASH;

            claimHashesAndTypehashes[i][0] = claimHash;
            claimHashesAndTypehashes[i][1] = typehash;
        }

        bool success = logic.registerBatch(claimHashesAndTypehashes);
        assertTrue(success, "Batch registration should succeed");

        // Verify registrations
        for (uint256 i = 0; i < 3; i++) {
            bytes32 claimHash = claimHashesAndTypehashes[i][0];
            bytes32 typehash = claimHashesAndTypehashes[i][1];

            uint256 registrationTs = logic.getRegistrationStatus(address(this), claimHash, typehash);
            assertEq(registrationTs, block.timestamp, "Registration timestamp should match block timestamp");
        }
    }

    function test_registerUsingClaimWithWitness() public {
        uint256 tokenId = 1;
        uint256 amount = 100;
        uint256 nonce = 42;
        uint256 expires = block.timestamp + 1 days;
        bytes32 typehash = COMPACT_TYPEHASH;
        bytes32 witness = keccak256("witness data");

        bytes32 claimHash =
            logic.registerUsingClaimWithWitness(sponsor, tokenId, amount, arbiter, nonce, expires, typehash, witness);

        // Verify the claim is registered
        uint256 registrationTs = logic.getRegistrationStatus(sponsor, claimHash, typehash);
        assertEq(registrationTs, block.timestamp, "Registration timestamp should match block timestamp");

        // Verify the generated claimHash matches expected
        bytes32 expectedClaimHash =
            HashLib.toFlatMessageHashWithWitness(sponsor, tokenId, amount, arbiter, nonce, expires, typehash, witness);
        assertEq(claimHash, expectedClaimHash, "Claim hash should match expected value");
    }

    function test_registerUsingBatchClaimWithWitness() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0] = [uint256(1), uint256(100)];
        idsAndAmounts[1] = [uint256(2), uint256(200)];

        uint256 nonce = 42;
        uint256 expires = block.timestamp + 1 days;
        bytes32 typehash = BATCH_COMPACT_TYPEHASH;
        bytes32 witness = keccak256("batch witness data");

        bytes32 claimHash =
            logic.registerUsingBatchClaimWithWitness(sponsor, idsAndAmounts, arbiter, nonce, expires, typehash, witness);

        // Verify the claim is registered
        uint256 registrationTs = logic.getRegistrationStatus(sponsor, claimHash, typehash);
        assertEq(registrationTs, block.timestamp, "Registration timestamp should match block timestamp");

        // Verify the generated claimHash matches expected
        bytes32 expectedClaimHash =
            _toFlatBatchClaimWithWitnessMessageHash(sponsor, idsAndAmounts, arbiter, nonce, expires, typehash, witness);
        assertEq(claimHash, expectedClaimHash, "Batch claim hash should match expected value");
    }

    function test_getRegistrationStatus_nonexistent() public view {
        bytes32 claimHash = keccak256("look ma, no claim");
        bytes32 typehash = COMPACT_TYPEHASH;

        uint256 registrationTs = logic.getRegistrationStatus(sponsor, claimHash, typehash);
        assertEq(registrationTs, 0, "Registration timestamp for nonexistent claim should be 0");
    }

    function test_register_zeroAddress() public {
        bytes32 claimHash = keccak256("test claim for zero address");
        bytes32 typehash = COMPACT_TYPEHASH;

        // Register with zero address as sponsor
        logic.register(address(0), claimHash, typehash);

        // Verify registration for zero address
        uint256 registrationTs = logic.getRegistrationStatus(address(0), claimHash, typehash);
        assertEq(registrationTs, block.timestamp, "Registration for zero address should succeed");
    }

    function test_register_zeroHash() public {
        bytes32 claimHash = bytes32(0);
        bytes32 typehash = COMPACT_TYPEHASH;

        // Register with zero hash
        logic.register(sponsor, claimHash, typehash);

        // Verify registration with zero hash
        uint256 registrationTs = logic.getRegistrationStatus(sponsor, claimHash, typehash);
        assertEq(registrationTs, block.timestamp, "Registration with zero hash should succeed");
    }

    function test_register_reregistration() public {
        bytes32 claimHash = keccak256("test claim for reregistration");
        bytes32 typehash = COMPACT_TYPEHASH;

        // First registration
        logic.register(sponsor, claimHash, typehash);
        uint256 firstRegistrationTs = logic.getRegistrationStatus(sponsor, claimHash, typehash);

        // Jump ahead in time
        vm.warp(block.timestamp + 1 days);

        // Re-register the same claim
        logic.register(sponsor, claimHash, typehash);
        uint256 secondRegistrationTs = logic.getRegistrationStatus(sponsor, claimHash, typehash);

        // Verify timestamp updated
        assertNotEq(
            firstRegistrationTs, secondRegistrationTs, "Registration timestamp should update on re-registration"
        );
        assertEq(secondRegistrationTs, block.timestamp, "New registration timestamp should match current block time");
    }

    function test_registerBatch_emptyArray() public {
        bytes32[2][] memory emptyArray = new bytes32[2][](0);

        // Should succeed with empty array
        bool success = logic.registerBatch(emptyArray);
        assertTrue(success, "Batch registration with empty array should succeed");
    }

    function test_registerBatch_duplicateEntries() public {
        bytes32[2][] memory duplicateEntries = new bytes32[2][](3);

        // Create three entries with two duplicates
        bytes32 duplicateClaimHash = keccak256("duplicate");
        bytes32 typehash = COMPACT_TYPEHASH;

        duplicateEntries[0][0] = duplicateClaimHash;
        duplicateEntries[0][1] = typehash;

        duplicateEntries[1][0] = keccak256("unique");
        duplicateEntries[1][1] = typehash;

        duplicateEntries[2][0] = duplicateClaimHash; // Duplicate of first entry
        duplicateEntries[2][1] = typehash;

        // Register batch with duplicates
        bool success = logic.registerBatch(duplicateEntries);
        assertTrue(success, "Batch registration with duplicates should succeed");

        // Verify registrations (all should be registered)
        for (uint256 i = 0; i < 3; i++) {
            bytes32 claimHash = duplicateEntries[i][0];
            bytes32 entryTypehash = duplicateEntries[i][1];

            uint256 registrationTs = logic.getRegistrationStatus(address(this), claimHash, entryTypehash);
            assertEq(registrationTs, block.timestamp, "Registration timestamp should match block timestamp");
        }
    }

    function test_registerUsingClaimWithWitness_zeroValues() public {
        uint256 tokenId;
        uint256 amount;
        uint256 nonce;
        uint256 expires;
        bytes32 typehash = COMPACT_TYPEHASH;
        bytes32 witness = bytes32(0);

        bytes32 claimHash = logic.registerUsingClaimWithWitness(
            address(0), tokenId, amount, address(0), nonce, expires, typehash, witness
        );

        uint256 registrationTs = logic.getRegistrationStatus(address(0), claimHash, typehash);
        assertEq(registrationTs, block.timestamp, "Registration with zero values should succeed");
    }

    function test_registerUsingBatchClaimWithWitness_emptyArray() public {
        uint256[2][] memory emptyArray = new uint256[2][](0);

        uint256 nonce = 42;
        uint256 expires = block.timestamp + 1 days;
        bytes32 typehash = BATCH_COMPACT_TYPEHASH;
        bytes32 witness = keccak256("empty batch witness data");

        bytes32 claimHash =
            logic.registerUsingBatchClaimWithWitness(sponsor, emptyArray, arbiter, nonce, expires, typehash, witness);

        // Verify the claim is registered
        uint256 registrationTs = logic.getRegistrationStatus(sponsor, claimHash, typehash);
        assertEq(registrationTs, block.timestamp, "Registration with empty array should succeed");
    }

    function test_registerUsingBatchClaimWithWitness_maxValues() public {
        uint256[2][] memory maxValues = new uint256[2][](2);
        maxValues[0] = [type(uint256).max, type(uint256).max];
        maxValues[1] = [type(uint256).max, type(uint256).max];

        uint256 nonce = type(uint256).max;
        uint256 expires = type(uint256).max;
        bytes32 typehash = BATCH_COMPACT_TYPEHASH;
        bytes32 witness = keccak256("max value witness");

        bytes32 claimHash =
            logic.registerUsingBatchClaimWithWitness(sponsor, maxValues, arbiter, nonce, expires, typehash, witness);

        // Verify the claim is registered
        uint256 registrationTs = logic.getRegistrationStatus(sponsor, claimHash, typehash);
        assertEq(registrationTs, block.timestamp, "Registration with maximum values should succeed");
    }

    /// @dev this is a copy of the function in HashLib, modified to accept memory args
    function _toFlatBatchClaimWithWitnessMessageHash(
        address _sponsor,
        uint256[2][] memory _idsAndAmounts,
        address _arbiter,
        uint256 _nonce,
        uint256 _expires,
        bytes32 _typehash,
        bytes32 _witness
    ) internal pure returns (bytes32 messageHash) {
        bytes memory packedData = abi.encode(
            _typehash, _arbiter, _sponsor, _nonce, _expires, keccak256(abi.encodePacked(_idsAndAmounts)), _witness
        );
        messageHash = keccak256(packedData);
    }
}
