// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";
import { ClaimHashLib } from "src/lib/ClaimHashLib.sol";
import { ClaimHashFunctionCastLib } from "src/lib/ClaimHashFunctionCastLib.sol";
import { HashLib } from "src/lib/HashLib.sol";
import { EfficiencyLib } from "src/lib/EfficiencyLib.sol";
import { IdLib } from "src/lib/IdLib.sol";

import { AllocatedTransfer, Claim } from "src/types/Claims.sol";
import { AllocatedBatchTransfer, BatchClaim } from "src/types/BatchClaims.sol";
import { MultichainClaim, ExogenousMultichainClaim } from "src/types/MultichainClaims.sol";
import { BatchMultichainClaim, ExogenousBatchMultichainClaim } from "src/types/BatchMultichainClaims.sol";
import { Component, ComponentsById, BatchClaimComponent } from "src/types/Components.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { Scope } from "src/types/Scope.sol";

import {
    COMPACT_TYPEHASH,
    COMPACT_TYPESTRING_FRAGMENT_ONE,
    COMPACT_TYPESTRING_FRAGMENT_TWO,
    COMPACT_TYPESTRING_FRAGMENT_THREE,
    COMPACT_TYPESTRING_FRAGMENT_FOUR,
    BATCH_COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX,
    PERMIT2_DEPOSIT_WITNESS_FRAGMENT_HASH
} from "src/types/EIP712Types.sol";

contract ClaimHashLibTester {
    using ClaimHashLib for BatchClaimComponent[];
    using ClaimHashLib for *;
    using HashLib for *;

    function callToClaimHash(AllocatedTransfer calldata transfer) external view returns (bytes32) {
        return ClaimHashLib.toClaimHash(transfer);
    }

    function callToClaimHash(AllocatedBatchTransfer calldata transfer) external view returns (bytes32) {
        return ClaimHashLib.toClaimHash(transfer);
    }

    function callToMessageHashes(Claim calldata claim) external view returns (bytes32 claimHash, bytes32 typehash) {
        return ClaimHashLib.toMessageHashes(claim);
    }

    function callToMessageHashes(BatchClaim calldata claim)
        external
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return ClaimHashLib.toMessageHashes(claim);
    }

    function callToMessageHashes(MultichainClaim calldata claim)
        external
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return ClaimHashLib.toMessageHashes(claim);
    }

    function callToMessageHashes(BatchMultichainClaim calldata claim)
        external
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return ClaimHashLib.toMessageHashes(claim);
    }

    function callToMessageHashes(ExogenousMultichainClaim calldata claim)
        external
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return ClaimHashLib.toMessageHashes(claim);
    }

    function callToMessageHashes(ExogenousBatchMultichainClaim calldata claim)
        external
        view
        returns (bytes32 claimHash, bytes32 typehash)
    {
        return ClaimHashLib.toMessageHashes(claim);
    }

    function callToIdsAndAmountsHash(BatchClaimComponent[] calldata claims) external pure returns (uint256) {
        return claims.toIdsAndAmountsHash();
    }

    function callToIdsAndAmountsHash(uint256[2][] calldata idsAndAmounts) external pure returns (bytes32) {
        return idsAndAmounts.toIdsAndAmountsHash(new uint256[](0));
    }
}

contract ClaimHashLibTest is Test {
    using EfficiencyLib for address;

    ClaimHashLibTester internal tester;

    address constant SPONSOR = address(0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa);
    address constant CLAIMANT = address(0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB);
    address constant ARBITER = address(0xCcCCcCCcCCCcccCccccCcCCcCCCCCcCcCcCCCcC1);
    bytes32 constant WITNESS = bytes32(uint256(123456789));

    function setUp() public {
        tester = new ClaimHashLibTester();
    }

    function testToClaimHash_AllocatedTransfer() public view {
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });

        AllocatedTransfer memory transfer = AllocatedTransfer({
            allocatorData: bytes(""),
            nonce: 12345,
            expires: block.timestamp + 1 days,
            id: 1,
            recipients: recipients
        });

        bytes32 expectedTypehash = COMPACT_TYPEHASH;
        bytes32 expectedHash = keccak256(
            abi.encode(
                expectedTypehash,
                address(this),
                address(this),
                transfer.nonce,
                transfer.expires,
                transfer.id,
                uint256(100)
            )
        );

        assertEq(tester.callToClaimHash(transfer), expectedHash);
    }

    function testToClaimHash_AllocatedBatchTransfer() public view {
        Component[] memory portions1 = new Component[](1);
        portions1[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });

        Component[] memory portions2 = new Component[](1);
        portions2[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 200 });

        ComponentsById[] memory transfers = new ComponentsById[](2);
        transfers[0] = ComponentsById({ id: 1, portions: portions1 });
        transfers[1] = ComponentsById({ id: 2, portions: portions2 });

        AllocatedBatchTransfer memory batchTransfer = AllocatedBatchTransfer({
            allocatorData: bytes(""),
            nonce: 12345,
            expires: block.timestamp + 1 days,
            transfers: transfers
        });

        bytes32 idsAndAmountsHash = keccak256(abi.encode(uint256(1), uint256(100), uint256(2), uint256(200)));

        bytes32 expectedHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                address(this),
                address(this),
                batchTransfer.nonce,
                batchTransfer.expires,
                idsAndAmountsHash
            )
        );

        assertEq(
            tester.callToClaimHash(batchTransfer), expectedHash, "Batch transfer hash doesn't match expected value"
        );
    }

    function testToMessageHashes_Claim() public view {
        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });

        Claim memory claim = Claim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            id: 1,
            allocatedAmount: 100,
            claimants: claimants
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(claim);

        bytes32 expectedTypehash = keccak256(
            abi.encodePacked(
                COMPACT_TYPESTRING_FRAGMENT_ONE,
                COMPACT_TYPESTRING_FRAGMENT_TWO,
                COMPACT_TYPESTRING_FRAGMENT_THREE,
                COMPACT_TYPESTRING_FRAGMENT_FOUR,
                "Witness)"
            )
        );

        bytes32 expectedClaimHash = keccak256(
            abi.encode(
                expectedTypehash,
                address(this),
                claim.sponsor,
                claim.nonce,
                claim.expires,
                claim.id,
                claim.allocatedAmount,
                claim.witness
            )
        );

        assertEq(actualTypehash, expectedTypehash, "Typehash should match expected value");
        assertEq(actualClaimHash, expectedClaimHash, "Claim hash should match expected value");
    }

    function testToMessageHashes_BatchClaim() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);

        Component[] memory portions1 = new Component[](1);
        portions1[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });
        claims[0] = BatchClaimComponent({ id: 1, allocatedAmount: 100, portions: portions1 });

        Component[] memory portions2 = new Component[](1);
        portions2[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 200 });
        claims[1] = BatchClaimComponent({ id: 2, allocatedAmount: 200, portions: portions2 });

        BatchClaim memory batchClaim = BatchClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            claims: claims
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(batchClaim);

        bytes32 expectedTypehash = keccak256(
            abi.encodePacked(
                BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
                BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
                BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
                BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
                "Witness)"
            )
        );

        bytes32 idsAndAmountsHash = keccak256(abi.encode(uint256(1), uint256(100), uint256(2), uint256(200)));

        bytes32 expectedClaimHash = keccak256(
            abi.encode(
                expectedTypehash,
                address(this),
                batchClaim.sponsor,
                batchClaim.nonce,
                batchClaim.expires,
                idsAndAmountsHash,
                batchClaim.witness
            )
        );

        assertEq(actualTypehash, expectedTypehash, "Typehash should match expected value");
        assertEq(actualClaimHash, expectedClaimHash, "Claim hash should match expected value");
    }

    function testToMessageHashes_MultichainClaim() public view {
        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });

        bytes32[] memory additionalChains = new bytes32[](1);
        additionalChains[0] = bytes32(uint256(1));

        MultichainClaim memory claim = MultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            id: 1,
            allocatedAmount: 100,
            claimants: claimants
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(claim);
        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(actualTypehash, expectedTypehash);

        bytes32 idsAndAmountsHashBytes = keccak256(abi.encode(claim.id, claim.allocatedAmount));
        uint256 idsAndAmountsHash = uint256(idsAndAmountsHashBytes);

        bytes32 thisChainElementHash =
            _computeElementHash(expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, claim.witness);

        bytes32 elementsHash = _computeNonExoElementsHash(thisChainElementHash, additionalChains);

        bytes32 expectedClaimHash =
            keccak256(abi.encode(expectedTypehash, claim.sponsor, claim.nonce, claim.expires, elementsHash));

        assertEq(actualClaimHash, expectedClaimHash, "Claim hash should match expected value");
    }

    function testToMessageHashes_BatchMultichainClaim() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        Component[] memory portions = new Component[](1);
        portions[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });
        claims[0] = BatchClaimComponent({ id: 1, allocatedAmount: 100, portions: portions });

        bytes32[] memory additionalChains = new bytes32[](5);
        additionalChains[0] = bytes32(uint256(1));
        additionalChains[1] = bytes32(uint256(2));
        additionalChains[2] = bytes32(uint256(3));
        additionalChains[3] = bytes32(uint256(4));
        additionalChains[4] = bytes32(uint256(5));

        BatchMultichainClaim memory batchClaim = BatchMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            claims: claims
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(batchClaim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(actualTypehash, expectedTypehash);

        uint256 idsAndAmountsHash = tester.callToIdsAndAmountsHash(claims);

        bytes32 thisChainElementHash = _computeElementHash(
            expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, batchClaim.witness
        );

        bytes32 elementsHash = _computeNonExoElementsHash(thisChainElementHash, additionalChains);

        bytes32 expectedClaimHash = keccak256(
            abi.encode(expectedTypehash, batchClaim.sponsor, batchClaim.nonce, batchClaim.expires, elementsHash)
        );

        assertEq(actualClaimHash, expectedClaimHash, "Claim hash should match expected value");
    }

    function testToMessageHashes_ExogenousMultichainClaim() public view {
        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });

        bytes32[] memory additionalChains = new bytes32[](1);
        additionalChains[0] = bytes32(uint256(1));

        ExogenousMultichainClaim memory claim = ExogenousMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            chainIndex: 0,
            notarizedChainId: 1,
            id: 1,
            allocatedAmount: 100,
            claimants: claimants
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(claim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(actualTypehash, expectedTypehash);

        bytes32 idsAndAmountsHashBytes = keccak256(abi.encode(claim.id, claim.allocatedAmount));
        uint256 idsAndAmountsHash = uint256(idsAndAmountsHashBytes);

        bytes32 elementHash =
            _computeElementHash(expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, claim.witness);

        bytes32 elementsHash = _computeExoElementsHash(elementHash, additionalChains, claim.chainIndex);

        bytes32 expectedClaimHash =
            keccak256(abi.encode(expectedTypehash, claim.sponsor, claim.nonce, claim.expires, elementsHash));

        assertEq(actualClaimHash, expectedClaimHash, "Claim hash should match expected value");
    }

    function testToMessageHashes_ExogenousBatchMultichainClaim() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        Component[] memory portions = new Component[](1);
        portions[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });
        claims[0] = BatchClaimComponent({ id: 1, allocatedAmount: 100, portions: portions });

        bytes32[] memory additionalChains = new bytes32[](1);
        additionalChains[0] = bytes32(uint256(1));

        ExogenousBatchMultichainClaim memory batchClaim = ExogenousBatchMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            chainIndex: 0,
            notarizedChainId: 1,
            claims: claims
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(batchClaim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(actualTypehash, expectedTypehash);

        uint256 idsAndAmountsHash = tester.callToIdsAndAmountsHash(claims);

        bytes32 elementHash = _computeElementHash(
            expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, batchClaim.witness
        );

        bytes32 elementsHash = _computeExoElementsHash(elementHash, additionalChains, batchClaim.chainIndex);

        bytes32 expectedClaimHash = keccak256(
            abi.encode(expectedTypehash, batchClaim.sponsor, batchClaim.nonce, batchClaim.expires, elementsHash)
        );

        assertEq(actualClaimHash, expectedClaimHash, "Hash should match expected value");
    }

    function testFunctionCast_BatchMultichainClaim() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        Component[] memory portions = new Component[](1);
        portions[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });
        claims[0] = BatchClaimComponent({ id: 1, allocatedAmount: 100, portions: portions });

        bytes32[] memory additionalChains = new bytes32[](2);
        additionalChains[0] = bytes32(uint256(1));
        additionalChains[1] = bytes32(uint256(2));

        BatchMultichainClaim memory batchClaim = BatchMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            claims: claims
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(batchClaim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(actualTypehash, expectedTypehash, "Typehash should match expected value (cast batch multi-chain)");

        uint256 idsAndAmountsHash = tester.callToIdsAndAmountsHash(claims);

        bytes32 thisChainElementHash = keccak256(
            abi.encode(expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, batchClaim.witness)
        );

        bytes32 elementsHash =
            keccak256(abi.encodePacked(thisChainElementHash, additionalChains[0], additionalChains[1]));

        bytes32 expectedClaimHash = keccak256(
            abi.encode(expectedTypehash, batchClaim.sponsor, batchClaim.nonce, batchClaim.expires, elementsHash)
        );

        assertEq(actualClaimHash, expectedClaimHash, "Hash should match expected value (cast batch multi-chain)");
    }

    function testFunctionCast_ExogenousBatchMultichainClaim() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        Component[] memory portions = new Component[](1);
        portions[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });
        claims[0] = BatchClaimComponent({ id: 1, allocatedAmount: 100, portions: portions });

        bytes32[] memory additionalChains = new bytes32[](5);
        additionalChains[0] = bytes32(uint256(1));
        additionalChains[1] = bytes32(uint256(2)); // This will be replaced
        additionalChains[2] = bytes32(uint256(3));
        additionalChains[3] = bytes32(uint256(4));
        additionalChains[4] = bytes32(uint256(5));

        ExogenousBatchMultichainClaim memory batchClaim = ExogenousBatchMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            chainIndex: 1, // Replace the second element
            notarizedChainId: 1,
            claims: claims
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(batchClaim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(
            actualTypehash,
            expectedTypehash,
            "Typehash should match expected value (cast exo batch multi-chain index 1)"
        );

        uint256 idsAndAmountsHash = tester.callToIdsAndAmountsHash(claims);

        bytes32 elementHash = _computeElementHash(
            expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, batchClaim.witness
        );

        bytes32 elementsHash = _computeExoElementsHash(elementHash, additionalChains, batchClaim.chainIndex);

        bytes32 expectedClaimHash = keccak256(
            abi.encode(expectedTypehash, batchClaim.sponsor, batchClaim.nonce, batchClaim.expires, elementsHash)
        );

        assertEq(
            actualClaimHash, expectedClaimHash, "Hash should match expected value (cast exo batch multi-chain index 1)"
        );
    }

    function testToMessageHashes_MultichainClaim_MultipleChains() public view {
        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });

        bytes32[] memory additionalChains = new bytes32[](5);
        additionalChains[0] = bytes32(uint256(1));
        additionalChains[1] = bytes32(uint256(2));
        additionalChains[2] = bytes32(uint256(3));
        additionalChains[3] = bytes32(uint256(4));
        additionalChains[4] = bytes32(uint256(5));

        MultichainClaim memory claim = MultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            id: 1,
            allocatedAmount: 100,
            claimants: claimants
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(claim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(actualTypehash, expectedTypehash, "Typehash should match expected value (multi-chain)");

        bytes32 idsAndAmountsHashBytes = keccak256(abi.encode(claim.id, claim.allocatedAmount));
        uint256 idsAndAmountsHash = uint256(idsAndAmountsHashBytes);

        bytes32 thisChainElementHash =
            _computeElementHash(expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, claim.witness);

        bytes32 elementsHash = _computeNonExoElementsHash(thisChainElementHash, additionalChains);

        bytes32 expectedClaimHash =
            keccak256(abi.encode(expectedTypehash, claim.sponsor, claim.nonce, claim.expires, elementsHash));

        assertEq(actualClaimHash, expectedClaimHash, "Claim hash should match expected value (multi-chain)");
    }

    function testToMessageHashes_BatchMultichainClaim_MultipleChains() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        Component[] memory portions = new Component[](1);
        portions[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });
        claims[0] = BatchClaimComponent({ id: 1, allocatedAmount: 100, portions: portions });

        bytes32[] memory additionalChains = new bytes32[](5);
        additionalChains[0] = bytes32(uint256(1));
        additionalChains[1] = bytes32(uint256(2));
        additionalChains[2] = bytes32(uint256(3));
        additionalChains[3] = bytes32(uint256(4));
        additionalChains[4] = bytes32(uint256(5));

        BatchMultichainClaim memory batchClaim = BatchMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            claims: claims
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(batchClaim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(actualTypehash, expectedTypehash, "Typehash should match expected value (batch multi-chain)");

        uint256 idsAndAmountsHash = tester.callToIdsAndAmountsHash(claims);

        bytes32 thisChainElementHash = _computeElementHash(
            expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, batchClaim.witness
        );

        bytes32 elementsHash = _computeNonExoElementsHash(thisChainElementHash, additionalChains);

        bytes32 expectedClaimHash = keccak256(
            abi.encode(expectedTypehash, batchClaim.sponsor, batchClaim.nonce, batchClaim.expires, elementsHash)
        );

        assertEq(actualClaimHash, expectedClaimHash, "Claim hash should match expected value (batch multi-chain)");
    }

    function testToMessageHashes_ExogenousMultichainClaim_MultipleChains_Index1() public view {
        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });

        bytes32[] memory additionalChains = new bytes32[](5);
        additionalChains[0] = bytes32(uint256(1));
        additionalChains[1] = bytes32(uint256(2));
        additionalChains[2] = bytes32(uint256(3));
        additionalChains[3] = bytes32(uint256(4));
        additionalChains[4] = bytes32(uint256(5));

        ExogenousMultichainClaim memory claim = ExogenousMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            chainIndex: 1, // Replace the second element
            notarizedChainId: 1,
            id: 1,
            allocatedAmount: 100,
            claimants: claimants
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(claim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(actualTypehash, expectedTypehash, "Typehash should match expected value (exo multi-chain index 1)");

        bytes32 idsAndAmountsHashBytes = keccak256(abi.encode(claim.id, claim.allocatedAmount));
        uint256 idsAndAmountsHash = uint256(idsAndAmountsHashBytes);

        bytes32 elementHash =
            _computeElementHash(expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, claim.witness);

        bytes32 elementsHash = _computeExoElementsHash(elementHash, additionalChains, claim.chainIndex);

        bytes32 expectedClaimHash =
            keccak256(abi.encode(expectedTypehash, claim.sponsor, claim.nonce, claim.expires, elementsHash));

        assertEq(actualClaimHash, expectedClaimHash, "Claim hash should match expected value (exo multi-chain index 1)");
    }

    function testToMessageHashes_ExogenousBatchMultichainClaim_MultipleChains_Index1() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        Component[] memory portions = new Component[](1);
        portions[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });
        claims[0] = BatchClaimComponent({ id: 1, allocatedAmount: 100, portions: portions });

        bytes32[] memory additionalChains = new bytes32[](5);
        additionalChains[0] = bytes32(uint256(1));
        additionalChains[1] = bytes32(uint256(2));
        additionalChains[2] = bytes32(uint256(3));
        additionalChains[3] = bytes32(uint256(4));
        additionalChains[4] = bytes32(uint256(5));

        ExogenousBatchMultichainClaim memory batchClaim = ExogenousBatchMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            chainIndex: 1, // Replace the second element
            notarizedChainId: 1,
            claims: claims
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(batchClaim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(
            actualTypehash,
            expectedTypehash,
            "Typehash should match expected value (cast exo batch multi-chain index 1)"
        );

        uint256 idsAndAmountsHash = tester.callToIdsAndAmountsHash(claims);

        bytes32 elementHash = _computeElementHash(
            expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, batchClaim.witness
        );

        bytes32 elementsHash = _computeExoElementsHash(elementHash, additionalChains, batchClaim.chainIndex);

        bytes32 expectedClaimHash = keccak256(
            abi.encode(expectedTypehash, batchClaim.sponsor, batchClaim.nonce, batchClaim.expires, elementsHash)
        );

        assertEq(
            actualClaimHash, expectedClaimHash, "Hash should match expected value (cast exo batch multi-chain index 1)"
        );
    }

    function testFunctionCast_BatchMultichainClaim_MultipleChains() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        Component[] memory portions = new Component[](1);
        portions[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });
        claims[0] = BatchClaimComponent({ id: 1, allocatedAmount: 100, portions: portions });

        bytes32[] memory additionalChains = new bytes32[](5);
        additionalChains[0] = bytes32(uint256(1));
        additionalChains[1] = bytes32(uint256(2));
        additionalChains[2] = bytes32(uint256(3));
        additionalChains[3] = bytes32(uint256(4));
        additionalChains[4] = bytes32(uint256(5));

        BatchMultichainClaim memory batchClaim = BatchMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            claims: claims
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(batchClaim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(actualTypehash, expectedTypehash, "Typehash should match expected value (cast batch multi-chain)");

        uint256 idsAndAmountsHash = tester.callToIdsAndAmountsHash(claims);

        bytes32 thisChainElementHash = _computeElementHash(
            expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, batchClaim.witness
        );

        bytes32 elementsHash = _computeNonExoElementsHash(thisChainElementHash, additionalChains);

        bytes32 expectedClaimHash = keccak256(
            abi.encode(expectedTypehash, batchClaim.sponsor, batchClaim.nonce, batchClaim.expires, elementsHash)
        );

        assertEq(actualClaimHash, expectedClaimHash, "Hash should match expected value (cast batch multi-chain)");
    }

    function testFunctionCast_ExogenousBatchMultichainClaim_MultipleChains_Index1() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        Component[] memory portions = new Component[](1);
        portions[0] = Component({ claimant: CLAIMANT.asUint256(), amount: 100 });
        claims[0] = BatchClaimComponent({ id: 1, allocatedAmount: 100, portions: portions });

        bytes32[] memory additionalChains = new bytes32[](5);
        additionalChains[0] = bytes32(uint256(1));
        additionalChains[1] = bytes32(uint256(2)); // This will be replaced
        additionalChains[2] = bytes32(uint256(3));
        additionalChains[3] = bytes32(uint256(4));
        additionalChains[4] = bytes32(uint256(5));

        ExogenousBatchMultichainClaim memory batchClaim = ExogenousBatchMultichainClaim({
            allocatorData: bytes(""),
            sponsorSignature: bytes(""),
            sponsor: SPONSOR,
            nonce: 12345,
            expires: block.timestamp + 1 days,
            witness: WITNESS,
            witnessTypestring: "Witness",
            additionalChains: additionalChains,
            chainIndex: 1, // Replace the second element
            notarizedChainId: 1,
            claims: claims
        });

        (bytes32 actualClaimHash, bytes32 actualTypehash) = tester.callToMessageHashes(batchClaim);

        (bytes32 expectedElementTypehash, bytes32 expectedTypehash) = _computeMultichainTypehashes("Witness");
        assertEq(
            actualTypehash,
            expectedTypehash,
            "Typehash should match expected value (cast exo batch multi-chain index 1)"
        );

        uint256 idsAndAmountsHash = tester.callToIdsAndAmountsHash(claims);

        bytes32 elementHash = _computeElementHash(
            expectedElementTypehash, address(this), block.chainid, idsAndAmountsHash, batchClaim.witness
        );

        bytes32 elementsHash = _computeExoElementsHash(elementHash, additionalChains, batchClaim.chainIndex);

        bytes32 expectedClaimHash = keccak256(
            abi.encode(expectedTypehash, batchClaim.sponsor, batchClaim.nonce, batchClaim.expires, elementsHash)
        );

        assertEq(
            actualClaimHash, expectedClaimHash, "Hash should match expected value (cast exo batch multi-chain index 1)"
        );
    }

    function _computeMultichainTypehashes(string memory witnessTypestring)
        internal
        pure
        returns (bytes32 elementTypehash, bytes32 multichainCompactTypehash)
    {
        string memory fullMultichainString = string(
            abi.encodePacked(
                "MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)",
                "Element(address arbiter,uint256 chainId,uint256[2][] idsAndAmounts,Mandate mandate)",
                "Mandate(",
                witnessTypestring,
                ")"
            )
        );

        string memory fullElementString = string(
            abi.encodePacked(
                "Element(address arbiter,uint256 chainId,uint256[2][] idsAndAmounts,Mandate mandate)",
                "Mandate(",
                witnessTypestring,
                ")"
            )
        );

        multichainCompactTypehash = keccak256(bytes(fullMultichainString));
        elementTypehash = keccak256(bytes(fullElementString));
    }

    function _computeElementHash(
        bytes32 elementTypehash,
        address arbiter,
        uint256 chainId,
        uint256 idsAndAmountsHashUint,
        bytes32 witness
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(elementTypehash, arbiter, chainId, idsAndAmountsHashUint, witness));
    }

    function _computeNonExoElementsHash(bytes32 thisChainElementHash, bytes32[] memory additionalChains)
        internal
        pure
        returns (bytes32)
    {
        bytes memory packed = abi.encodePacked(thisChainElementHash);
        for (uint256 i = 0; i < additionalChains.length; ++i) {
            packed = bytes.concat(packed, additionalChains[i]);
        }
        return keccak256(packed);
    }

    function _computeExoElementsHash(bytes32 elementHash, bytes32[] memory additionalChains, uint256 chainIndex)
        internal
        pure
        returns (bytes32)
    {
        // Create a new array that is exactly one element longer.
        bytes32[] memory allElements = new bytes32[](additionalChains.length + 1);

        // The element hash will be inserted in the new array at an index one
        // element further the provided chainIndex (since 0 means it's the first
        // *subsequent* additional chain after the notarized chain).
        uint256 currentElementIndexInAllElementsArray = chainIndex + 1;

        // Copy over each element to the new array up until we reach the element
        // hash's insertion point. There should always be at least one element
        // to copy over here (that for the notarized chain ID).
        for (uint256 i = 0; i < currentElementIndexInAllElementsArray; ++i) {
            allElements[i] = additionalChains[i];
        }

        // Insert the new element hash at the derived insertion point.
        allElements[currentElementIndexInAllElementsArray] = elementHash;

        // Copy over each element after the inserted element hash, if any.
        for (uint256 i = currentElementIndexInAllElementsArray; i < additionalChains.length; ++i) {
            allElements[i + 1] = additionalChains[i];
        }

        // Pack and hash the array with the inserted element hash.
        return keccak256(abi.encodePacked(allElements));
    }
}
