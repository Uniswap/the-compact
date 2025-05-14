// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test, console, stdError } from "forge-std/Test.sol";
import { HashLib } from "src/lib/HashLib.sol";
import { IdLib } from "src/lib/IdLib.sol";
import { EfficiencyLib } from "src/lib/EfficiencyLib.sol";
import { Scope } from "src/types/Scope.sol";
import { ResetPeriod } from "src/types/ResetPeriod.sol";
import { AllocatedTransfer } from "src/types/Claims.sol";
import { AllocatedBatchTransfer } from "src/types/BatchClaims.sol";
import { Component, ComponentsById, BatchClaimComponent } from "src/types/Components.sol";
import { COMPACT_TYPEHASH, BATCH_COMPACT_TYPEHASH } from "src/types/EIP712Types.sol";

contract HashLibTest is Test {
    using HashLib for *;
    using EfficiencyLib for *;
    using IdLib for address;

    HashLibTester internal tester;

    address sponsor;
    address claimant1;
    address claimant2;
    address token1;
    address token2;

    uint256 nonce;
    uint256 expiration;

    uint96 allocatorId = IdLib.usingAllocatorId(address(0xdeadbeef));
    bytes12 lockTag = IdLib.toLockTag(allocatorId, Scope.Multichain, ResetPeriod.OneDay);

    function setUp() public {
        tester = new HashLibTester();
        sponsor = makeAddr("Sponsor");
        claimant1 = makeAddr("Claimant1");
        claimant2 = makeAddr("Claimant2");
        token1 = makeAddr("Token1");
        token2 = makeAddr("Token2");
        nonce = vm.randomUint();
        expiration = uint256(uint64(vm.randomUint()));
    }

    function _makeClaimant(address _recipient) internal view returns (uint256) {
        return abi.decode(abi.encodePacked(lockTag, _recipient), (uint256));
    }

    function testToTransferMessageHash_SingleRecipient() public {
        uint256 id = vm.randomUint();
        uint256 amount = vm.randomUint();
        Component[] memory recipients = new Component[](1);
        uint256 claimant1_val = _makeClaimant(claimant1);
        recipients[0] = Component({ claimant: claimant1_val, amount: amount });

        AllocatedTransfer memory transfer = AllocatedTransfer({
            allocatorData: bytes(""),
            nonce: nonce,
            expires: expiration,
            id: id,
            recipients: recipients
        });

        bytes32 expectedHash = keccak256(
            abi.encode(COMPACT_TYPEHASH, sponsor, sponsor, transfer.nonce, transfer.expires, transfer.id, amount)
        );

        vm.prank(sponsor);
        bytes32 actualHash = tester.callToTransferMessageHash(transfer);
        assertEq(actualHash, expectedHash, "Transfer single recipient hash mismatch");
    }

    function test_toTransferMessageHash_MultipleRecipients() public {
        uint256 id = 9876;
        uint256 amount1 = 1000;
        uint256 amount2 = 500;
        uint256 totalAmount = amount1 + amount2;
        Component[] memory recipients = new Component[](2);
        uint256 claimant1_val = _makeClaimant(claimant1);
        uint256 claimant2_val = _makeClaimant(claimant2);
        recipients[0] = Component({ claimant: claimant1_val, amount: amount1 });
        recipients[1] = Component({ claimant: claimant2_val, amount: amount2 });

        AllocatedTransfer memory transfer = AllocatedTransfer({
            allocatorData: bytes(""),
            nonce: nonce,
            expires: expiration,
            id: id,
            recipients: recipients
        });

        vm.prank(sponsor);
        bytes32 actualHash = tester.callToTransferMessageHash(transfer);

        bytes32 expectedHash = keccak256(
            abi.encode(COMPACT_TYPEHASH, sponsor, sponsor, transfer.nonce, transfer.expires, transfer.id, totalAmount)
        );

        assertEq(actualHash, expectedHash, "Transfer multiple recipients hash mismatch");
    }

    function test_toTransferMessageHash_RevertOverflow() public {
        uint256 id = 111;
        Component[] memory recipients = new Component[](2);
        uint256 claimant1_val = _makeClaimant(claimant1);
        uint256 claimant2_val = _makeClaimant(claimant2);
        recipients[0] = Component({ claimant: claimant1_val, amount: type(uint256).max });
        recipients[1] = Component({ claimant: claimant2_val, amount: 1 });

        AllocatedTransfer memory transfer = AllocatedTransfer({
            allocatorData: bytes(""),
            nonce: nonce,
            expires: expiration,
            id: id,
            recipients: recipients
        });

        vm.expectRevert(stdError.arithmeticError);
        tester.callToTransferMessageHash(transfer);
    }

    function test_toBatchTransferMessageHash() public {
        Component[] memory portions1 = new Component[](2);
        portions1[0] = Component({ claimant: _makeClaimant(claimant1), amount: 100 });
        portions1[1] = Component({ claimant: _makeClaimant(claimant2), amount: 200 });
        ComponentsById memory transfer1 = ComponentsById({ id: vm.randomUint(), portions: portions1 });

        Component[] memory portions2 = new Component[](1);
        portions2[0] = Component({ claimant: _makeClaimant(claimant1), amount: 300 });
        ComponentsById memory transfer2 = ComponentsById({ id: 22222, portions: portions2 });

        ComponentsById[] memory transfers = new ComponentsById[](2);
        transfers[0] = transfer1;
        transfers[1] = transfer2;

        AllocatedBatchTransfer memory batchTransfer = AllocatedBatchTransfer({
            allocatorData: bytes(""),
            nonce: nonce,
            expires: expiration,
            transfers: transfers
        });

        bytes32 expectedHash = _calculateBatchTransferMessageHash(batchTransfer);

        vm.prank(sponsor);
        bytes32 actualHash = tester.callToBatchTransferMessageHash(batchTransfer);
        assertEq(actualHash, expectedHash, "BatchTransfer hash mismatch");
    }

    function test_toBatchTransferMessageHash_RevertOverflow() public {
        // ID 1 setup (will cause overflow)
        uint256 id1 = vm.randomUint();
        Component[] memory portions1 = new Component[](2);
        uint256 claimant1_val = _makeClaimant(claimant1);
        uint256 claimant2_val = _makeClaimant(claimant2);
        portions1[0] = Component({ claimant: claimant1_val, amount: type(uint256).max });
        portions1[1] = Component({ claimant: claimant2_val, amount: 1 });
        ComponentsById memory transfer1 = ComponentsById({ id: id1, portions: portions1 });

        // ID 2 setup (normal)
        uint256 id2 = vm.randomUint();
        uint256 amount2_1 = 300;
        Component[] memory portions2 = new Component[](1);
        portions2[0] = Component({ claimant: claimant1_val, amount: amount2_1 });
        ComponentsById memory transfer2 = ComponentsById({ id: id2, portions: portions2 });

        // Batch setup
        ComponentsById[] memory transfers = new ComponentsById[](2);
        transfers[0] = transfer1;
        transfers[1] = transfer2;

        AllocatedBatchTransfer memory batchTransfer = AllocatedBatchTransfer({
            allocatorData: bytes(""),
            nonce: nonce,
            expires: expiration,
            transfers: transfers
        });

        vm.expectRevert(stdError.arithmeticError);
        tester.callToBatchTransferMessageHash(batchTransfer);
    }

    function testToFlatMessageHashWithWitness() public {
        uint256 tokenId = vm.randomUint();
        uint256 amount = vm.randomUint();
        bytes32 typehash = keccak256(bytes("SomeTypehash()"));
        bytes32 witness = keccak256(bytes("witness data"));

        bytes32 expectedHash =
            keccak256(abi.encode(typehash, address(this), sponsor, nonce, expiration, tokenId, amount, witness));

        bytes32 actualHash = tester.callToFlatMessageHashWithWitness(
            sponsor, tokenId, amount, address(this), nonce, expiration, typehash, witness
        );

        assertEq(actualHash, expectedHash, "FlatMessageWithWitness hash mismatch");
    }

    function testToFlatBatchClaimWithWitnessMessageHash() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0] = [vm.randomUint(), vm.randomUint()];
        idsAndAmounts[1] = [vm.randomUint(), vm.randomUint()];

        bytes32 typehash = keccak256(bytes("BatchTypehash()"));
        bytes32 witness = keccak256(bytes("batch witness data"));
        uint256[] memory noReplacements = new uint256[](0);

        bytes32 expectedIdsAmountsHash = tester.callToIdsAndAmountsHash(idsAndAmounts, noReplacements);
        bytes32 expectedHash =
            keccak256(abi.encode(typehash, address(this), sponsor, nonce, expiration, expectedIdsAmountsHash, witness));

        bytes32 actualHash = tester.callToFlatBatchClaimWithWitnessMessageHash(
            sponsor, idsAndAmounts, address(this), nonce, expiration, typehash, witness, noReplacements
        );

        assertEq(actualHash, expectedHash, "FlatBatchClaimWithWitness hash mismatch");
    }

    function testToFlatBatchClaimWithWitnessMessageHash_WithReplacements() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0] = [vm.randomUint(), vm.randomUint()];
        idsAndAmounts[1] = [vm.randomUint(), vm.randomUint()];

        uint256[] memory replacementAmounts = new uint256[](1);
        replacementAmounts[0] = vm.randomUint();

        bytes32 typehash = keccak256(bytes("BatchTypehashWithReplace()"));
        bytes32 witness = keccak256(bytes("batch witness data replace"));
        bytes32 expectedIdsAmountsHash = tester.callToIdsAndAmountsHash(idsAndAmounts, replacementAmounts);

        bytes32 expectedHash =
            keccak256(abi.encode(typehash, address(this), sponsor, nonce, expiration, expectedIdsAmountsHash, witness));

        bytes32 actualHash = tester.callToFlatBatchClaimWithWitnessMessageHash(
            sponsor, idsAndAmounts, address(this), nonce, expiration, typehash, witness, replacementAmounts
        );

        assertEq(actualHash, expectedHash, "FlatBatchClaimWithWitness (replace) hash mismatch");
    }

    function testToIdsAndAmountsHash_NoReplace() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](3);
        idsAndAmounts[0] = [vm.randomUint(), vm.randomUint()];
        idsAndAmounts[1] = [vm.randomUint(), vm.randomUint()];
        idsAndAmounts[2] = [vm.randomUint(), vm.randomUint()];
        uint256[] memory noReplacements = new uint256[](0);

        bytes memory encoded = abi.encodePacked(
            idsAndAmounts[0][0],
            idsAndAmounts[0][1],
            idsAndAmounts[1][0],
            idsAndAmounts[1][1],
            idsAndAmounts[2][0],
            idsAndAmounts[2][1]
        );
        bytes32 expectedHash = keccak256(encoded);

        bytes32 actualHash = tester.callToIdsAndAmountsHash(idsAndAmounts, noReplacements);
        assertEq(actualHash, expectedHash, "toIdsAndAmountsHash no replace failed");
    }

    function testToIdsAndAmountsHash_ReplaceSingle() public {
        uint256[2][] memory idsAndAmountsOriginal = new uint256[2][](3);
        idsAndAmountsOriginal[0] = [vm.randomUint(), vm.randomUint()];
        idsAndAmountsOriginal[1] = [vm.randomUint(), vm.randomUint()];
        idsAndAmountsOriginal[2] = [vm.randomUint(), vm.randomUint()];

        uint256[] memory replacements = new uint256[](1);
        replacements[0] = vm.randomUint();

        bytes32 actualHash = tester.callToIdsAndAmountsHash(idsAndAmountsOriginal, replacements);

        uint256[2][] memory idsAndAmountsExpected = new uint256[2][](3);
        for (uint256 i = 0; i < idsAndAmountsOriginal.length; i++) {
            idsAndAmountsExpected[i][0] = idsAndAmountsOriginal[i][0];
            idsAndAmountsExpected[i][1] = idsAndAmountsOriginal[i][1];
        }

        idsAndAmountsExpected[0][1] = replacements[0];

        bytes memory packedData = abi.encodePacked(
            idsAndAmountsExpected[0][0],
            idsAndAmountsExpected[0][1],
            idsAndAmountsExpected[1][0],
            idsAndAmountsExpected[1][1],
            idsAndAmountsExpected[2][0],
            idsAndAmountsExpected[2][1]
        );
        bytes32 expectedHash = keccak256(packedData);

        assertEq(actualHash, expectedHash, "toIdsAndAmountsHash replace single failed");
    }

    function testToIdsAndAmountsHash_ReplaceMultiple() public {
        uint256[2][] memory idsAndAmountsOriginal = new uint256[2][](3);
        idsAndAmountsOriginal[0] = [vm.randomUint(), vm.randomUint()];
        idsAndAmountsOriginal[1] = [vm.randomUint(), vm.randomUint()];
        idsAndAmountsOriginal[2] = [vm.randomUint(), vm.randomUint()];

        uint256[] memory replacements = new uint256[](2);
        replacements[0] = vm.randomUint();
        replacements[1] = vm.randomUint();

        bytes32 actualHash = tester.callToIdsAndAmountsHash(idsAndAmountsOriginal, replacements);

        uint256[2][] memory idsAndAmountsExpected = new uint256[2][](3);
        for (uint256 i = 0; i < idsAndAmountsOriginal.length; i++) {
            idsAndAmountsExpected[i][0] = idsAndAmountsOriginal[i][0];
            idsAndAmountsExpected[i][1] = idsAndAmountsOriginal[i][1];
        }

        idsAndAmountsExpected[0][1] = replacements[0];
        idsAndAmountsExpected[1][1] = replacements[1];

        bytes memory packedData = abi.encodePacked(
            idsAndAmountsExpected[0][0],
            idsAndAmountsExpected[0][1],
            idsAndAmountsExpected[1][0],
            idsAndAmountsExpected[1][1],
            idsAndAmountsExpected[2][0],
            idsAndAmountsExpected[2][1]
        );
        bytes32 expectedHash = keccak256(packedData);

        assertEq(actualHash, expectedHash, "toIdsAndAmountsHash replace multiple failed");
    }

    function testToIdsAndAmountsHash() public {
        uint256 id1 = vm.randomUint();
        uint256 amount1 = vm.randomUint();
        Component[] memory portions1 = new Component[](1);
        uint256 claimant1_val = _makeClaimant(claimant1);
        portions1[0] = Component({ claimant: claimant1_val, amount: amount1 });
        BatchClaimComponent memory claim1 =
            BatchClaimComponent({ id: id1, allocatedAmount: amount1, portions: portions1 });

        uint256 id2 = vm.randomUint();
        uint256 amount2 = vm.randomUint();
        Component[] memory portions2 = new Component[](1);
        uint256 claimant2_val = _makeClaimant(claimant2);
        portions2[0] = Component({ claimant: claimant2_val, amount: amount2 });
        BatchClaimComponent memory claim2 =
            BatchClaimComponent({ id: id2, allocatedAmount: amount2, portions: portions2 });

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        claims[0] = claim1;
        claims[1] = claim2;

        bytes memory encoded = abi.encode(id1, amount1, id2, amount2);
        bytes32 expectedHash = keccak256(encoded);

        uint256 actualHash = tester.callToIdsAndAmountsHash(claims);
        assertEq(bytes32(actualHash), expectedHash, "toIdsAndAmountsHash failed");
    }

    function test_toIdsAndAmountsHash_Empty() public view {
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](0);
        bytes memory encoded = abi.encode();
        bytes32 expectedHash = keccak256(encoded);

        uint256 actualHash = tester.callToIdsAndAmountsHash(claims);
        assertEq(bytes32(actualHash), expectedHash, "toIdsAndAmountsHash empty failed");
    }

    function _calculateBatchTransferMessageHash(AllocatedBatchTransfer memory transfer)
        internal
        view
        returns (bytes32 messageHash)
    {
        ComponentsById[] memory transfers = transfer.transfers;
        uint256[2][] memory idsAndAmounts = new uint256[2][](transfers.length);
        for (uint256 i = 0; i < transfers.length; ++i) {
            uint256 amount = 0;

            Component[] memory portions = transfers[i].portions;
            for (uint256 j = 0; j < portions.length; ++j) {
                amount += portions[j].amount;
            }

            idsAndAmounts[i][0] = transfers[i].id;
            idsAndAmounts[i][1] = amount;
        }

        return keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                sponsor,
                sponsor,
                transfer.nonce,
                transfer.expires,
                uint256(keccak256(abi.encodePacked(idsAndAmounts)))
            )
        );
    }

    function testFuzz_ToTransferMessageHash(uint256 _id, uint256 _amount, uint256 _nonce, uint256 _expires) public {
        // Bound the inputs to avoid overflows
        vm.assume(_amount > 0 && _amount < type(uint128).max);

        Component[] memory recipients = new Component[](1);
        uint256 claimant1_val = _makeClaimant(claimant1);
        recipients[0] = Component({ claimant: claimant1_val, amount: _amount });

        AllocatedTransfer memory transfer = AllocatedTransfer({
            allocatorData: bytes(""),
            nonce: _nonce,
            expires: _expires,
            id: _id,
            recipients: recipients
        });

        bytes32 expectedHash = keccak256(
            abi.encode(COMPACT_TYPEHASH, sponsor, sponsor, transfer.nonce, transfer.expires, transfer.id, _amount)
        );

        vm.prank(sponsor);
        bytes32 actualHash = tester.callToTransferMessageHash(transfer);

        assertEq(actualHash, expectedHash, "Transfer hash mismatch");
    }

    function testFuzz_ToTransferMessageHash_MultipleRecipients(
        uint256 _id,
        uint256 _amount1,
        uint256 _amount2,
        uint256 _nonce,
        uint256 _expires
    ) public {
        // Bound the inputs to avoid overflows
        vm.assume(_amount1 > 0 && _amount1 < type(uint128).max);
        vm.assume(_amount2 > 0 && _amount2 < type(uint128).max);

        Component[] memory recipients = new Component[](2);
        uint256 claimant1_val = _makeClaimant(claimant1);
        uint256 claimant2_val = _makeClaimant(claimant2);
        recipients[0] = Component({ claimant: claimant1_val, amount: _amount1 });
        recipients[1] = Component({ claimant: claimant2_val, amount: _amount2 });

        uint256 totalAmount = _amount1 + _amount2;
        vm.assume(totalAmount >= _amount1);

        AllocatedTransfer memory transfer = AllocatedTransfer({
            allocatorData: bytes(""),
            nonce: _nonce,
            expires: _expires,
            id: _id,
            recipients: recipients
        });

        bytes32 expectedHash = keccak256(
            abi.encode(COMPACT_TYPEHASH, sponsor, sponsor, transfer.nonce, transfer.expires, transfer.id, totalAmount)
        );

        vm.prank(sponsor);
        bytes32 actualHash = tester.callToTransferMessageHash(transfer);

        assertEq(actualHash, expectedHash, "Transfer multiple recipients hash mismatch");
    }

    function testFuzz_ToFlatMessageHashWithWitness(uint256 _tokenId, uint256 _amount, uint256 _nonce, uint256 _expires)
        public
        view
    {
        bytes32 typehash = keccak256(bytes("SomeTypehash()"));
        bytes32 witness = keccak256(bytes("witness data"));

        bytes32 expectedHash =
            keccak256(abi.encode(typehash, address(this), sponsor, _nonce, _expires, _tokenId, _amount, witness));

        bytes32 actualHash = tester.callToFlatMessageHashWithWitness(
            sponsor, _tokenId, _amount, address(this), _nonce, _expires, typehash, witness
        );

        assertEq(actualHash, expectedHash, "FlatMessageWithWitness hash mismatch");
    }

    function testFuzz_ToIdsAndAmountsHash(uint256 _id1, uint256 _amount1, uint256 _id2, uint256 _amount2) public view {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0] = [_id1, _amount1];
        idsAndAmounts[1] = [_id2, _amount2];
        uint256[] memory noReplacements = new uint256[](0);

        bytes memory encoded = abi.encodePacked(_id1, _amount1, _id2, _amount2);
        bytes32 expectedHash = keccak256(encoded);

        bytes32 actualHash = tester.callToIdsAndAmountsHash(idsAndAmounts, noReplacements);

        assertEq(actualHash, expectedHash, "toIdsAndAmountsHash failed");
    }

    function testFuzz_ToIdsAndAmountsHash_WithReplacement(
        uint256 _id1,
        uint256 _amount1,
        uint256 _id2,
        uint256 _amount2,
        uint256 _replacementAmount
    ) public view {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0] = [_id1, _amount1];
        idsAndAmounts[1] = [_id2, _amount2];

        uint256[] memory replacements = new uint256[](1);
        replacements[0] = _replacementAmount;

        bytes memory encoded = abi.encodePacked(_id1, _replacementAmount, _id2, _amount2);
        bytes32 expectedHash = keccak256(encoded);

        bytes32 actualHash = tester.callToIdsAndAmountsHash(idsAndAmounts, replacements);

        assertEq(actualHash, expectedHash, "toIdsAndAmountsHash with replacement failed");
    }

    function testFuzz_toIdsAndAmountsHash(uint256 _id1, uint256 _amount1, uint256 _id2, uint256 _amount2) public view {
        Component[] memory portions1 = new Component[](1);
        portions1[0] = Component({ claimant: _makeClaimant(claimant1), amount: _amount1 });
        BatchClaimComponent memory claim1 =
            BatchClaimComponent({ id: _id1, allocatedAmount: _amount1, portions: portions1 });

        Component[] memory portions2 = new Component[](1);
        portions2[0] = Component({ claimant: _makeClaimant(claimant2), amount: _amount2 });
        BatchClaimComponent memory claim2 =
            BatchClaimComponent({ id: _id2, allocatedAmount: _amount2, portions: portions2 });

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        claims[0] = claim1;
        claims[1] = claim2;

        bytes memory encoded = abi.encode(_id1, _amount1, _id2, _amount2);
        bytes32 expectedHash = keccak256(encoded);

        uint256 actualHash = tester.callToIdsAndAmountsHash(claims);
        assertEq(bytes32(actualHash), expectedHash, "toIdsAndAmountsHash failed");
    }
}

contract HashLibTester {
    using HashLib for *;

    function callToTransferMessageHash(AllocatedTransfer calldata transfer)
        external
        view
        returns (bytes32 messageHash)
    {
        return transfer.toTransferMessageHash();
    }

    function callToBatchTransferMessageHash(AllocatedBatchTransfer calldata transfer)
        external
        view
        returns (bytes32 messageHash)
    {
        return transfer.toBatchTransferMessageHash();
    }

    function callToIdsAndAmountsHash(uint256[2][] calldata idsAndAmounts, uint256[] memory replacementAmounts)
        external
        pure
        returns (bytes32 idsAndAmountsHash)
    {
        return idsAndAmounts.toIdsAndAmountsHash(replacementAmounts);
    }

    function callToIdsAndAmountsHash(BatchClaimComponent[] calldata claims)
        external
        pure
        returns (uint256 idsAndAmountsHash)
    {
        return claims.toIdsAndAmountsHash();
    }

    function callToFlatMessageHashWithWitness(
        address sponsor,
        uint256 tokenId,
        uint256 amount,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external pure returns (bytes32 messageHash) {
        return
            HashLib.toFlatMessageHashWithWitness(sponsor, tokenId, amount, arbiter, nonce, expires, typehash, witness);
    }

    function callToFlatBatchClaimWithWitnessMessageHash(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 nonce,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        uint256[] memory replacementAmounts
    ) external pure returns (bytes32 messageHash) {
        return HashLib.toFlatBatchClaimWithWitnessMessageHash(
            sponsor, idsAndAmounts, arbiter, nonce, expires, typehash, witness, replacementAmounts
        );
    }
}
