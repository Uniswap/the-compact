// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";
import { Setup } from "./Setup.sol";
import { CreateClaimHashWithWitnessArgs, CreateBatchClaimHashWithWitnessArgs } from "./TestHelperStructs.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { IdLib } from "../../src/lib/IdLib.sol";

contract RegisterForTest is Setup {
    using IdLib for address;
    using IdLib for uint96;

    // Test parameters
    address arbiter;
    uint256 nonce;
    uint256 expires;
    uint256 id;
    uint256 amount;
    bytes32 witness;
    uint256 witnessArgument;
    uint96 allocatorId;
    bytes12 lockTag;

    function setUp() public override {
        super.setUp();

        // Setup test parameters
        arbiter = makeAddr("arbiter");
        nonce = 0;
        expires = block.timestamp + 1000;
        amount = 1e18;
        witnessArgument = 234;
        witness = _createCompactWitness(witnessArgument);

        vm.prank(allocator);
        allocatorId = theCompact.__registerAllocator(allocator, "");

        lockTag = allocatorId.toLockTag(Scope.Multichain, ResetPeriod.TenMinutes);

        // Create a deposit to get an ID
        id = _makeDeposit(swapper, amount, lockTag);
    }

    function test_registerFor() public {
        // Create claim hash
        CreateClaimHashWithWitnessArgs memory args = CreateClaimHashWithWitnessArgs({
            typehash: compactWithWitnessTypehash,
            arbiter: arbiter,
            sponsor: swapper,
            nonce: nonce,
            expires: expires,
            id: id,
            amount: amount,
            witness: witness
        });
        bytes32 claimHash = _createClaimHashWithWitness(args);

        // Create digest and get sponsor signature
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
        bytes memory sponsorSignature = abi.encodePacked(r, vs);

        // Call registerFor
        bytes32 returnedClaimHash = theCompact.registerFor(
            compactWithWitnessTypehash, arbiter, swapper, nonce, expires, id, amount, witness, sponsorSignature
        );

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        (bool isActive, uint256 registrationTimestamp) =
            theCompact.getRegistrationStatus(swapper, claimHash, compactWithWitnessTypehash);
        assertTrue(isActive);
        assertEq(registrationTimestamp, block.timestamp);
    }

    function test_registerBatchFor() public {
        // Create multiple deposits
        uint256 id2 = _makeDeposit(swapper, address(token), amount, lockTag);

        // Create idsAndAmounts array
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0] = [id, amount];
        idsAndAmounts[1] = [id2, amount];

        // Create batch claim hash
        bytes32 batchTypehash = keccak256(
            "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)"
        );
        bytes32 idsAndAmountsHash = keccak256(abi.encodePacked(idsAndAmounts));

        CreateBatchClaimHashWithWitnessArgs memory args = CreateBatchClaimHashWithWitnessArgs({
            typehash: batchTypehash,
            arbiter: arbiter,
            sponsor: swapper,
            nonce: nonce,
            expires: expires,
            idsAndAmountsHash: idsAndAmountsHash,
            witness: witness
        });
        bytes32 claimHash = _createBatchClaimHashWithWitness(args);

        // Create digest and get sponsor signature
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
        bytes memory sponsorSignature = abi.encodePacked(r, vs);

        // Call registerBatchFor
        bytes32 returnedClaimHash = theCompact.registerBatchFor(
            batchTypehash, arbiter, swapper, nonce, expires, idsAndAmountsHash, witness, sponsorSignature
        );

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        (bool isActive, uint256 registrationTimestamp) =
            theCompact.getRegistrationStatus(swapper, claimHash, batchTypehash);
        assertTrue(isActive);
        assertEq(registrationTimestamp, block.timestamp);
    }

    function test_registerMultichainFor() public {
        // Setup for multichain test
        uint256 notarizedChainId = block.chainid;
        uint256 anotherChainId = 7171717;

        bytes32 multichainTypehash = keccak256(
            "MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)Element(address arbiter,uint256 chainId,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)"
        );

        bytes32 elementsHash;
        bytes32 claimHash;
        bytes memory sponsorSignature;
        {
            // Create elements for multichain compact
            bytes32 elementTypehash = keccak256(
                "Element(address arbiter,uint256 chainId,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)"
            );

            // Create idsAndAmounts array for this chain
            uint256[2][] memory idsAndAmounts = new uint256[2][](1);
            idsAndAmounts[0] = [id, amount];
            bytes32 idsAndAmountsHash = keccak256(abi.encodePacked(idsAndAmounts));

            // Create element hash for this chain
            bytes32 elementHash =
                keccak256(abi.encode(elementTypehash, arbiter, notarizedChainId, idsAndAmountsHash, witness));

            // Create element hash for another chain
            bytes32 anotherElementHash =
                keccak256(abi.encode(elementTypehash, arbiter, anotherChainId, idsAndAmountsHash, witness));

            // Create elements hash and claim hash
            bytes32[] memory elements = new bytes32[](2);
            elements[0] = elementHash;
            elements[1] = anotherElementHash;
            elementsHash = keccak256(abi.encodePacked(elements));

            // Create multichain claim hash
            claimHash = keccak256(abi.encode(multichainTypehash, swapper, nonce, expires, elementsHash));

            // Create digest and get sponsor signature
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
            (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
            sponsorSignature = abi.encodePacked(r, vs);
        }

        // Call registerMultichainFor
        bytes32 returnedClaimHash = theCompact.registerMultichainFor(
            multichainTypehash, swapper, nonce, expires, elementsHash, notarizedChainId, sponsorSignature
        );

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        (bool isActive, uint256 registrationTimestamp) =
            theCompact.getRegistrationStatus(swapper, claimHash, multichainTypehash);
        assertTrue(isActive);
        assertEq(registrationTimestamp, block.timestamp);
    }

    function test_registerFor_invalidSignature() public {
        // Create claim hash
        CreateClaimHashWithWitnessArgs memory args = CreateClaimHashWithWitnessArgs({
            typehash: compactWithWitnessTypehash,
            arbiter: arbiter,
            sponsor: swapper,
            nonce: nonce,
            expires: expires,
            id: id,
            amount: amount,
            witness: witness
        });
        bytes32 claimHash = _createClaimHashWithWitness(args);

        // Create digest and get invalid signature (from a different account)
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        uint256 invalidPrivateKey = uint256(keccak256("invalid"));
        (bytes32 r, bytes32 vs) = vm.signCompact(invalidPrivateKey, digest);
        bytes memory invalidSignature = abi.encodePacked(r, vs);

        // Expect revert when calling registerFor with invalid signature
        vm.expectRevert(ITheCompact.InvalidSignature.selector);
        theCompact.registerFor(
            compactWithWitnessTypehash, arbiter, swapper, nonce, expires, id, amount, witness, invalidSignature
        );
    }

    function test_registerBatchFor_invalidSignature() public {
        // Create idsAndAmounts array
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0] = [id, amount];

        // Create batch claim hash
        bytes32 batchTypehash = keccak256(
            "BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)"
        );
        bytes32 idsAndAmountsHash = keccak256(abi.encodePacked(idsAndAmounts));

        CreateBatchClaimHashWithWitnessArgs memory args = CreateBatchClaimHashWithWitnessArgs({
            typehash: batchTypehash,
            arbiter: arbiter,
            sponsor: swapper,
            nonce: nonce,
            expires: expires,
            idsAndAmountsHash: idsAndAmountsHash,
            witness: witness
        });
        bytes32 claimHash = _createBatchClaimHashWithWitness(args);

        // Create digest and get invalid signature (from a different account)
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        uint256 invalidPrivateKey = uint256(keccak256("invalid"));
        (bytes32 r, bytes32 vs) = vm.signCompact(invalidPrivateKey, digest);
        bytes memory invalidSignature = abi.encodePacked(r, vs);

        // Expect revert when calling registerBatchFor with invalid signature
        vm.expectRevert(ITheCompact.InvalidSignature.selector);
        theCompact.registerBatchFor(
            batchTypehash, arbiter, swapper, nonce, expires, idsAndAmountsHash, witness, invalidSignature
        );
    }

    function test_registerMultichainFor_invalidSignature() public {
        // Setup for multichain test
        uint256 notarizedChainId = block.chainid;
        bytes32 elementsHash = keccak256("elements");

        // Create multichain claim hash
        bytes32 multichainTypehash = keccak256(
            "MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)Element(address arbiter,uint256 chainId,uint256[2][] idsAndAmounts,Mandate mandate)Mandate(uint256 witnessArgument)"
        );
        bytes32 claimHash = keccak256(abi.encode(multichainTypehash, swapper, nonce, expires, elementsHash));

        // Create digest and get invalid signature (from a different account)
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        uint256 invalidPrivateKey = uint256(keccak256("invalid"));
        (bytes32 r, bytes32 vs) = vm.signCompact(invalidPrivateKey, digest);
        bytes memory invalidSignature = abi.encodePacked(r, vs);

        // Expect revert when calling registerMultichainFor with invalid signature
        vm.expectRevert(ITheCompact.InvalidSignature.selector);
        theCompact.registerMultichainFor(
            multichainTypehash, swapper, nonce, expires, elementsHash, notarizedChainId, invalidSignature
        );
    }
}
