// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITheCompact } from "../../src/interfaces/ITheCompact.sol";
import { Setup } from "./Setup.sol";
import {
    CreateClaimHashWithWitnessArgs,
    CreateBatchClaimHashWithWitnessArgs,
    CreateMultichainClaimHashWithWitnessArgs
} from "./TestHelperStructs.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { Lock, Element } from "../../src/types/EIP712Types.sol";
import { IdLib } from "../../src/lib/IdLib.sol";

// Add imports for EIP-1271 support
import { MockERC1271Wallet } from "../../lib/solady/test/utils/mocks/MockERC1271Wallet.sol";
import { AlwaysOkayERC1271 } from "../../src/test/AlwaysOkayERC1271.sol";

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
            compactWithWitnessTypehash,
            arbiter,
            swapper,
            nonce,
            expires,
            lockTag,
            address(0),
            amount,
            witness,
            sponsorSignature
        );
        vm.snapshotGasLastCall("registerFor");

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        bool isRegistered = theCompact.isRegistered(swapper, claimHash, compactWithWitnessTypehash);
        assertTrue(isRegistered);
    }

    function test_registerFor_noWitness() public {
        // Create claim hash
        CreateClaimHashWithWitnessArgs memory args = CreateClaimHashWithWitnessArgs({
            typehash: compactTypehash,
            arbiter: arbiter,
            sponsor: swapper,
            nonce: nonce,
            expires: expires,
            id: id,
            amount: amount,
            witness: ""
        });
        bytes32 claimHash = _createClaimHash(args);

        // Create digest and get sponsor signature
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
        bytes memory sponsorSignature = abi.encodePacked(r, vs);

        // Call registerFor
        bytes32 returnedClaimHash = theCompact.registerFor(
            compactTypehash, arbiter, swapper, nonce, expires, lockTag, address(0), amount, "", sponsorSignature
        );
        vm.snapshotGasLastCall("registerForNoWitness");

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        bool isRegistered = theCompact.isRegistered(swapper, claimHash, compactTypehash);
        assertTrue(isRegistered);
    }

    function test_registerBatchFor() public {
        // Create multiple deposits
        uint256 id2 = _makeDeposit(swapper, address(token), amount, lockTag);

        // Create idsAndAmounts array
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0] = [id, amount];
        idsAndAmounts[1] = [id2, amount];

        bytes32 idsAndAmountsHash = _hashOfHashes(idsAndAmounts);

        CreateBatchClaimHashWithWitnessArgs memory args = CreateBatchClaimHashWithWitnessArgs({
            typehash: batchCompactWithWitnessTypehash,
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
            batchCompactWithWitnessTypehash,
            arbiter,
            swapper,
            nonce,
            expires,
            idsAndAmountsHash,
            witness,
            sponsorSignature
        );
        vm.snapshotGasLastCall("registerBatchFor");

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        bool isRegistered = theCompact.isRegistered(swapper, claimHash, batchCompactWithWitnessTypehash);
        assertTrue(isRegistered);
    }

    function test_registerBatchFor_noWitness() public {
        // Create multiple deposits
        uint256 id2 = _makeDeposit(swapper, address(token), amount, lockTag);

        // Create idsAndAmounts array
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0] = [id, amount];
        idsAndAmounts[1] = [id2, amount];

        // Create batch claim hash
        bytes32 idsAndAmountsHash = _hashOfHashes(idsAndAmounts);

        CreateBatchClaimHashWithWitnessArgs memory args = CreateBatchClaimHashWithWitnessArgs({
            typehash: batchCompactTypehash,
            arbiter: arbiter,
            sponsor: swapper,
            nonce: nonce,
            expires: expires,
            idsAndAmountsHash: idsAndAmountsHash,
            witness: ""
        });
        bytes32 claimHash = _createBatchClaimHash(args);

        // Create digest and get sponsor signature
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
        bytes memory sponsorSignature = abi.encodePacked(r, vs);

        // Call registerBatchFor
        bytes32 returnedClaimHash = theCompact.registerBatchFor(
            batchCompactTypehash, arbiter, swapper, nonce, expires, idsAndAmountsHash, "", sponsorSignature
        );
        vm.snapshotGasLastCall("registerBatchForNoWitness");

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        bool isRegistered = theCompact.isRegistered(swapper, claimHash, batchCompactTypehash);
        assertTrue(isRegistered);
    }

    function test_registerMultichainFor() public {
        // Setup for multichain test
        uint256 notarizedChainId = block.chainid;
        uint256 anotherChainId = 7171717;

        bytes32 elementsHash;
        bytes32 claimHash;
        bytes memory sponsorSignature;
        {
            // Create elements for multichain compact
            bytes32 elementTypehash = multichainElementsWithWitnessTypehash;

            // Create idsAndAmounts array for this chain
            uint256[2][] memory idsAndAmounts = new uint256[2][](1);
            idsAndAmounts[0] = [id, amount];
            bytes32 idsAndAmountsHash = _hashOfHashes(idsAndAmounts);

            // Create element hash for this chain
            bytes32 elementHash =
                _createMultichainElementHash(elementTypehash, arbiter, notarizedChainId, idsAndAmountsHash, witness);

            // Create element hash for another chain
            bytes32 anotherElementHash =
                _createMultichainElementHash(elementTypehash, arbiter, anotherChainId, idsAndAmountsHash, witness);

            // Create elements hash and claim hash
            bytes32[] memory elements = new bytes32[](2);
            elements[0] = elementHash;
            elements[1] = anotherElementHash;
            elementsHash = keccak256(abi.encodePacked(elements));

            // Create multichain claim hash
            claimHash =
                keccak256(abi.encode(multichainCompactWithWitnessTypehash, swapper, nonce, expires, elementsHash));

            // Create digest and get sponsor signature
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
            (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
            sponsorSignature = abi.encodePacked(r, vs);
        }

        // Call registerMultichainFor
        bytes32 returnedClaimHash = theCompact.registerMultichainFor(
            multichainCompactWithWitnessTypehash,
            swapper,
            nonce,
            expires,
            elementsHash,
            notarizedChainId,
            sponsorSignature
        );
        vm.snapshotGasLastCall("registerMultichainFor");

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        bool isRegistered = theCompact.isRegistered(swapper, claimHash, multichainCompactWithWitnessTypehash);
        assertTrue(isRegistered);
    }

    function test_registerForWithEIP1271Sponsor() public {
        // Create EIP-1271 wallet that will act as the sponsor
        (, uint256 erc1271SignerPrivateKey) = makeAddrAndKey("erc1271Signer");
        address erc1271Signer = vm.addr(erc1271SignerPrivateKey);
        MockERC1271Wallet erc1271Sponsor = new MockERC1271Wallet(erc1271Signer);

        // Give the EIP-1271 sponsor some tokens and make a deposit
        vm.deal(address(erc1271Sponsor), 2e18);
        vm.prank(address(erc1271Sponsor));
        uint256 erc1271Id = theCompact.depositNative{ value: amount }(lockTag, address(erc1271Sponsor));

        // Create claim hash and signature
        (bytes32 claimHash, bytes memory sponsorSignature) =
            _prepareRegisterForEIP1271(erc1271Sponsor, erc1271SignerPrivateKey, erc1271Id);

        // Call registerFor with EIP-1271 sponsor
        bytes32 returnedClaimHash = theCompact.registerFor(
            compactWithWitnessTypehash,
            arbiter,
            address(erc1271Sponsor),
            nonce,
            expires,
            lockTag,
            address(0),
            amount,
            witness,
            sponsorSignature
        );
        vm.snapshotGasLastCall("registerForWithEIP1271");

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        bool isRegistered = theCompact.isRegistered(address(erc1271Sponsor), claimHash, compactWithWitnessTypehash);
        assertTrue(isRegistered);
    }

    function test_registerBatchForWithEIP1271Sponsor() public {
        // Create EIP-1271 wallet that will act as the sponsor
        (, uint256 erc1271SignerPrivateKey) = makeAddrAndKey("erc1271Signer");
        address erc1271Signer = vm.addr(erc1271SignerPrivateKey);
        MockERC1271Wallet erc1271Sponsor = new MockERC1271Wallet(erc1271Signer);

        // Prepare batch data and signature in a helper
        (bytes32 claimHash, bytes memory sponsorSignature, bytes32 idsAndAmountsHash) =
            _prepareBatchRegisterForEIP1271(erc1271Sponsor, erc1271SignerPrivateKey);

        // Call registerBatchFor with EIP-1271 sponsor
        bytes32 returnedClaimHash = theCompact.registerBatchFor(
            batchCompactWithWitnessTypehash,
            arbiter,
            address(erc1271Sponsor),
            nonce,
            expires,
            idsAndAmountsHash,
            witness,
            sponsorSignature
        );
        vm.snapshotGasLastCall("registerBatchForWithEIP1271");

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        bool isRegistered = theCompact.isRegistered(address(erc1271Sponsor), claimHash, batchCompactWithWitnessTypehash);
        assertTrue(isRegistered);
    }

    function test_registerMultichainForWithEIP1271Sponsor() public {
        // Create EIP-1271 wallet that will act as the sponsor
        (, uint256 erc1271SignerPrivateKey) = makeAddrAndKey("erc1271Signer");
        address erc1271Signer = vm.addr(erc1271SignerPrivateKey);
        MockERC1271Wallet erc1271Sponsor = new MockERC1271Wallet(erc1271Signer);

        // Give the EIP-1271 sponsor some tokens and make a deposit
        vm.deal(address(erc1271Sponsor), 2e18);
        vm.prank(address(erc1271Sponsor));
        uint256 erc1271Id = theCompact.depositNative{ value: amount }(lockTag, address(erc1271Sponsor));

        // Prepare multichain data and signature
        (bytes32 claimHash, bytes memory sponsorSignature, bytes32 elementsHash) =
            _prepareMultichainRegisterForEIP1271(erc1271Sponsor, erc1271SignerPrivateKey, erc1271Id);

        // Call registerMultichainFor with EIP-1271 sponsor
        bytes32 returnedClaimHash = theCompact.registerMultichainFor(
            multichainCompactWithWitnessTypehash,
            address(erc1271Sponsor),
            nonce,
            expires,
            elementsHash,
            block.chainid,
            sponsorSignature
        );
        vm.snapshotGasLastCall("registerMultichainForWithEIP1271");

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        bool isRegistered =
            theCompact.isRegistered(address(erc1271Sponsor), claimHash, multichainCompactWithWitnessTypehash);
        assertTrue(isRegistered);
    }

    function test_registerMultichainFor_noWitness() public {
        // Setup for multichain test
        uint256 notarizedChainId = block.chainid;
        uint256 anotherChainId = 7171717;
        bytes32 multichainTypehash = multichainCompactTypehash;

        bytes32 elementsHash;
        bytes32 claimHash;
        bytes memory sponsorSignature;
        {
            // Create elements for multichain compact
            bytes32 elementTypehash = multichainElementsTypehash;

            // Create idsAndAmounts array for this chain
            uint256[2][] memory idsAndAmounts = new uint256[2][](1);
            idsAndAmounts[0] = [id, amount];
            bytes32 idsAndAmountsHash = _hashOfHashes(idsAndAmounts);

            // Create element hash for this chain
            bytes32 elementHash =
                _createMultichainElementHash(elementTypehash, arbiter, notarizedChainId, idsAndAmountsHash, "");

            // Create element hash for another chain
            bytes32 anotherElementHash =
                _createMultichainElementHash(elementTypehash, arbiter, anotherChainId, idsAndAmountsHash, "");

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
        vm.snapshotGasLastCall("registerMultichainForNoWitness");

        // Verify the claim hash
        assertEq(returnedClaimHash, claimHash);

        // Verify registration status
        bool isRegistered = theCompact.isRegistered(swapper, claimHash, multichainTypehash);
        assertTrue(isRegistered);
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
            compactWithWitnessTypehash,
            arbiter,
            swapper,
            nonce,
            expires,
            lockTag,
            address(0),
            amount,
            witness,
            invalidSignature
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
        bytes32 idsAndAmountsHash = _hashOfHashes(idsAndAmounts);

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
        bytes32 claimHash =
            keccak256(abi.encode(multichainCompactWithWitnessTypehash, swapper, nonce, expires, elementsHash));

        // Create digest and get invalid signature (from a different account)
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        uint256 invalidPrivateKey = uint256(keccak256("invalid"));
        (bytes32 r, bytes32 vs) = vm.signCompact(invalidPrivateKey, digest);
        bytes memory invalidSignature = abi.encodePacked(r, vs);

        // Expect revert when calling registerMultichainFor with invalid signature
        vm.expectRevert(ITheCompact.InvalidSignature.selector);
        theCompact.registerMultichainFor(
            multichainCompactWithWitnessTypehash,
            swapper,
            nonce,
            expires,
            elementsHash,
            notarizedChainId,
            invalidSignature
        );
    }

    function _prepareRegisterForEIP1271(
        MockERC1271Wallet erc1271Sponsor,
        uint256 erc1271SignerPrivateKey,
        uint256 erc1271Id
    ) private view returns (bytes32 claimHash, bytes memory sponsorSignature) {
        // Create claim hash for EIP-1271 sponsor
        CreateClaimHashWithWitnessArgs memory args = CreateClaimHashWithWitnessArgs({
            typehash: compactWithWitnessTypehash,
            arbiter: arbiter,
            sponsor: address(erc1271Sponsor),
            nonce: nonce,
            expires: expires,
            id: erc1271Id,
            amount: amount,
            witness: witness
        });
        claimHash = _createClaimHashWithWitness(args);

        // Create digest and get EIP-1271 sponsor signature
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        (bytes32 r, bytes32 vs) = vm.signCompact(erc1271SignerPrivateKey, digest);
        sponsorSignature = abi.encodePacked(r, vs);
    }

    function _prepareBatchRegisterForEIP1271(MockERC1271Wallet erc1271Sponsor, uint256 erc1271SignerPrivateKey)
        private
        returns (bytes32 claimHash, bytes memory sponsorSignature, bytes32 idsAndAmountsHash)
    {
        // Give the EIP-1271 sponsor some tokens and make deposits
        vm.deal(address(erc1271Sponsor), 2e18);
        token.mint(address(erc1271Sponsor), amount);
        vm.startPrank(address(erc1271Sponsor));
        uint256 erc1271Id1 = theCompact.depositNative{ value: amount }(lockTag, address(erc1271Sponsor));
        token.approve(address(theCompact), amount);
        uint256 erc1271Id2 = theCompact.depositERC20(address(token), lockTag, amount, address(erc1271Sponsor));
        vm.stopPrank();

        // Create idsAndAmounts array
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0] = [erc1271Id1, amount];
        idsAndAmounts[1] = [erc1271Id2, amount];
        idsAndAmountsHash = _hashOfHashes(idsAndAmounts);

        // Create batch claim hash
        CreateBatchClaimHashWithWitnessArgs memory args = CreateBatchClaimHashWithWitnessArgs({
            typehash: batchCompactWithWitnessTypehash,
            arbiter: arbiter,
            sponsor: address(erc1271Sponsor),
            nonce: nonce,
            expires: expires,
            idsAndAmountsHash: idsAndAmountsHash,
            witness: witness
        });
        claimHash = _createBatchClaimHashWithWitness(args);

        // Create digest and get EIP-1271 sponsor signature
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        (bytes32 r, bytes32 vs) = vm.signCompact(erc1271SignerPrivateKey, digest);
        sponsorSignature = abi.encodePacked(r, vs);
    }

    function _prepareMultichainRegisterForEIP1271(
        MockERC1271Wallet erc1271Sponsor,
        uint256 erc1271SignerPrivateKey,
        uint256 erc1271Id
    ) private view returns (bytes32 claimHash, bytes memory sponsorSignature, bytes32 elementsHash) {
        uint256 notarizedChainId = block.chainid;
        uint256 anotherChainId = 7171717;

        // Create Lock array for the commitment
        Lock[] memory commitments = new Lock[](1);
        commitments[0] =
            Lock({ lockTag: bytes12(bytes32(erc1271Id)), token: address(uint160(erc1271Id)), amount: amount });

        // Create Element array
        Element[] memory elements = new Element[](2);
        elements[0] = Element({ arbiter: arbiter, chainId: notarizedChainId, commitments: commitments });
        elements[1] = Element({ arbiter: arbiter, chainId: anotherChainId, commitments: commitments });

        // Create witness hashes array
        bytes32[] memory witnessHashes = new bytes32[](2);
        witnessHashes[0] = witness;
        witnessHashes[1] = witness;

        // Use existing helper to create elements hash
        elementsHash = _createMultichainElementsHash(multichainElementsWithWitnessTypehash, elements, witnessHashes);

        // Create multichain claim hash
        claimHash = _createMultichainClaimHashWithWitness(
            CreateMultichainClaimHashWithWitnessArgs({
                typehash: multichainCompactWithWitnessTypehash,
                sponsor: address(erc1271Sponsor),
                nonce: nonce,
                expires: expires,
                elementsHash: elementsHash
            })
        );

        // Create digest and get EIP-1271 sponsor signature
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        (bytes32 r, bytes32 vs) = vm.signCompact(erc1271SignerPrivateKey, digest);
        sponsorSignature = abi.encodePacked(r, vs);
    }
}
