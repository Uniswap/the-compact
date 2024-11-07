// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";
import { Ownable } from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import { ServerAllocator } from "src/examples/allocator/ServerAllocator.sol";
import { IServerAllocator } from "src/interfaces/IServerAllocator.sol";
import { Compact, COMPACT_TYPEHASH } from "src/types/EIP712Types.sol";
import { TheCompactMock } from "src/test/TheCompactMock.sol";
import { ERC20Mock } from "src/test/ERC20Mock.sol";
import { console } from "forge-std/console.sol";
import { IERC1271 } from "lib/permit2/src/interfaces/IERC1271.sol";

abstract contract MocksSetup is Test {
    address owner = makeAddr("owner");
    address signer;
    uint256 signerPK;
    address attacker;
    uint256 attackerPK;
    ERC20Mock usdc;
    TheCompactMock compactContract;
    ServerAllocator serverAllocator;
    uint256 usdcId;

    function setUp() public virtual {
        usdc = new ERC20Mock("USDC", "USDC");
        compactContract = new TheCompactMock();
        serverAllocator = new ServerAllocator(owner, address(compactContract));
        usdcId = compactContract.getTokenId(address(usdc), address(serverAllocator));
        (signer, signerPK) = makeAddrAndKey("signer");
        (attacker, attackerPK) = makeAddrAndKey("attacker");
    }
}

abstract contract AttestSetup {
    bytes4 internal constant _ATTEST_SELECTOR = 0x1a808f91;

    function createAttest(address from_, uint256 id_, uint256 amount_) internal pure returns (bytes32) {
        return keccak256(abi.encode(from_, id_, amount_));
    }
}

abstract contract CreateHash is Test {
    struct Allocator {
        bytes32 hash;
    }

    // stringified types
    string EIP712_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"; // Hashed inside the funcion
    // string ALLOCATOR_TYPE = "Allocator(bytes32 hash)"; // Hashed inside the funcion
    string REGISTER_ATTEST_TYPE = "RegisterAttest(address signer,bytes32 attestHash,uint256 expiration,uint256 nonce)"; // Hashed inside the funcion
    string NONCE_CONSUMPTION_TYPE = "NonceConsumption(address signer,uint256[] nonces,bytes32[] attests)"; // Hashed inside the funcion
    // EIP712 domain type
    string name = "Allocator";
    string version = "1";

    // function _hashAllocator(Allocator memory data, address verifyingContract) internal view returns (bytes32) {
    //     // hash typed data
    //     return keccak256(
    //         abi.encodePacked(
    //             "\x19\x01", // backslash is needed to escape the character
    //             _domainSeperator(verifyingContract),
    //             keccak256(abi.encode(keccak256(bytes(ALLOCATOR_TYPE)), data.hash))
    //         )
    //     );
    // }

    function _hashCompact(Compact memory data, address verifyingContract) internal view returns (bytes32) {
        // hash typed data
        return keccak256(
            abi.encodePacked(
                "\x19\x01", // backslash is needed to escape the character
                _domainSeperator(verifyingContract),
                keccak256(abi.encode(COMPACT_TYPEHASH, data.arbiter, data.sponsor, data.nonce, data.expires, data.id, data.amount))
            )
        );
    }

    function _hashRegisterAttest(ServerAllocator.RegisterAttest memory data, address verifyingContract) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01", // backslash is needed to escape the character
                _domainSeperator(verifyingContract),
                keccak256(abi.encode(keccak256(bytes(REGISTER_ATTEST_TYPE)), data.signer, data.attestHash, data.expiration, data.nonce))
            )
        );
    }

    function _hashNonceConsumption(ServerAllocator.NonceConsumption memory data, address verifyingContract) internal view returns (bytes32) {
        // hash typed data
        return keccak256(
            abi.encodePacked(
                "\x19\x01", // backslash is needed to escape the character
                _domainSeperator(verifyingContract),
                keccak256(abi.encode(keccak256(bytes(NONCE_CONSUMPTION_TYPE)), data.signer, data.nonces, data.attests))
            )
        );
    }

    function _domainSeperator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes(EIP712_DOMAIN_TYPE)), keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, verifyingContract));
    }

    function _signMessage(bytes32 hash_, uint256 signerPK_) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPK_, hash_);
        return abi.encodePacked(r, s, v);
    }
}

abstract contract SignerSet is MocksSetup, CreateHash, AttestSetup {
    function setUp() public virtual override {
        super.setUp();
        vm.prank(owner);
        serverAllocator.addSigner(signer);
    }
}

contract ServerAllocator_OwnerSet is MocksSetup, CreateHash {
    function test_checkOwner() public view {
        assertEq(serverAllocator.owner(), owner);
    }
}

contract ServerAllocator_ManageSigners is MocksSetup, CreateHash {
    function test_noSigners() public view {
        assertEq(serverAllocator.getAllSigners().length, 0);
    }

    function test_fuzz_onlyOwnerCanAddSigner(address attacker_) public {
        vm.assume(attacker_ != owner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker_));
        vm.prank(attacker_);
        serverAllocator.addSigner(signer);
    }

    function test_addSigner() public {
        vm.prank(owner);
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.SignerAdded(signer);
        serverAllocator.addSigner(signer);
        assertEq(serverAllocator.getAllSigners().length, 1);
        assertEq(serverAllocator.getAllSigners()[0], signer);
    }

    function test_addAnotherSigner() public {
        vm.startPrank(owner);
        // add first signer
        serverAllocator.addSigner(signer);

        // add second signer
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.SignerAdded(attacker);
        serverAllocator.addSigner(attacker);
        assertEq(serverAllocator.getAllSigners().length, 2);
        assertEq(serverAllocator.getAllSigners()[0], signer);
        assertEq(serverAllocator.getAllSigners()[1], attacker);
    }

    function test_removeSigner() public {
        vm.startPrank(owner);
        // add first signer
        serverAllocator.addSigner(signer);
        assertEq(serverAllocator.getAllSigners().length, 1);

        // remove first signer
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.SignerRemoved(signer);
        serverAllocator.removeSigner(signer);
        assertEq(serverAllocator.getAllSigners().length, 0);
    }

    function test_signerCantAddOrRemoveSigners() public {
        vm.prank(owner);

        // add first signer
        serverAllocator.addSigner(signer);

        vm.startPrank(signer);
        // try to add another signer
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, signer));
        serverAllocator.addSigner(attacker);

        // try to remove a signer
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, signer));
        serverAllocator.removeSigner(signer);
    }

    function test_addingSignerTwice() public {
        vm.startPrank(owner);
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.SignerAdded(signer);
        serverAllocator.addSigner(signer);
        assertEq(serverAllocator.getAllSigners().length, 1);

        // adding signer again will just return without adding the signer again
        serverAllocator.addSigner(signer);
        assertEq(serverAllocator.getAllSigners().length, 1);
    }
}

contract ServerAllocator_Attest is SignerSet {
    function test_fuzz_RegisterAttest_onlySigner(address attacker_) public {
        vm.assume(attacker_ != signer);

        vm.prank(attacker_);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.InvalidSigner.selector, attacker_));
        serverAllocator.registerAttest(createAttest(attacker_, usdcId, 100), vm.getBlockTimestamp() + 1 days);
    }

    function test_fuzz_registerAttest_attestExpired(uint256 expiration_) public {
        vm.assume(expiration_ < vm.getBlockTimestamp());

        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.Expired.selector, expiration_, vm.getBlockTimestamp()));
        serverAllocator.registerAttest(createAttest(signer, usdcId, 100), expiration_);
    }

    function test_registerAttest_successful() public {
        vm.prank(signer);
        bytes32 attest = createAttest(signer, usdcId, 100);
        uint256 expiration = vm.getBlockTimestamp() + 1 days;
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.AttestRegistered(attest, expiration);
        serverAllocator.registerAttest(attest, expiration);

        assertEq(serverAllocator.checkAttestExpirations(attest)[0], expiration);
    }

    function test_registerAttestViaSignature_InvalidSignature() public {
        bytes32 attest = createAttest(signer, usdcId, 100);
        uint256 expiration = vm.getBlockTimestamp() + 1 days;

        IServerAllocator.RegisterAttest memory attestData = IServerAllocator.RegisterAttest(signer, attest, expiration, 0);
        bytes32 message = _hashRegisterAttest(attestData, address(serverAllocator));
        bytes memory signature = _signMessage(message, attackerPK);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.InvalidSignature.selector, signature, attacker));
        serverAllocator.registerAttestViaSignature(attestData, signature);
    }

    function test_registerAttestViaSignature_successful() public {
        bytes32 attest = createAttest(signer, usdcId, 100);
        uint256 expiration = vm.getBlockTimestamp() + 1 days;

        IServerAllocator.RegisterAttest memory attestData = IServerAllocator.RegisterAttest(signer, attest, expiration, 0);
        bytes32 message = _hashRegisterAttest(attestData, address(serverAllocator));
        bytes memory signature = _signMessage(message, signerPK);

        vm.prank(attacker);
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.AttestRegistered(attest, expiration);
        serverAllocator.registerAttestViaSignature(attestData, signature);
    }

    function test_registerAttestViaSignature_AlreadyUsedSig() public {
        bytes32 attest = createAttest(signer, usdcId, 100);
        uint256 expiration = vm.getBlockTimestamp() + 1 days;

        IServerAllocator.RegisterAttest memory attestData = IServerAllocator.RegisterAttest(signer, attest, expiration, 0);
        bytes32 message = _hashRegisterAttest(attestData, address(serverAllocator));
        bytes memory signature = _signMessage(message, signerPK);

        vm.prank(attacker);
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.AttestRegistered(attest, expiration);
        serverAllocator.registerAttestViaSignature(attestData, signature);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.AlreadyUsedSig.selector, attest, 0));
        serverAllocator.registerAttestViaSignature(attestData, signature);
    }

    function test_registerSameAttestTwice() public {
        vm.startPrank(signer);
        bytes32 attest = createAttest(signer, usdcId, 100);
        uint256 expiration1 = vm.getBlockTimestamp() + 1 days;
        uint256 expiration2 = vm.getBlockTimestamp() + 2 days;

        // first attest
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.AttestRegistered(attest, expiration1);
        serverAllocator.registerAttest(attest, expiration1);

        assertEq(serverAllocator.checkAttestExpirations(attest)[0], expiration1);

        // second attest with different expiration
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.AttestRegistered(attest, expiration2);
        serverAllocator.registerAttest(attest, expiration2);

        assertEq(serverAllocator.checkAttestExpirations(attest)[0], expiration1);
        assertEq(serverAllocator.checkAttestExpirations(attest)[1], expiration2);
    }

    function test_fuzz_attest_callerMustBeCompact(address caller_) public {
        vm.assume(caller_ != address(compactContract));

        vm.prank(caller_);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.InvalidCaller.selector, caller_, address(compactContract)));
        serverAllocator.attest(caller_, signer, attacker, usdcId, 100);
    }

    function test_fuzz_attest_notRegistered(address operator_, address from_, address to_, uint256 id_, uint256 amount_) public {
        vm.prank(address(compactContract));
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.UnregisteredAttest.selector, keccak256(abi.encode(from_, id_, amount_))));
        serverAllocator.attest(operator_, from_, to_, id_, amount_);
    }

    function test_attest_expired() public {
        uint256 amount_ = 100;
        bytes32 attest = createAttest(attacker, usdcId, amount_);
        uint256 expiration = vm.getBlockTimestamp();

        // register attest
        vm.prank(signer);
        serverAllocator.registerAttest(attest, expiration);

        // move time forward
        vm.warp(vm.getBlockTimestamp() + 1);

        // check attest
        vm.prank(address(compactContract));
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.ExpiredAttests.selector, attest));
        serverAllocator.attest(signer, attacker, makeAddr("to"), usdcId, amount_);
    }

    function test_fuzz_attest_successful(address operator_, address from_, address to_, uint256 id_, uint256 amount_) public {
        bytes32 attest = createAttest(from_, id_, amount_);
        uint256 expiration = vm.getBlockTimestamp();

        // register attest
        vm.prank(signer);
        serverAllocator.registerAttest(attest, expiration);

        // check for attest
        assertEq(serverAllocator.checkAttestExpirations(attest)[0], expiration);

        // check attest
        vm.prank(address(compactContract));
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.Attested(from_, id_, amount_);
        bytes4 attestSelector = serverAllocator.attest(operator_, from_, to_, id_, amount_);
        assertEq(attestSelector, _ATTEST_SELECTOR);

        // check attest was consumed
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.UnregisteredAttest.selector, attest));
        serverAllocator.checkAttestExpirations(attest);
    }
}

contract ServerAllocator_Consume is SignerSet {
    function test_consume_onlySignerCanConsume() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.InvalidSigner.selector, attacker));
        serverAllocator.consume(new uint256[](0), new bytes32[](0));
    }

    function test_consume_requiresNoncesAndAttestsToBeOfSameLength() public {
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.InvalidInput.selector));
        serverAllocator.consume(new uint256[](0), new bytes32[](1));
    }

    function test_consume_successfulWithoutAttests() public {
        vm.prank(signer);

        uint256[] memory nonces = new uint256[](3);
        nonces[0] = 1;
        nonces[1] = 2;
        nonces[2] = 3;

        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.NoncesConsumed(nonces);
        serverAllocator.consume(nonces, new bytes32[](3));

        assertEq(compactContract.consumedNonces(0), false);
        for (uint256 i = 0; i < nonces.length; ++i) {
            assertEq(compactContract.consumedNonces(nonces[i]), true);
        }
    }

    function test_consume_successfulWithAttests() public {
        vm.startPrank(signer);

        uint256[] memory nonces = new uint256[](3);
        nonces[0] = 1;
        nonces[1] = 2;
        nonces[2] = 3;

        bytes32[] memory attests = new bytes32[](3);
        attests[0] = createAttest(signer, usdcId, 100);
        attests[1] = createAttest(signer, usdcId, 200);
        attests[2] = createAttest(signer, usdcId, 300);

        // register attests
        serverAllocator.registerAttest(attests[0], vm.getBlockTimestamp());
        serverAllocator.registerAttest(attests[1], vm.getBlockTimestamp());
        serverAllocator.registerAttest(attests[2], vm.getBlockTimestamp());

        assertEq(serverAllocator.checkAttestExpirations(attests[0])[0], vm.getBlockTimestamp());
        assertEq(serverAllocator.checkAttestExpirations(attests[1])[0], vm.getBlockTimestamp());
        assertEq(serverAllocator.checkAttestExpirations(attests[2])[0], vm.getBlockTimestamp());

        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.NoncesConsumed(nonces);
        serverAllocator.consume(nonces, attests);

        assertEq(compactContract.consumedNonces(0), false);
        for (uint256 i = 0; i < nonces.length; ++i) {
            assertEq(compactContract.consumedNonces(nonces[i]), true);
        }

        // check attests were consumed
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.UnregisteredAttest.selector, attests[0]));
        serverAllocator.checkAttestExpirations(attests[0]);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.UnregisteredAttest.selector, attests[1]));
        serverAllocator.checkAttestExpirations(attests[1]);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.UnregisteredAttest.selector, attests[2]));
        serverAllocator.checkAttestExpirations(attests[2]);
    }

    function test_consumeViaSignature_requiresNoncesAndAttestsToBeOfSameLength() public {
        bytes32 message = _hashNonceConsumption(IServerAllocator.NonceConsumption(signer, new uint256[](0), new bytes32[](1)), address(serverAllocator));
        bytes memory signature = _signMessage(message, signerPK);

        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.InvalidInput.selector));
        serverAllocator.consumeViaSignature(IServerAllocator.NonceConsumption(signer, new uint256[](0), new bytes32[](1)), signature);
    }

    function test_consumeViaSignature_requireValidSignature() public {
        bytes32 message = _hashNonceConsumption(IServerAllocator.NonceConsumption(signer, new uint256[](1), new bytes32[](1)), address(serverAllocator));
        bytes memory signature = _signMessage(message, attackerPK);

        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.InvalidSignature.selector, signature, attacker));
        serverAllocator.consumeViaSignature(IServerAllocator.NonceConsumption(signer, new uint256[](1), new bytes32[](1)), signature);
    }

    function test_consumeViaSignature_successfulWithoutAttests() public {
        uint256[] memory nonces = new uint256[](3);
        nonces[0] = 1;
        nonces[1] = 2;
        nonces[2] = 3;

        bytes32 message = _hashNonceConsumption(IServerAllocator.NonceConsumption(signer, nonces, new bytes32[](3)), address(serverAllocator));
        bytes memory signature = _signMessage(message, signerPK);

        vm.prank(attacker);
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.NoncesConsumed(nonces);
        serverAllocator.consumeViaSignature(IServerAllocator.NonceConsumption(signer, nonces, new bytes32[](3)), signature);
    }

    function test_consumeViaSignature_successfulWithAttests() public {
        uint256[] memory nonces = new uint256[](3);
        nonces[0] = 1;
        nonces[1] = 2;
        nonces[2] = 3;

        bytes32[] memory attests = new bytes32[](3);
        attests[0] = createAttest(signer, usdcId, 100);
        attests[1] = createAttest(signer, usdcId, 200);
        attests[2] = createAttest(signer, usdcId, 300);

        vm.startPrank(signer);
        // register attests
        serverAllocator.registerAttest(attests[0], vm.getBlockTimestamp());
        serverAllocator.registerAttest(attests[1], vm.getBlockTimestamp());
        serverAllocator.registerAttest(attests[2], vm.getBlockTimestamp());
        vm.stopPrank();

        assertEq(serverAllocator.checkAttestExpirations(attests[0])[0], vm.getBlockTimestamp());
        assertEq(serverAllocator.checkAttestExpirations(attests[1])[0], vm.getBlockTimestamp());
        assertEq(serverAllocator.checkAttestExpirations(attests[2])[0], vm.getBlockTimestamp());

        bytes32 message = _hashNonceConsumption(IServerAllocator.NonceConsumption(signer, nonces, attests), address(serverAllocator));
        bytes memory signature = _signMessage(message, signerPK);

        vm.prank(attacker);
        vm.expectEmit(address(serverAllocator));
        emit IServerAllocator.NoncesConsumed(nonces);
        serverAllocator.consumeViaSignature(IServerAllocator.NonceConsumption(signer, nonces, attests), signature);

        assertEq(compactContract.consumedNonces(0), false);
        for (uint256 i = 0; i < nonces.length; ++i) {
            assertEq(compactContract.consumedNonces(nonces[i]), true);
        }

        // check attests were consumed
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.UnregisteredAttest.selector, attests[0]));
        serverAllocator.checkAttestExpirations(attests[0]);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.UnregisteredAttest.selector, attests[1]));
        serverAllocator.checkAttestExpirations(attests[1]);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.UnregisteredAttest.selector, attests[2]));
        serverAllocator.checkAttestExpirations(attests[2]);
    }
}

contract ServerAllocator_isValidSignature is SignerSet {
    function test_isValidSignature_revertInvalidSig() public {
        bytes32 message = _hashCompact(Compact(signer, signer, 0, vm.getBlockTimestamp(), usdcId, 100), address(serverAllocator));
        bytes memory signature = _signMessage(message, attackerPK);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IServerAllocator.InvalidSignature.selector, signature, attacker));
        serverAllocator.isValidSignature(message, signature);
    }

    function test_isValidSignature_successful() public {
        bytes32 message = _hashCompact(Compact(signer, signer, 0, vm.getBlockTimestamp(), usdcId, 100), address(serverAllocator));
        bytes memory signature = _signMessage(message, signerPK);

        vm.prank(attacker);
        bytes4 magicValue = serverAllocator.isValidSignature(message, signature);
        assertEq(magicValue, IERC1271.isValidSignature.selector);
    }
}
