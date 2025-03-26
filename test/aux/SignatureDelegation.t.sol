import "../TheCompact.t.sol";
import { AlwaysOkDelegator } from "src/test/AlwaysOkDelegator.sol";

interface ISignatureDelegatorLogic {
    function requestSetSignDelegator() external;

    function setSignDelegator(address operator) external;
}

contract SignDelegationTest is TheCompactTest {
    AlwaysOkDelegator delegator;
    uint256 originalSwapperPrivateKey;

    function setUp() public override {
        super.setUp();
        delegator = new AlwaysOkDelegator();
        // deliberately breaking all ecdsas in TheCompactTest (allocator addr and allocatorPrivateKey wont match, so recover must fail)
        originalSwapperPrivateKey = swapperPrivateKey;
        swapperPrivateKey = 1337;

        vm.prank(swapper);
        ISignatureDelegatorLogic(address(theCompact)).requestSetSignDelegator();
        vm.warp(block.timestamp + 2 days);
        vm.prank(swapper);
        ISignatureDelegatorLogic(address(theCompact)).setSignDelegator(address(delegator));
    }

    modifier withOriginalSwapperPrivateKey() {
        swapperPrivateKey = originalSwapperPrivateKey;
        _;
    }

    function test_batchDepositAndRegisterWithWitnessViaPermit2ThenClaim() public override withOriginalSwapperPrivateKey {
        super.test_batchDepositAndRegisterWithWitnessViaPermit2ThenClaim();
    }

    function test_depositAndRegisterWithWitnessViaPermit2ThenClaim() public override withOriginalSwapperPrivateKey {
        super.test_depositAndRegisterWithWitnessViaPermit2ThenClaim();
    }

    function test_depositBatchViaPermit2NativeAndERC20() public override withOriginalSwapperPrivateKey {
        super.test_depositBatchViaPermit2NativeAndERC20();
    }

    function test_depositBatchViaPermit2SingleERC20() public override withOriginalSwapperPrivateKey {
        super.test_depositBatchViaPermit2SingleERC20();
    }

    function test_depositERC20ViaPermit2AndURI() public override withOriginalSwapperPrivateKey {
        super.test_depositERC20ViaPermit2AndURI();
    }
}
