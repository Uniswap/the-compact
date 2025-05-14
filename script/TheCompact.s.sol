// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Script, console } from "forge-std/Script.sol";
import { TheCompact } from "../src/TheCompact.sol";

interface ImmutableCreate2Factory {
    function safeCreate2(bytes32 salt, bytes calldata initializationCode)
        external
        payable
        returns (address deploymentAddress);
}

contract TheCompactScript is Script {
    TheCompact public theCompact;

    function setUp() public { }

    function run() public {
        vm.startBroadcast();

        // ensure permit2 is deployed
        assert(address(0x000000000022D473030F116dDEE9F6B43aC78BA3).code.length > 0);

        // to deploy using create2 (need to rederive salt and target address when changing code):
        bytes32 salt = bytes32(0x00000000000000000000000000000000000000008a0f466a78cd1102ce3d82f7);
        address targetAddress = address(0x00000000000018DF021Ff2467dF97ff846E09f48);
        // ensure create2 deployer is deployed
        address immutableCreate2Factory = address(0x0000000000FFe8B47B3e2130213B802212439497);
        assert(immutableCreate2Factory.code.length > 0);
        // deploy it and check the target address
        theCompact = TheCompact(
            ImmutableCreate2Factory(immutableCreate2Factory).safeCreate2(salt, type(TheCompact).creationCode)
        );
        assert(address(theCompact) == targetAddress);

        // // to just deploy it directly:
        // theCompact = new TheCompact();

        assert(keccak256(bytes(theCompact.name())) == keccak256(bytes("The Compact")));

        vm.stopBroadcast();
    }
}
