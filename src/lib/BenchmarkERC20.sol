// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ERC20 } from "solady/tokens/ERC20.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";

/**
 * @title BenchmarkERC20
 * @notice Contract implementing a simple ERC20 token used for benchmarking purposes.
 * The deployer receives the maximum possible token supply and has exclusive rights
 * to burn tokens from any address.
 */
contract BenchmarkERC20 is ERC20 {
    using EfficiencyLib for bool;

    address private immutable deployer;

    /**
     * @notice Error thrown when a non-deployer address attempts to burn tokens or
     * when the target for the token burn is the deployer address.
     */
    error InvalidBurn();

    /**
     * @notice Returns the name of the token.
     * @return The name of the token as a string.
     */
    function name() public view virtual override returns (string memory) {
        return "Benchmark ERC20";
    }

    /**
     * @notice Returns the symbol of the token.
     * @return The symbol of the token as a string.
     */
    function symbol() public view virtual override returns (string memory) {
        return "BENCHMARK_ERC20";
    }

    /**
     * @notice Constructor that sets the deployer address and mints the maximum
     * possible token supply to the deployer.
     */
    constructor() {
        deployer = msg.sender;

        _mint(deployer, type(uint256).max);
    }

    /**
     * @notice Burns all tokens from a target address. Can only be called by the deployer.
     * @param target The address from which to burn all tokens.
     */
    function burn(address target) external {
        if ((msg.sender != deployer).or(target == deployer)) {
            revert InvalidBurn();
        }

        _burn(target, balanceOf(target));
    }
}
