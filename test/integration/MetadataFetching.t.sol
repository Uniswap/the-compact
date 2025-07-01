// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TheCompact } from "../../src/TheCompact.sol";
import { MockERC20 } from "../../lib/solady/test/utils/mocks/MockERC20.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { Setup } from "./Setup.sol";
import { IdLib } from "../../src/lib/IdLib.sol";

/**
 * @title MetadataFetchingTest
 * @notice Integration tests for metadata fetching functionality
 * Tests name(id), symbol(id), and decimals(id) for:
 * - Native tokens (ETH) should return default ETH values
 * - Tokens with their own name/symbol/decimals should return those values
 * - Tokens without these methods should return default values
 */
contract MetadataFetchingTest is Setup {
    using IdLib for uint96;

    // Mock token that doesn't implement name/symbol/decimals
    MockERC20WithoutMetadata public tokenWithoutMetadata;

    // Mock token with custom name/symbol/decimals
    MockERC20 public customToken;

    function setUp() public override {
        super.setUp();

        // Deploy a token without metadata methods
        tokenWithoutMetadata = new MockERC20WithoutMetadata();

        // Deploy a token with custom metadata
        customToken = new MockERC20("Custom Token", "CSTM", 8);

        // Mint tokens to the swapper
        tokenWithoutMetadata.mint(swapper, 1e18);
        customToken.mint(swapper, 1e18);

        // Approve tokens for TheCompact
        vm.startPrank(swapper);
        tokenWithoutMetadata.approve(address(theCompact), 1e18);
        customToken.approve(address(theCompact), 1e18);
        vm.stopPrank();
    }

    function test_name_nativeToken() public {
        // Register allocator and create a deposit with native token (ETH)
        (, bytes12 lockTag) = _registerAllocator(alwaysOKAllocator);
        uint256 id = _makeDeposit(swapper, 1e18, lockTag);

        // Verify name returns the default ETH value
        string memory name = theCompact.name(id);
        assertEq(name, "Compact Native Token");
    }

    function test_symbol_nativeToken() public {
        // Register allocator and create a deposit with native token (ETH)
        (, bytes12 lockTag) = _registerAllocator(alwaysOKAllocator);
        uint256 id = _makeDeposit(swapper, 1e18, lockTag);

        // Verify symbol returns the default ETH value
        string memory symbol = theCompact.symbol(id);
        assertEq(symbol, unicode"🤝-ETH");
    }

    function test_decimals_nativeToken() public {
        // Register allocator and create a deposit with native token (ETH)
        (, bytes12 lockTag) = _registerAllocator(alwaysOKAllocator);
        uint256 id = _makeDeposit(swapper, 1e18, lockTag);

        // Verify decimals returns the default ETH value (18)
        uint8 decimals = theCompact.decimals(id);
        assertEq(decimals, 18);
    }

    function test_name_customToken() public {
        // Register allocator and create a deposit with custom token
        (, bytes12 lockTag) = _registerAllocator(alwaysOKAllocator);
        uint256 id = _makeDeposit(swapper, address(customToken), 1e18, lockTag);

        // Verify name returns the custom token's name
        string memory name = theCompact.name(id);
        assertEq(name, "Compact Custom Token");
    }

    function test_symbol_customToken() public {
        // Register allocator and create a deposit with custom token
        (, bytes12 lockTag) = _registerAllocator(alwaysOKAllocator);
        uint256 id = _makeDeposit(swapper, address(customToken), 1e18, lockTag);

        // Verify symbol returns the custom token's symbol
        string memory symbol = theCompact.symbol(id);
        assertEq(symbol, unicode"🤝-CSTM");
    }

    function test_decimals_customToken() public {
        // Register allocator and create a deposit with custom token
        (, bytes12 lockTag) = _registerAllocator(alwaysOKAllocator);
        uint256 id = _makeDeposit(swapper, address(customToken), 1e18, lockTag);

        // Verify decimals returns the custom token's decimals (8)
        uint8 decimals = theCompact.decimals(id);
        assertEq(decimals, 8);
    }

    function test_name_tokenWithoutMetadata() public {
        // Register allocator and create a deposit with token that doesn't implement metadata
        (, bytes12 lockTag) = _registerAllocator(alwaysOKAllocator);
        uint256 id = _makeDeposit(swapper, address(tokenWithoutMetadata), 1e18, lockTag);

        // Verify name returns the default value for tokens without metadata
        string memory name = theCompact.name(id);
        assertEq(name, "Compact Unknown Token");
    }

    function test_symbol_tokenWithoutMetadata() public {
        // Register allocator and create a deposit with token that doesn't implement metadata
        (, bytes12 lockTag) = _registerAllocator(alwaysOKAllocator);
        uint256 id = _makeDeposit(swapper, address(tokenWithoutMetadata), 1e18, lockTag);

        // Verify symbol returns the default value for tokens without metadata
        string memory symbol = theCompact.symbol(id);
        assertEq(symbol, unicode"🤝-???");
    }

    function test_decimals_tokenWithoutMetadata() public {
        // Register allocator and create a deposit with token that doesn't implement metadata
        (, bytes12 lockTag) = _registerAllocator(alwaysOKAllocator);
        uint256 id = _makeDeposit(swapper, address(tokenWithoutMetadata), 1e18, lockTag);

        // Verify decimals returns the default value (0) for tokens without metadata
        uint8 decimals = theCompact.decimals(id);
        assertEq(decimals, 0);
    }
}

/**
 * @title MockERC20WithoutMetadata
 * @notice A mock ERC20 token that doesn't implement name, symbol, or decimals methods
 */
contract MockERC20WithoutMetadata {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        address owner = msg.sender;
        _transfer(owner, to, amount);
        return true;
    }

    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        address owner = msg.sender;
        _approve(owner, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        address spender = msg.sender;
        _spendAllowance(from, spender, amount);
        _transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) public {
        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[from] = fromBalance - amount;
        }
        _balances[to] += amount;

        emit Transfer(from, to, amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _spendAllowance(address owner, address spender, uint256 amount) internal {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "ERC20: insufficient allowance");
            unchecked {
                _approve(owner, spender, currentAllowance - amount);
            }
        }
    }
}
