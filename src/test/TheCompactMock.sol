// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { IAllocator } from "src/interfaces/IAllocator.sol";
import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { ERC20 } from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import { IdLib } from "src/lib/IdLib.sol";

contract TheCompactMock is ERC6909 {
    using IdLib for uint96;
    using IdLib for uint256;
    using IdLib for address;

    mapping(uint256 nonce => bool consumed) public consumedNonces;

    function __registerAllocator(address allocator, bytes calldata proof) external returns (uint96) {
        return 0;
    }

    function deposit(address token, uint256 amount, address allocator) external {
        ERC20(token).transferFrom(msg.sender, address(this), amount);
        uint256 id = _getTokenId(token, allocator);
        _mint(msg.sender, id, amount);
    }

    function transfer(address from, address to, uint256 amount, address token, address allocator) external {
        uint256 id = _getTokenId(token, allocator);
        IAllocator(allocator).attest(msg.sender, from, to, id, amount);
        _transfer(msg.sender, from, to, id, amount);
    }

    function claim(address from, address to, address token, uint256 amount, address allocator, bytes calldata signature) external {
        uint256 id = _getTokenId(token, allocator);
        IAllocator(allocator).isValidSignature(keccak256(abi.encode(from, id, amount)), signature);
        _transfer(msg.sender, from, to, id, amount);
    }

    function withdraw(address token, uint256 amount, address allocator) external {
        uint256 id = _getTokenId(token, allocator);
        IAllocator(allocator).attest(msg.sender, msg.sender, msg.sender, id, amount);
        ERC20(token).transferFrom(address(this), msg.sender, amount);
        _burn(msg.sender, id, amount);
    }

    function consume(uint256[] calldata nonces) external returns (bool) {
        for (uint256 i = 0; i < nonces.length; ++i) {
            consumedNonces[nonces[i]] = true;
        }
        return true;
    }

    function getTokenId(address token, address allocator) external pure returns (uint256) {
        return _getTokenId(token, allocator);
    }

    function name(
        uint256 // id
    ) public view virtual override returns (string memory) {
        return "TheCompactMock";
    }

    function symbol(
        uint256 // id
    ) public view virtual override returns (string memory) {
        return "TCM";
    }

    function tokenURI(
        uint256 // id
    ) public view virtual override returns (string memory) {
        return "";
    }

    function _getTokenId(address token, address allocator) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(token, allocator)));
    }
}
