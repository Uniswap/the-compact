// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";
import { MetadataRenderer } from "../../src/lib/MetadataRenderer.sol";
import { ResetPeriod } from "../../src/types/ResetPeriod.sol";
import { Scope } from "../../src/types/Scope.sol";
import { MockERC20 } from "lib/solady/test/utils/mocks/MockERC20.sol";
import { EfficiencyLib } from "../../src/lib/EfficiencyLib.sol";
import { IdLib } from "../../src/lib/IdLib.sol";
import { MetadataLib } from "../../src/lib/MetadataLib.sol";
import { LibString } from "solady/utils/LibString.sol";
import { JSONParserLib } from "solady/utils/JSONParserLib.sol";
import { TheCompact } from "../../src/TheCompact.sol";

library CreateAddress {
    /*────────────────── PUBLIC API ──────────────────*/

    /**
     * @param deployer The account that will call `new SomeContract()`.
     * @param nonce    The deployer’s *creation* nonce (starts at 1, not 0).
     * @return predicted The address Ethereum will assign for that <deployer, nonce>.
     *
     * @dev Implements the formula in the yellow-paper (App. H) / EIP-161:
     *      addr = keccak256( RLP([deployer, nonce]) )[12:]
     *      – Handles every nonce that fits in uint256.
     *      – Gas cost ~400–650 gas (higher for very large nonces).
     */
    function compute(address deployer, uint256 nonce) internal pure returns (address predicted) {
        unchecked {
            require(nonce != 0, "nonce must be >= 1");

            /* ───── 1. RLP-encode the nonce ───── */
            bytes memory rlpNonce;
            if (nonce <= 0x7f) {
                // single-byte, no prefix
                rlpNonce = abi.encodePacked(bytes1(uint8(nonce)));
            } else {
                // big-endian byte sequence (no leading zeros)
                uint256 n = nonce;
                uint256 len;
                while (n != 0) {
                    ++len;
                    n >>= 8;
                }
                bytes memory buf = new bytes(len);
                n = nonce;
                for (uint256 i; i < len; ++i) {
                    buf[len - 1 - i] = bytes1(uint8(n));
                    n >>= 8;
                }
                // prefix 0x80 + len for strings <= 55 bytes (always true for uint256)
                rlpNonce = abi.encodePacked(bytes1(uint8(0x80 + len)), buf);
            }

            /* ───── 2. Build the full RLP stream [deployer, nonce] ───── */
            uint256 payloadLen = 1 /*0x94*/ + 20 /*addr*/ + rlpNonce.length;

            bytes memory rlp;
            if (payloadLen < 56) {
                // short-form list header: 0xc0 + payloadLen
                rlp = abi.encodePacked(bytes1(uint8(0xc0 + payloadLen)), bytes1(0x94), deployer, rlpNonce);
            } else {
                // long-form list header (payloadLen ≥ 56 — practically unreachable,
                // would need nonce > 2²⁷⁷): kept for completeness.
                uint256 lenOfLen;
                uint256 tmp = payloadLen;
                while (tmp != 0) {
                    ++lenOfLen;
                    tmp >>= 8;
                }
                bytes memory lenBytes = new bytes(lenOfLen);
                tmp = payloadLen;
                for (uint256 i; i < lenOfLen; ++i) {
                    lenBytes[lenOfLen - 1 - i] = bytes1(uint8(tmp));
                    tmp >>= 8;
                }
                rlp = abi.encodePacked(bytes1(uint8(0xf7 + lenOfLen)), lenBytes, bytes1(0x94), deployer, rlpNonce);
            }

            /* ───── 3. Hash & truncate ───── */
            predicted = address(uint160(uint256(keccak256(rlp))));
        }
    }

    /* ───── Convenience fast-path for nonce == 1 (costs ~220 gas) ───── */
    function firstCreate(address deployer) internal pure returns (address) {
        bytes32 h = keccak256(
            abi.encodePacked(
                bytes1(0xd6), // list header  (0xc0 + 0x16)
                bytes1(0x94), // 20-byte addr
                deployer,
                bytes1(0x01) // nonce 1
            )
        );
        return address(uint160(uint256(h)));
    }
}

contract MockAllocator {
    function name() public pure returns (string memory) {
        return unicode"Smallocator 🤏";
    }
}

// Test contract with no `name()`, `symbol()`, or `decimals()` functions
contract Dummy { }

// Mock malicious token with JSON-breaking characters in name and symbol
contract MaliciousToken {
    function name() public pure returns (string memory) {
        // Contains quotes, backslashes, and newlines that could break JSON
        return "Malicious\"Token\\with\nSpecial\r\tChars";
    }

    function symbol() public pure returns (string memory) {
        // Contains quotes and control characters
        return "MAL\"ICE\n\r\t";
    }

    function decimals() public pure returns (uint8) {
        return 18;
    }
}

contract MetadataRendererTest is Test {
    using EfficiencyLib for address;
    using IdLib for *;
    using LibString for *;
    using MetadataLib for ResetPeriod;
    using MetadataLib for Scope;
    using MetadataLib for MetadataLib.Lock;
    using JSONParserLib for string;
    using JSONParserLib for JSONParserLib.Item;
    using CreateAddress for address;

    TheCompact public theCompact;
    MetadataRenderer public metadataRenderer;
    MockERC20 public mockToken;
    address public mockAllocator;
    uint256 public tokenErc6909Id;
    uint256 public nativeErc6909Id;

    // Mock ERC20 details
    string constant MOCK_TOKEN_NAME = "Wrapped Bitcoin";
    string constant MOCK_TOKEN_SYMBOL = "WBTC";
    uint8 constant MOCK_TOKEN_DECIMALS = 9;

    // Native Token details
    string constant NATIVE_TOKEN_NAME = "Native Token";
    string constant NATIVE_TOKEN_SYMBOL = "ETH";
    uint8 constant NATIVE_TOKEN_DECIMALS = 18;

    // Allocator details
    string constant ALLOCATOR_NAME = unicode"Smallocator 🤏";
    string constant UNNAMED_ALLOCATOR_NAME = "Unnamed Allocator";

    // Unknown token details
    string constant UNKNOWN_TOKEN_NAME = "Unknown Token";
    string constant UNKNOWN_TOKEN_SYMBOL = "???";
    uint8 constant UNKNOWN_TOKEN_DECIMALS = 0;

    function setUp() public {
        theCompact = new TheCompact();

        // NOTE: Tstorish is deployed first, metadata renderer second
        metadataRenderer = MetadataRenderer(address(theCompact).compute(2));

        mockToken =
            new MockERC20{ salt: bytes32(uint256(0xdeadbeef)) }(MOCK_TOKEN_NAME, MOCK_TOKEN_SYMBOL, MOCK_TOKEN_DECIMALS);
        mockAllocator = address(new MockAllocator());

        theCompact.__registerAllocator(mockAllocator, "");

        tokenErc6909Id = MetadataLib.Lock({
            token: address(mockToken),
            allocator: mockAllocator,
            resetPeriod: ResetPeriod.OneDay,
            scope: Scope.ChainSpecific
        }).toId();
        nativeErc6909Id = MetadataLib.Lock({
            token: address(0),
            allocator: mockAllocator,
            resetPeriod: ResetPeriod.SevenDaysAndOneHour,
            scope: Scope.Multichain
        }).toId();

        assertEq(metadataRenderer.decimals(nativeErc6909Id), NATIVE_TOKEN_DECIMALS, "Native decimals mismatch");
    }

    function test_uri_erc20() public {
        string memory uri = metadataRenderer.uri(tokenErc6909Id);
        vm.snapshotGasLastCall("uriERC20");

        JSONParserLib.Item memory json = uri.parse();

        // Verify top-level fields
        assertEq(json.at('"name"').value(), string.concat('"Compact ', MOCK_TOKEN_SYMBOL, '"'));
        string memory expectedDescription = string.concat(
            '"[The Compact v1] ',
            MOCK_TOKEN_NAME,
            " (",
            address(mockToken).toHexStringChecksummed(),
            ") resource lock using ",
            ALLOCATOR_NAME,
            " (",
            address(mockAllocator).toHexStringChecksummed(),
            '), Chain-specific scope, and a 24h reset period"'
        );
        assertEq(json.at('"description"').value(), expectedDescription);
        assertTrue(json.at('"image"').value().startsWith('"data:image/svg+xml;base64,'));
        assertTrue(json.at('"attributes"').isArray());

        // Verify attributes
        JSONParserLib.Item[] memory attributes = json.at('"attributes"').children();
        string memory lockTagHex = uint96(tokenErc6909Id.toLockTag()).toHexString();

        assertAttribute(attributes, "ID", tokenErc6909Id.toHexString(), true);
        assertAttribute(attributes, "Token Address", address(mockToken).toHexStringChecksummed(), true);
        assertAttribute(attributes, "Token Name", MOCK_TOKEN_NAME, true);
        assertAttribute(attributes, "Token Symbol", MOCK_TOKEN_SYMBOL, true);
        assertAttribute(attributes, "Token Decimals", uint256(MOCK_TOKEN_DECIMALS).toString(), false);
        assertAttribute(attributes, "Allocator Address", address(mockAllocator).toHexStringChecksummed(), true);
        assertAttribute(attributes, "Allocator Name", ALLOCATOR_NAME, true);
        assertAttribute(attributes, "Scope", Scope.ChainSpecific.toString(), true);
        assertAttribute(attributes, "Reset Period", ResetPeriod.OneDay.toString(), true);
        assertAttribute(attributes, "Lock Tag", lockTagHex, true);
        assertAttribute(attributes, "Origin Chain", block.chainid.toString(), true);
    }

    function test_uri_native() public {
        string memory uri = metadataRenderer.uri(nativeErc6909Id);
        vm.snapshotGasLastCall("uriNative");

        JSONParserLib.Item memory json = uri.parse();

        // Verify top-level fields
        assertEq(json.at('"name"').value(), string.concat('"Compact ', NATIVE_TOKEN_SYMBOL, '"'));
        string memory expectedDescription = string.concat(
            '"[The Compact v1] ',
            NATIVE_TOKEN_NAME,
            " (",
            address(0).toHexStringChecksummed(),
            ") resource lock using ",
            ALLOCATOR_NAME,
            " (",
            address(mockAllocator).toHexStringChecksummed(),
            '), Multichain scope, and a 7d 1h reset period"'
        );
        assertEq(json.at('"description"').value(), expectedDescription);
        assertTrue(json.at('"image"').value().startsWith('"data:image/svg+xml;base64,'));
        assertTrue(json.at('"attributes"').isArray());

        // Verify attributes
        JSONParserLib.Item[] memory attributes = json.at('"attributes"').children();
        string memory lockTagHex = uint96(nativeErc6909Id.toLockTag()).toHexString();

        assertAttribute(attributes, "ID", nativeErc6909Id.toHexString(), true);
        assertAttribute(attributes, "Token Address", address(0).toHexStringChecksummed(), true);
        assertAttribute(attributes, "Token Name", NATIVE_TOKEN_NAME, true);
        assertAttribute(attributes, "Token Symbol", NATIVE_TOKEN_SYMBOL, true);
        assertAttribute(attributes, "Token Decimals", uint256(NATIVE_TOKEN_DECIMALS).toString(), false);
        assertAttribute(attributes, "Allocator Address", address(mockAllocator).toHexStringChecksummed(), true);
        assertAttribute(attributes, "Allocator Name", ALLOCATOR_NAME, true);
        assertAttribute(attributes, "Scope", Scope.Multichain.toString(), true);
        assertAttribute(attributes, "Reset Period", ResetPeriod.SevenDaysAndOneHour.toString(), true);
        assertAttribute(attributes, "Lock Tag", lockTagHex, true);
        assertAttribute(attributes, "Origin Chain", block.chainid.toString(), true);
    }

    function test_name_erc20() public view {
        string memory expectedName = string.concat("Compact ", MOCK_TOKEN_NAME);
        assertEq(metadataRenderer.name(tokenErc6909Id), expectedName, "ERC20 name mismatch");
    }

    function test_name_native() public view {
        string memory expectedName = string.concat("Compact ", NATIVE_TOKEN_NAME);
        assertEq(metadataRenderer.name(nativeErc6909Id), expectedName, "Native name mismatch");
    }

    function test_symbol_erc20() public view {
        string memory expectedSymbol = string.concat(unicode"🤝-", MOCK_TOKEN_SYMBOL);
        assertEq(metadataRenderer.symbol(tokenErc6909Id), expectedSymbol, "ERC20 symbol mismatch");
    }

    function test_symbol_native() public view {
        string memory expectedSymbol = string.concat(unicode"🤝-", NATIVE_TOKEN_SYMBOL);
        assertEq(metadataRenderer.symbol(nativeErc6909Id), expectedSymbol, "Native symbol mismatch");
    }

    function test_decimals_erc20() public view {
        assertEq(metadataRenderer.decimals(tokenErc6909Id), MOCK_TOKEN_DECIMALS, "ERC20 decimals mismatch");
    }

    function test_decimals_native() public view {
        assertEq(metadataRenderer.decimals(nativeErc6909Id), NATIVE_TOKEN_DECIMALS, "Native decimals mismatch");
    }

    function test_uri_unnamedAllocator() public {
        address unnamedAllocator = address(new Dummy());
        theCompact.__registerAllocator(unnamedAllocator, "");
        MetadataLib.Lock memory lock = MetadataLib.Lock({
            token: address(mockToken),
            allocator: unnamedAllocator,
            resetPeriod: ResetPeriod.OneMinute,
            scope: Scope.Multichain
        });
        uint256 id = lock.toId();
        string memory uri = metadataRenderer.uri(id);
        JSONParserLib.Item memory json = uri.parse();

        string memory expectedDescription = string.concat(
            '"[The Compact v1] ',
            MOCK_TOKEN_NAME,
            " (",
            address(mockToken).toHexStringChecksummed(),
            ") resource lock using ",
            UNNAMED_ALLOCATOR_NAME,
            " (",
            unnamedAllocator.toHexStringChecksummed(),
            '), Multichain scope, and a 1m reset period"'
        );
        assertEq(json.at('"description"').value(), expectedDescription);

        JSONParserLib.Item[] memory attributes = json.at('"attributes"').children();
        assertAttribute(attributes, "Allocator Name", UNNAMED_ALLOCATOR_NAME, true);
        assertAttribute(attributes, "Allocator Address", unnamedAllocator.toHexStringChecksummed(), true);
    }

    function test_uri_unknownToken() public {
        address unknownTokenAddress = address(new Dummy());
        MetadataLib.Lock memory lock = MetadataLib.Lock({
            token: unknownTokenAddress,
            allocator: mockAllocator,
            resetPeriod: ResetPeriod.TenMinutes,
            scope: Scope.ChainSpecific
        });
        uint256 id = lock.toId();
        string memory uri = metadataRenderer.uri(id);
        JSONParserLib.Item memory json = uri.parse();

        assertEq(json.at('"name"').value(), string.concat('"Compact ', UNKNOWN_TOKEN_SYMBOL, '"'));

        string memory expectedDescription = string.concat(
            '"[The Compact v1] ',
            UNKNOWN_TOKEN_NAME,
            " (",
            unknownTokenAddress.toHexStringChecksummed(),
            ") resource lock using ",
            ALLOCATOR_NAME,
            " (",
            address(mockAllocator).toHexStringChecksummed(),
            '), Chain-specific scope, and a 10m reset period"'
        );
        assertEq(json.at('"description"').value(), expectedDescription);

        JSONParserLib.Item[] memory attributes = json.at('"attributes"').children();
        assertAttribute(attributes, "Token Name", UNKNOWN_TOKEN_NAME, true);
        assertAttribute(attributes, "Token Symbol", UNKNOWN_TOKEN_SYMBOL, true);
        assertAttribute(attributes, "Token Decimals", uint256(UNKNOWN_TOKEN_DECIMALS).toString(), false);
        assertAttribute(attributes, "Token Address", unknownTokenAddress.toHexStringChecksummed(), true);
    }

    function test_name_unknownToken() public {
        uint256 id = MetadataLib.Lock({
            token: address(new Dummy()),
            allocator: mockAllocator,
            resetPeriod: ResetPeriod.TenMinutes,
            scope: Scope.ChainSpecific
        }).toId();
        string memory expectedName = string.concat("Compact ", UNKNOWN_TOKEN_NAME);
        assertEq(metadataRenderer.name(id), expectedName, "Unknown token name mismatch");
    }

    function test_symbol_unknownToken() public {
        uint256 id = MetadataLib.Lock({
            token: address(new Dummy()),
            allocator: mockAllocator,
            resetPeriod: ResetPeriod.TenMinutes,
            scope: Scope.ChainSpecific
        }).toId();
        string memory expectedSymbol = string.concat(unicode"🤝-", UNKNOWN_TOKEN_SYMBOL);
        assertEq(metadataRenderer.symbol(id), expectedSymbol, "Unknown token symbol mismatch");
    }

    function test_decimals_unknownToken() public {
        uint256 id = MetadataLib.Lock({
            token: address(new Dummy()),
            allocator: mockAllocator,
            resetPeriod: ResetPeriod.TenMinutes,
            scope: Scope.ChainSpecific
        }).toId();
        assertEq(metadataRenderer.decimals(id), UNKNOWN_TOKEN_DECIMALS, "Unknown token decimals mismatch");
    }

    function test_uri_maliciousTokenEscaping() public {
        // Deploy malicious token with JSON-breaking characters
        address maliciousTokenAddr = address(new MaliciousToken());

        MetadataLib.Lock memory lock = MetadataLib.Lock({
            token: maliciousTokenAddr,
            allocator: mockAllocator,
            resetPeriod: ResetPeriod.OneHourAndFiveMinutes,
            scope: Scope.ChainSpecific
        });
        uint256 id = lock.toId();

        // Generate URI with malicious token
        string memory uri = metadataRenderer.uri(id);

        // Verify that the URI is valid JSON by parsing it
        JSONParserLib.Item memory json = uri.parse();

        // Verify the JSON structure is intact
        assertTrue(json.at('"name"').isString(), "Name field should be a string");
        assertTrue(json.at('"description"').isString(), "Description field should be a string");
        assertTrue(json.at('"image"').isString(), "Image field should be a string");
        assertTrue(json.at('"attributes"').isArray(), "Attributes should be an array");

        // Verify attributes array contains escaped values
        JSONParserLib.Item[] memory attributes = json.at('"attributes"').children();

        // The token name should be properly escaped in the attributes
        string memory expectedEscapedName = "Malicious\\\"Token\\\\with\\nSpecial\\r\\tChars";
        assertAttribute(attributes, "Token Name", expectedEscapedName, true);

        // The token symbol should be properly escaped in the attributes
        string memory expectedEscapedSymbol = "MAL\\\"ICE\\n\\r\\t";
        assertAttribute(attributes, "Token Symbol", expectedEscapedSymbol, true);

        // Verify that the description field contains properly escaped values
        string memory description = json.at('"description"').value();

        // The description should contain the escaped token name
        assertTrue(description.contains(expectedEscapedName), "Description should contain escaped token name");

        // Verify that the name field in the JSON uses the escaped symbol
        string memory nameField = json.at('"name"').value();
        assertTrue(nameField.contains(expectedEscapedSymbol), "Name field should contain escaped token symbol");
    }

    function assertAttribute(
        JSONParserLib.Item[] memory attributes,
        string memory traitTypeToFind,
        string memory expectedValue,
        bool expectedValueIsQuoted
    ) internal pure {
        bool foundAttribute = false;
        for (uint256 i = 0; i < attributes.length; i++) {
            JSONParserLib.Item memory attribute = attributes[i];
            string memory currentTraitType = attribute.at('"trait_type"').value();
            // Remove quotes from trait_type for comparison
            if (currentTraitType.startsWith('"')) {
                currentTraitType = currentTraitType.slice(1, bytes(currentTraitType).length - 1);
            }

            if (keccak256(bytes(currentTraitType)) == keccak256(bytes(traitTypeToFind))) {
                string memory actualValue = attribute.at('"value"').value();
                string memory formattedExpectedValue =
                    expectedValueIsQuoted ? string.concat('"', expectedValue, '"') : expectedValue;
                assertEq(
                    actualValue, formattedExpectedValue, string.concat("Attribute ", traitTypeToFind, " value mismatch")
                );
                foundAttribute = true;
                break;
            }
        }
        assertTrue(foundAttribute, string.concat("Attribute ", traitTypeToFind, " not found"));
    }

    function test_revert_invalidMetadataRendererResponse() public {
        vm.etch(address(metadataRenderer), hex"5f5ffd"); // push0 push0 revert

        vm.expectRevert(bytes(""), address(metadataRenderer));
        theCompact.name(nativeErc6909Id);
    }
}
