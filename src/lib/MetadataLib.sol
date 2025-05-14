// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";
import { IdLib } from "./IdLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { LibString } from "solady/utils/LibString.sol";
import { MetadataReaderLib } from "solady/utils/MetadataReaderLib.sol";
import { Base64 } from "solady/utils/Base64.sol";

/**
 * @title MetadataLib
 * @notice Library contract implementing logic for deriving and displaying
 * ERC6909 metadata as well as metadata specific to various underlying tokens.
 */
library MetadataLib {
    using EfficiencyLib for Scope;
    using EfficiencyLib for ResetPeriod;
    using EfficiencyLib for address;
    using EfficiencyLib for uint96;
    using IdLib for address;
    using IdLib for uint96;
    using LibString for address;
    using LibString for uint256;
    using LibString for uint96;
    using MetadataReaderLib for address;
    using MetadataLib for address;
    using MetadataLib for ResetPeriod;
    using MetadataLib for Scope;
    using MetadataLib for Lock;

    struct Lock {
        address token;
        address allocator;
        ResetPeriod resetPeriod;
        Scope scope;
    }

    /**
     * @notice Internal pure function for converting a ResetPeriod enum to a human-readable string.
     * @param resetPeriod The ResetPeriod enum value to convert.
     * @return A string representation of the reset period.
     */
    function toString(ResetPeriod resetPeriod) internal pure returns (string memory) {
        if (resetPeriod == ResetPeriod.OneSecond) {
            return "1s";
        } else if (resetPeriod == ResetPeriod.FifteenSeconds) {
            return "15s";
        } else if (resetPeriod == ResetPeriod.OneMinute) {
            return "1m";
        } else if (resetPeriod == ResetPeriod.TenMinutes) {
            return "10m";
        } else if (resetPeriod == ResetPeriod.OneHourAndFiveMinutes) {
            return "1h 5m";
        } else if (resetPeriod == ResetPeriod.OneDay) {
            return "24h";
        } else if (resetPeriod == ResetPeriod.SevenDaysAndOneHour) {
            return "7d 1h";
        } else {
            return "30d";
        }
    }

    /**
     * @notice Internal pure function for converting a Scope enum to a human-readable string.
     * @param scope The Scope enum value to convert.
     * @return A string representation of the scope.
     */
    function toString(Scope scope) internal pure returns (string memory) {
        if (scope == Scope.Multichain) {
            return "Multichain";
        } else {
            return "Chain-specific";
        }
    }

    /**
     * @notice Internal view function for generating a token URI for a given lock and ID.
     * @param token       The address of the underlying token (or address(0) for native tokens).
     * @param allocator   The address of the allocator mediating the resource lock.
     * @param resetPeriod The duration after which the underlying tokens can be withdrawn once a forced withdrawal is initiated.
     * @param scope       The scope of the resource lock (multichain or single chain).
     * @param id          The ERC6909 token identifier.
     * @return uri A JSON string containing token metadata.
     */
    function toURI(address token, address allocator, ResetPeriod resetPeriod, Scope scope, uint256 id)
        internal
        view
        returns (string memory uri)
    {
        Lock memory lock = Lock({ token: token, allocator: allocator, resetPeriod: resetPeriod, scope: scope });
        string memory attributes = _getAttributes(lock, id);
        string memory description = _getDescription(lock);
        string memory name = string.concat("{\"name\": \"Compact ", lock.token.readSymbolWithDefaultValue(), "\",");
        string memory image;
        {
            // Generate dynamic SVG and Base64 encode it
            string memory svg = _generateSvgImage(lock);
            string memory encodedSvg = Base64.encode(bytes(svg));
            image = string.concat("\"image\": \"data:image/svg+xml;base64,", encodedSvg, "\",");
        }

        uri = string.concat(name, description, image, attributes);
    }

    /**
     * @notice Internal view function for generating the attributes section of the token metadata.
     * @param lock The lock.
     * @param id The ERC6909 token identifier.
     * @return attributes The attributes section of the token metadata.
     */
    function _getAttributes(Lock memory lock, uint256 id) internal view returns (string memory attributes) {
        string memory allocator = lock.allocator.toHexStringChecksummed();
        string memory resetPeriod = lock.resetPeriod.toString();
        string memory scope = lock.scope.toString();
        string memory allocatorName = _tryReadAllocatorName(lock.allocator);
        string memory lockTagHex = uint96(lock.toLockTag()).toHexString();

        (string memory tokenAddress, string memory tokenName, string memory tokenSymbol, string memory tokenDecimals) =
            _getTokenDetails(lock);

        // Initialize the attributes string
        attributes = string.concat("\"attributes\": [", _makeAttribute("ID", id.toHexString(), false, true));

        // Token details
        {
            attributes = string.concat(
                attributes,
                _makeAttribute("Token Address", tokenAddress, false, true),
                _makeAttribute("Token Name", tokenName, false, true),
                _makeAttribute("Token Symbol", tokenSymbol, false, true),
                _makeAttribute("Token Decimals", tokenDecimals, false, false)
            );
        }

        // Allocator & Lock details
        {
            attributes = string.concat(
                attributes,
                _makeAttribute("Allocator Address", allocator, false, true),
                _makeAttribute("Allocator Name", allocatorName, false, true),
                _makeAttribute("Scope", scope, false, true),
                _makeAttribute("Reset Period", resetPeriod, false, true),
                _makeAttribute("Lock Tag", lockTagHex, false, true),
                _makeAttribute("Origin Chain", block.chainid.toString(), true, true)
            );
        }

        // Close the JSON array and object
        attributes = string.concat(attributes, "]}");
    }

    /**
     * @notice Internal view function for generating the description section of the token metadata.
     * @param lock The lock containing token, allocator, reset period, and scope information.
     * @return description The description section of the token metadata as a JSON string.
     */
    function _getDescription(Lock memory lock) internal view returns (string memory description) {
        (string memory tokenAddress, string memory tokenName,,) = _getTokenDetails(lock);
        string memory allocatorName = _tryReadAllocatorName(lock.allocator);
        string memory resetPeriod = lock.resetPeriod.toString();
        string memory scope = lock.scope.toString();
        description = string.concat(
            "\"description\": \"[The Compact v1] ",
            tokenName,
            " (",
            tokenAddress,
            ") resource lock using ",
            allocatorName,
            " (",
            lock.allocator.toHexStringChecksummed(),
            "), ",
            scope,
            " scope, ",
            "and a ",
            resetPeriod,
            " reset period",
            "\","
        );
    }

    /**
     * @notice Internal view function for retrieving token details.
     * @param lock The lock containing the token address.
     * @return tokenAddress The token's address as a checksummed hex string.
     * @return tokenName The token's name or a default value if not available.
     * @return tokenSymbol The token's symbol or a default value if not available.
     * @return tokenDecimals The token's decimals as a string or a default value if not available.
     */
    function _getTokenDetails(Lock memory lock)
        internal
        view
        returns (
            string memory tokenAddress,
            string memory tokenName,
            string memory tokenSymbol,
            string memory tokenDecimals
        )
    {
        tokenAddress = lock.token.toHexStringChecksummed();
        tokenName = lock.token.readNameWithDefaultValue();
        tokenSymbol = lock.token.readSymbolWithDefaultValue();
        tokenDecimals = uint256(lock.token.readDecimalsAsUint8WithDefaultValue()).toString();
    }

    /**
     * @notice Internal view function to generate a dynamic SVG image for the token.
     * @param lock The lock containing token, allocator, reset period, and scope information.
     * @return A string containing the complete SVG image markup.
     */
    function _generateSvgImage(Lock memory lock) internal view returns (string memory) {
        return string.concat(
            '<svg width="500" height="290" viewBox="0 0 500 290" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">',
            _getSvgDefs(lock),
            _getSvgBackground(),
            _getSvgBorder(),
            _getSvgAnimatedText(lock),
            _getSvgTitleSection(lock),
            _getSvgDetailsSection(lock),
            "</svg>"
        );
    }

    /**
     * @notice Dynamically generate a color scheme based on a given token address.
     * @param token The address of the token to generate colors for.
     * @return bgColor1 The first background color.
     * @return bgColor2 The second background color.
     * @return bgColor3 The third background color.
     */
    function _generateColors(address token) internal pure returns (string memory, string memory, string memory) {
        bytes32 tokenHash = keccak256(abi.encodePacked(token));

        string memory bgColor1 = LibString.toHexStringNoPrefix(uint24(bytes3(tokenHash)));
        string memory bgColor2 =
            LibString.toHexStringNoPrefix(uint24(bytes3(bytes32(uint256(uint256(tokenHash) >> 96)))));
        string memory bgColor3 =
            LibString.toHexStringNoPrefix(uint24(bytes3(bytes32(uint256(uint256(tokenHash) >> 192)))));

        return (bgColor1, bgColor2, bgColor3);
    }

    /**
     * @notice Returns the SVG definitions section with filters, gradients, and paths.
     * @param lock The lock containing the token address used for color generation.
     * @return A string containing the SVG definitions markup.
     */
    function _getSvgDefs(Lock memory lock) internal pure returns (string memory) {
        (string memory bgColor1, string memory bgColor2, string memory bgColor3) = _generateColors(lock.token);

        // Filter definitions for background generation (used to create the gradient effect)
        string memory filterDefs = string.concat(
            '<filter id="f1">',
            // feImage 1 (main background)
            '<feImage result="p0" xlink:href="data:image/svg+xml;base64,',
            Base64.encode(
                bytes(
                    string.concat(
                        '<svg width="500" height="290" viewBox="0 0 500 290" xmlns="http://www.w3.org/2000/svg">',
                        '<rect width="500px" height="290px" fill="#',
                        bgColor1,
                        '"/>',
                        "</svg>"
                    )
                )
            ),
            '"/>',
            // feImage 2 (first circle overlay)
            '<feImage result="p1" xlink:href="data:image/svg+xml;base64,',
            Base64.encode(
                bytes(
                    string.concat(
                        '<svg width="500" height="290" viewBox="0 0 500 290" xmlns="http://www.w3.org/2000/svg">',
                        '<circle cx="400" cy="100" r="150px" fill="#',
                        bgColor2,
                        '"/>',
                        "</svg>"
                    )
                )
            ),
            '"/>',
            // feImage 3 (second circle overlay)
            '<feImage result="p2" xlink:href="data:image/svg+xml;base64,',
            Base64.encode(
                bytes(
                    string.concat(
                        '<svg width="500" height="290" viewBox="0 0 500 290" xmlns="http://www.w3.org/2000/svg">',
                        '<circle cx="120" cy="200" r="120px" fill="#',
                        bgColor3,
                        '"/>',
                        "</svg>"
                    )
                )
            ),
            '"/>',
            // Blending directives (enhances the gradient effect)
            '<feBlend mode="overlay" in="p0" in2="p1" />',
            '<feBlend mode="exclusion" in2="p2" />',
            '<feGaussianBlur stdDeviation="42" />',
            "</filter>",
            // Blur filter (makes the gradient smoother)
            '<filter id="tb">',
            '<feGaussianBlur in="SourceGraphic" stdDeviation="24" />',
            "</filter>",
            // Drop shadow filter (makes the text more readable)
            '<filter id="ts" x="-20%" y="-20%" width="140%" height="140%">',
            '<feDropShadow dx="0" dy="0" stdDeviation="1" flood-opacity="0.8" flood-color="black" />',
            "</filter>"
        );

        // Path and mask definitions
        string memory pathAndMaskDefs = string.concat(
            // Outer clip path (clips the entire SVG)
            '<clipPath id="c">',
            '<rect width="500" height="290" rx="42" ry="42" />',
            "</clipPath>",
            // Path for the animated text (creates a looped animation)
            '<path id="tp" d="M40 12 H460 A28 28 0 0 1 488 40 V250 A28 28 0 0 1 460 278 H40 A28 28 0 0 1 12 250 V40 A28 28 0 0 1 40 12 z" />',
            // Gradient mask for the title text (fades out towards the right edge of the canvas)
            '<linearGradient id="gs" x1="0" y1="0" x2="1" y2="0">',
            '<stop offset="0.7" stop-color="white" stop-opacity="1" />',
            '<stop offset=".95" stop-color="white" stop-opacity="0" />',
            "</linearGradient>",
            '<mask id="fs" maskContentUnits="userSpaceOnUse">',
            '<rect width="440px" height="200px" fill="url(#gs)" />',
            "</mask>"
        );

        return string.concat("<defs>", filterDefs, pathAndMaskDefs, "</defs>");
    }

    /**
     * @notice Returns the SVG background section with gradient and filter effects.
     * @return A string containing the SVG background markup.
     */
    function _getSvgBackground() internal pure returns (string memory) {
        return string.concat(
            '<g clip-path="url(#c)">',
            '<rect fill="none" x="0px" y="0px" width="500px" height="290px" />',
            '<rect style="filter: url(#f1)" x="0px" y="0px" width="500px" height="290px" />',
            '<g style="filter:url(#tb); transform:scale(1.5); transform-origin:left top;">',
            '<rect fill="none" x="0px" y="0px" width="500px" height="290px" />',
            '<ellipse cx="25%" cy="0px" rx="180px" ry="120px" fill="#000" opacity="0.85" />',
            "</g>",
            "</g>"
        );
    }

    /**
     * @notice Returns the SVG border elements that frame the token image.
     * @return A string containing the SVG border markup.
     */
    function _getSvgBorder() internal pure returns (string memory) {
        return string.concat(
            '<rect x="0" y="0" width="500" height="290" rx="42" ry="42" fill="rgba(0,0,0,0)" stroke="rgba(255,255,255,0.2)" />',
            '<rect x="16" y="16" width="468" height="258" rx="26" ry="26" fill="rgba(0,0,0,0)" stroke="rgba(255,255,255,0.2)" />'
        );
    }

    /**
     * @notice Returns the SVG animated text that moves along the border.
     * @return The SVG animated text.
     */
    function _getSvgAnimatedText(Lock memory lock) internal view returns (string memory) {
        (string memory tokenAddress, string memory tokenName, string memory tokenSymbol,) = _getTokenDetails(lock);
        string memory middot = unicode" • ";
        string memory token = string.concat(
            tokenName,
            middot,
            tokenSymbol,
            middot,
            tokenAddress,
            middot,
            "Lock Tag ",
            uint96(toLockTag(lock)).toHexString()
        );
        string memory allocator = string.concat(
            "The Compact v1",
            middot,
            lock.scope.toString(),
            " Resource Lock",
            middot,
            _tryReadAllocatorName(lock.allocator),
            " @ ",
            lock.allocator.toHexStringChecksummed()
        );

        // Paths are duplicated to create a looped animation
        return string.concat(
            '<text text-rendering="optimizeSpeed" filter="url(#ts)">',
            _getTextPath(token, "-100%"),
            _getTextPath(token, "0%"),
            _getTextPath(allocator, "50%"),
            _getTextPath(allocator, "-50%"),
            "</text>"
        );
    }

    /**
     * @notice Builds a textPath element that moves along the border.
     * @param text The text to display.
     * @param startOffset The starting offset of the text.
     * @return The SVG animated text.
     */
    function _getTextPath(string memory text, string memory startOffset) internal pure returns (string memory) {
        return string.concat(
            '<textPath startOffset="',
            startOffset,
            '" fill="white" font-family="monospace" font-size="10px" xlink:href="#tp">',
            text,
            '<animate additive="sum" attributeName="startOffset" from="0%" to="100%" begin="0s" dur="30s" repeatCount="indefinite" />',
            "</textPath>"
        );
    }

    /**
     * @notice Returns the SVG title section.
     * @param lock The lock.
     * @return The SVG title section.
     */
    function _getSvgTitleSection(Lock memory lock) internal view returns (string memory) {
        (,, string memory tokenSymbol,) = _getTokenDetails(lock);
        string memory scope = lock.scope.toString();
        string memory lockId = lock.toId().toHexString();
        return string.concat(
            "<g id=\"title\">",
            '<text y="60px" x="32px" fill="white" font-family="monospace" font-weight="100" font-size="32px" filter="url(#ts)">',
            "Compact ",
            tokenSymbol,
            "</text>",
            '<text y="90px" x="32px" fill="rgba(255,255,255,0.6)" font-family="monospace" font-weight="50" font-size="22px" filter="url(#ts)">',
            scope,
            " Resource Lock",
            "</text>",
            '<text y="110px" x="32px" fill="rgba(255,255,255,0.6)" font-family="monospace" font-weight="100" font-size="10px" filter="url(#ts)">',
            "ID: ",
            lockId,
            "</text>",
            "</g>"
        );
    }

    /**
     * @notice Returns the SVG details section
     * @dev This section contains the details of the lock, including the token, allocator, and reset period.
     * @param lock The lock.
     * @return The SVG details section.
     */
    function _getSvgDetailsSection(Lock memory lock) internal view returns (string memory) {
        (, string memory tokenName, string memory tokenSymbol,) = _getTokenDetails(lock);
        string memory allocatorName = _tryReadAllocatorName(lock.allocator);
        string memory resetPeriod = lock.resetPeriod.toString();
        string memory scope = lock.scope.toString();
        // Handshake Icon
        string memory iconSvg = string.concat(
            '<g style="transform:translate(420px, 50px)">',
            '<text x="20px" y="28px" text-anchor="middle" font-size="64px" opacity="0.4">',
            unicode"🤝",
            "</text>",
            "</g>"
        );

        // Detail Boxes
        string memory detailBoxesSvg = string.concat(
            // Left column
            // Locked Token
            '<g style="transform:translate(32px, 140px)">',
            '<rect width="200px" height="64px" rx="8px" ry="8px" fill="rgba(0,0,0,0.6)" />',
            '<text x="12px" y="17px" font-family="monospace" font-size="12px" fill="rgba(255,255,255,0.6)">Locked Token: </text>',
            _makeWrappable(string.concat(tokenName, " (", tokenSymbol, ")"), "190px", "40px"),
            "</g>",
            // Reset Period
            '<g style="transform:translate(32px, 212px)">',
            '<rect width="200px" height="26px" rx="8px" ry="8px" fill="rgba(0,0,0,0.6)" />',
            '<text x="12px" y="17px" font-family="monospace" font-size="12px" fill="white">',
            '<tspan fill="rgba(255,255,255,0.6)">Reset Period: </tspan>',
            resetPeriod,
            "</text>",
            "</g>",
            // Right column
            // Allocator
            '<g style="transform:translate(260px, 140px)">',
            '<rect width="210px" height="64px" rx="8px" ry="8px" fill="rgba(0,0,0,0.6)" />',
            '<text x="12px" y="17px" font-family="monospace" font-size="12px" fill="rgba(255,255,255,0.6)">Allocator: </text>',
            _makeWrappable(allocatorName, "190px", "40px"),
            "</g>",
            // Resource lock tag
            '<g style="transform:translate(260px, 212px)">',
            '<rect width="210px" height="26px" rx="8px" ry="8px" fill="rgba(0,0,0,0.6)" />',
            '<text x="12px" y="17px" font-family="monospace" font-size="12px" fill="white">',
            '<tspan fill="rgba(255,255,255,0.6)">Scope: </tspan>',
            scope,
            "</text>",
            "</g>",
            // Bottom row (Origin Chain)
            "<g>",
            '<text x="50%" y="260px" font-family="monospace" font-size="12px" fill="white" text-anchor="middle" filter="url(#ts)">',
            '<tspan fill="rgba(255,255,255,0.6)">Origin Chain: </tspan>',
            LibString.toString(block.chainid),
            "</text>",
            "</g>"
        );

        return string.concat(iconSvg, detailBoxesSvg);
    }

    /**
     * @notice Internal pure function for formatting a metadata attribute as a JSON string.
     * @param trait      The trait name.
     * @param value      The trait value.
     * @param terminal   Whether this is the last attribute in the list.
     * @param quoted     Whether the value should be quoted.
     * @return attribute The formatted attribute string.
     */
    function _makeAttribute(string memory trait, string memory value, bool terminal, bool quoted)
        internal
        pure
        returns (string memory attribute)
    {
        string memory maybeQuote = quoted ? '"' : "";
        string memory terminator = terminal ? "" : ",";
        attribute =
            string.concat('{"trait_type": "', trait, '", "value": ', maybeQuote, value, maybeQuote, "}", terminator);
    }

    /**
     * @notice Wraps text in a foreignObject element to allow for text wrapping.
     * @param text The text to wrap.
     * @param width The width of the foreignObject.
     * @param height The height of the foreignObject.
     * @return The wrapped text.
     */
    function _makeWrappable(string memory text, string memory width, string memory height)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            '<foreignObject x="12px" y="22px" width="',
            width,
            '" height="',
            height,
            '">',
            '<span xmlns="http://www.w3.org/1999/xhtml" style="font-family: monospace;font-size: 14px;color: white;">',
            text,
            "</span>",
            "</foreignObject>"
        );
    }

    /**
     * @notice Try to read the name from the allocator contract.
     * @param allocatorAddress The address of the allocator.
     * @return The name of the allocator or "Unnamed Allocator" if not readable.
     */
    function _tryReadAllocatorName(address allocatorAddress) internal view returns (string memory) {
        string memory name = allocatorAddress.readName();
        if (bytes(name).length == 0) {
            name = "Unnamed Allocator";
        }
        return name;
    }

    /**
     * @notice Internal view function for retrieving a token's name with a fallback value.
     * @param token The address of the token.
     * @return name The token's name or a default value if not available.
     */
    function readNameWithDefaultValue(address token) internal view returns (string memory name) {
        // NOTE: this will not be the correct name on many chains, should we use a chain id -> name mapping?
        if (token == address(0)) {
            return "Native Token";
        }

        name = token.readName();
        if (bytes(name).length == 0) {
            name = "Unknown Token";
        }
    }

    /**
     * @notice Internal view function for retrieving a token's symbol with a fallback value.
     * @param token   The address of the token.
     * @return symbol The token's symbol or a default value if not available.
     */
    function readSymbolWithDefaultValue(address token) internal view returns (string memory symbol) {
        // NOTE: returning the correct symbol on many chains requires a chain id -> symbol mapping
        // which is not currently implemented; current default set to ETH
        if (token.isNullAddress()) {
            return "ETH";
        }

        symbol = token.readSymbol();
        if (bytes(symbol).length == 0) {
            symbol = "???";
        }
    }

    /**
     * @notice Internal view function for retrieving a token's decimals as a uint8 with a fallback value.
     * @param token     The address of the token.
     * @return decimals The token's decimals as a uint8 or a default value if not available.
     */
    function readDecimalsAsUint8WithDefaultValue(address token) internal view returns (uint8 decimals) {
        if (token.isNullAddress()) {
            return 18;
        }
        decimals = token.readDecimals();
    }

    /**
     * @notice Internal pure function for generating a lock tag from a lock.
     * @param lock The lock.
     * @return lockTag The lock tag.
     */
    function toLockTag(Lock memory lock) internal pure returns (bytes12) {
        uint96 allocatorId = lock.allocator.usingAllocatorId();
        return allocatorId.toLockTag(lock.scope, lock.resetPeriod);
    }

    /**
     * @notice Internal pure function for deriving a resource lock ID from lock details.
     * @param lock The lock.
     * @return id The ID.
     */
    function toId(Lock memory lock) internal pure returns (uint256 id) {
        id = (
            (lock.scope.asUint256() << 255) | (lock.resetPeriod.asUint256() << 252)
                | (lock.allocator.usingAllocatorId().asUint256() << 160) | lock.token.asUint256()
        );
    }
}
