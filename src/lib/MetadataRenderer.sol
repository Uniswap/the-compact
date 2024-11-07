// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { EfficiencyLib } from "./EfficiencyLib.sol";
import { MetadataLib } from "./MetadataLib.sol";
import { Lock } from "../types/Lock.sol";

/**
 * @title MetadataRenderer
 * @notice Deployed contract implementing functionality for deriving and displaying
 * ERC6909 metadata as well as metadata specific to various underlying tokens.
 */
contract MetadataRenderer {
    using EfficiencyLib for uint256;
    using MetadataLib for Lock;
    using MetadataLib for address;

    /**
     * @notice External view function for generating the URI for a resource lock's ERC6909
     * token. The URI is derived from the lock's details and token identifier.
     * @param lock The Lock struct containing the resource lock's details.
     * @param id   The ERC6909 token identifier.
     * @return     The generated URI string.
     */
    function uri(Lock memory lock, uint256 id) external view returns (string memory) {
        return lock.toURI(id);
    }

    /**
     * @notice External view function for generating the name of an ERC6909 token. Combines
     * "Compact" with the underlying token's name, falling back to a default if needed.
     * @param id The ERC6909 token identifier.
     * @return   The generated name string.
     */
    function name(uint256 id) external view returns (string memory) {
        return string.concat("Compact ", id.asSanitizedAddress().readNameWithDefaultValue());
    }

    /**
     * @notice External view function for generating the symbol of an ERC6909 token. Combines
     * a handshake emoji with the underlying token's symbol, falling back to a default if
     * needed.
     * @param id The ERC6909 token identifier.
     * @return   The generated symbol string.
     */
    function symbol(uint256 id) external view returns (string memory) {
        return string.concat(unicode"🤝-", id.asSanitizedAddress().readSymbolWithDefaultValue());
    }
}
