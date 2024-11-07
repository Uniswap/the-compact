// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Lock } from "../types/Lock.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";
import { IdLib } from "./IdLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { LibString } from "solady/utils/LibString.sol";
import { MetadataReaderLib } from "solady/utils/MetadataReaderLib.sol";

/**
 * @title MetadataLib
 * @notice Libray contract implementing logic for deriving and displaying
 * ERC6909 metadata as well as metadata specific to various underlying tokens.
 */
library MetadataLib {
    using MetadataLib for address;
    using MetadataLib for string;
    using IdLib for Lock;
    using IdLib for ResetPeriod;
    using EfficiencyLib for address;
    using LibString for uint256;
    using LibString for address;
    using MetadataReaderLib for address;
    using MetadataLib for ResetPeriod;
    using MetadataLib for Scope;

    function toString(ResetPeriod resetPeriod) internal pure returns (string memory) {
        if (resetPeriod == ResetPeriod.OneSecond) {
            return "One second";
        } else if (resetPeriod == ResetPeriod.FifteenSeconds) {
            return "Fifteen seconds";
        } else if (resetPeriod == ResetPeriod.OneMinute) {
            return "One minute";
        } else if (resetPeriod == ResetPeriod.TenMinutes) {
            return "Ten minutes";
        } else if (resetPeriod == ResetPeriod.OneHourAndFiveMinutes) {
            return "One hour and five minutes";
        } else if (resetPeriod == ResetPeriod.OneDay) {
            return "One day";
        } else if (resetPeriod == ResetPeriod.SevenDaysAndOneHour) {
            return "Seven days and one hour";
        } else if (resetPeriod == ResetPeriod.ThirtyDays) {
            return "Thirty days";
        } else {
            revert("Unknown reset period");
        }
    }

    function toString(Scope scope) internal pure returns (string memory) {
        if (scope == Scope.Multichain) {
            return "Multichain";
        } else if (scope == Scope.ChainSpecific) {
            return "Chain-specific";
        } else {
            revert("Unknown scope");
        }
    }

    function toURI(Lock memory lock, uint256 id) internal view returns (string memory uri) {
        string memory tokenAddress = lock.token.isNullAddress() ? "Native Token" : lock.token.toHexStringChecksummed();
        string memory allocator = lock.allocator.toHexStringChecksummed();
        string memory resetPeriod = lock.resetPeriod.toString();
        string memory scope = lock.scope.toString();
        string memory tokenName = lock.token.readNameWithDefaultValue();
        string memory tokenSymbol = lock.token.readSymbolWithDefaultValue();
        string memory tokenDecimals = uint256(lock.token.readDecimals()).toString();

        string memory name = string.concat("{\"name\": \"Compact ", tokenSymbol, "\",");
        string memory description = string.concat("\"description\": \"Compact ", tokenName, " (", tokenAddress, ") resource lock with allocator ", allocator, " and reset period of ", resetPeriod, "\",");
        string memory attributes = string.concat(
            "\"attributes\": [",
            toAttributeString("ID", id.toString(), false),
            toAttributeString("Token Address", tokenAddress, false),
            toAttributeString("Token Name", tokenName, false),
            toAttributeString("Token Symbol", tokenSymbol, false),
            toAttributeString("Token Decimals", tokenDecimals, false),
            toAttributeString("Allocator", allocator, false),
            toAttributeString("Scope", scope, false),
            toAttributeString("Reset Period", resetPeriod, true),
            "]}"
        );

        // Note: this just returns a default image; replace with a dynamic image based on attributes
        string memory image =
            "\"image\": \"data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pg0KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDIzLjAuNSwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPg0KPHN2ZyB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4Ig0KCSB2aWV3Qm94PSIwIDAgNDkyIDQ5MiIgc3R5bGU9ImVuYWJsZS1iYWNrZ3JvdW5kOm5ldyAwIDAgNDkyIDQ5MjsiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPGcgaWQ9Ik1hc3Rlcl9MYXllcl8yIj4NCjwvZz4NCjxnIGlkPSJMYXllcl8xIj4NCgk8Zz4NCgkJPGc+DQoJCQk8Zz4NCgkJCQk8Zz4NCgkJCQkJPHBhdGggc3R5bGU9ImZpbGwtcnVsZTpldmVub2RkO2NsaXAtcnVsZTpldmVub2RkO2ZpbGw6IzIxMjEyMTsiIGQ9Ik0zMjEuMzA4LDI5NC44NjRjNS4zNTIsNS4zMjgsOS40NTYsMTIuMTQ0LDE1Ljc5Miw4LjgzMg0KCQkJCQkJYzIuNDQ4LTEuMjcyLDUuMDY0LTMuMDk2LDcuMzItNS4yNTZjMy43NDQtMy41NzYsOC4yNTYtOS41MjgsNC42NTYtMTQuMjhjLTEyLjQ1Ni0xMS45NzYtMzYuMzg0LTMyLjExMi0zNi40NTYtMzIuMTYNCgkJCQkJCWw3LjU2LTguNTY4YzAuMDI0LDAuMDI0LDUuMTYsNC41MzYsMTEuODMyLDEwLjgyNGM4LjY4OCw4LjIwOCwyMC44NTYsMTYuMiwyNi43MzYsMjQuNDA4DQoJCQkJCQljMy4zMTIsNC42MDgsMi42MTYsMTIuNzQ0LDAuODY0LDE3LjUyYy0xLjM5MiwzLjg0LTQuMTA0LDcuNDY0LTcuMzIsMTAuNTM2Yy0zLjAyNCwyLjkwNC02LjYsNS40LTkuOTYsNy4xMjgNCgkJCQkJCWMtMy4zODQsMS43NTItNi43OTIsMi43Ni05LjY5NiwyLjc4NGMtMC4wOTYsMC40NTYtMC4yMTYsMC45MzYtMC4zMzYsMS4zOTJjLTAuOTYsMy4yNC0zLjAyNCw2LjA3Mi01LjYxNiw4LjQNCgkJCQkJCWMtMi4zMjgsMi4wODgtNS4xMzYsMy44MTYtNy45NDQsNS4wNjRjLTMuMDcyLDEuMzQ0LTYuMjg4LDIuMTEyLTkuMTY4LDIuMTZjLTAuMDk2LDAuOTM2LTAuMjg4LDEuODQ4LTAuNTUyLDIuNzYNCgkJCQkJCWMtMC45NiwzLjI0LTMuMDI0LDYuMDcyLTUuNjE2LDguNGMtMi4zMjgsMi4wODgtNS4xMzYsMy44MTYtNy45NDQsNS4wNjRjLTQuMTI4LDEuODI0LTguNTQ0LDIuNTY4LTEyLDEuOTY4DQoJCQkJCQljLTAuMTIsMS4yMjQtMC4zNiwyLjQtMC42OTYsMy41MDR2MC4wMjRjLTEuMDMyLDMuMzg0LTMsNi4yNC01LjUyLDguMzUyYy0yLjUyLDIuMTEyLTUuNTkyLDMuNDgtOC44NTYsMy45MzYNCgkJCQkJCWMtMy45NiwwLjU1Mi04LjE2LTAuMjQtMTEuOTA0LTIuNjg4Yy0xLjAzMi0wLjY3Mi0yLjE2LTEuNTM2LTMuNDgtMi41OTJsLTAuNzQ0LTAuNTc2bC0xMS4xNi04LjYxNmw2Ljk2LTkuMDI0bDExLjE2LDguNjE2DQoJCQkJCQlsMC43NDQsMC41NzZjMS4wMzIsMC43OTIsMS44OTYsMS40ODgsMi43ODQsMi4wNGMxLjI5NiwwLjg2NCwyLjczNiwxLjEyOCw0LjA4LDAuOTZjMS4xMjgtMC4xNjgsMi4xODQtMC42NDgsMy4wNzItMS4zOTINCgkJCQkJCWMwLjg2NC0wLjcyLDEuNTYtMS43MjgsMS45Mi0yLjkwNGwwLDBjMC40NTYtMS41NiwwLjM4NC0zLjUwNC0wLjQ1Ni01Ljc2Yy05LjUyOC0xMy4yOTYtMjkuNDQ4LTI5LjQyNC0yOS40OTYtMjkuNDcyDQoJCQkJCQlsNy4yLTguODU2YzAuMDQ4LDAuMDI0LDguMTEyLDYuNTc2LDE2Ljc1MiwxNS4wMjRjMi4zMDQsMi4yNTYsNC44NDgsNC43NTIsNy41MTIsNy4xMjhjMC40OCwwLjQzMiwwLjk4NCwwLjg2NCwxLjQ2NCwxLjI5Ng0KCQkJCQkJbDAsMGwwLDBjMC4wOTYsMC4wOTYsMC4yMTYsMC4xOTIsMC4zMTIsMC4yODhjMC42MjQsMC41NTIsMS4yNDgsMS4xMjgsMS44NzIsMS43MDRjMi4xMTIsMS44OTYsNC4yLDMuODE2LDYuMzg0LDUuNDk2DQoJCQkJCQljMi41OTIsMS44NDgsMi41NDQsMi4yMzIsNS40OTYsMS4zNDRjMC42MjQtMC4xOTIsMS4yOTYtMC41MjgsMi4wMTYtMC44NGMxLjc3Ni0wLjc2OCwzLjUwNC0xLjg0OCw0Ljg5Ni0zLjA5Ng0KCQkJCQkJYzEuMTI4LTEuMDMyLDEuOTkyLTIuMTEyLDIuMzA0LTMuMTY4YzAuMjQtMC44NCwwLjA3Mi0xLjg0OC0wLjc0NC0yLjk3NmMtOS41NzYtMTMuMzItMzUuOTA0LTM2LjQ1Ni0zNS45NzYtMzYuNTI4bDcuNTYtOC41NjgNCgkJCQkJCWMwLjA0OCwwLjA0OCwxNC42ODgsMTIuOTEyLDI2LjYxNiwyNS40ODhjMy4yNCwzLjE5Miw4LjA2NCw3LjU2LDExLjU0NCwxMC4yNzJjMS4yNzIsMC45MTIsMi4xNiwyLjA4OCw0LjA4LDEuNDE2DQoJCQkJCQljMC44MTYtMC4yODgsMS44NDgtMC42OTYsMy0xLjJjMS43NzYtMC43NjgsMy41MDQtMS44NDgsNC44OTYtMy4wOTZjMS4xMjgtMS4wMDgsMS45OTItMi4xMTIsMi4zMDQtMy4xNjgNCgkJCQkJCWMwLjI0LTAuODQsMC4wNzItMS44NDgtMC43NDQtM2MtOS41NzYtMTMuMzItMzUuOTA0LTM2LjQ1Ni0zNS45NzYtMzYuNTI4bDcuNTYtOC41NjgNCgkJCQkJCUMyOTIuMjIsMjY2LjY4OCwzMDkuMDQ0LDI4MS40OTYsMzIxLjMwOCwyOTQuODY0eiIvPg0KCQkJCTwvZz4NCgkJCQk8Zz4NCgkJCQkJPHBhdGggc3R5bGU9ImZpbGwtcnVsZTpldmVub2RkO2NsaXAtcnVsZTpldmVub2RkO2ZpbGw6IzIxMjEyMTsiIGQ9Ik00MjkuMDIsMjU0LjQyNEwzOTMuNjkyLDEyOS43MmwtMS41MzYtNS40NDhsLTUuNDQ4LDEuNDg4DQoJCQkJCQlsLTQ1LjIxNiwxMi40MDhsLTUuNTY4LDEuNTM2bDEuNTYsNS41MmwyLjEzNiw3LjUzNmMtMjEuNjk2LDEuOTY4LTQyLjg0LTIuNjY0LTYyLjU2OC02Ljk2DQoJCQkJCQljLTM5LjI2NC04LjU2OC03My4yOTYtMTUuOTg0LTk5LjU3NiwyNS44OTZsMCwwYy03LjEwNCwxMS4zNTItMTQuODU2LDI0Ljg0LTE2LjY1NiwzNS4xNg0KCQkJCQkJYy0yLjQ3MiwxNC4wNCwzLjAyNCwyMy4wNCwyNS4yNDgsMTguOTZjMTMuNjU2LTIuNDk2LDIyLjA4LTkuMzYsMjkuOTI4LTE1Ljc2OGM4Ljg4LTcuMjQ4LDE2Ljg3Mi0xMy43NTIsMzIuMzc2LTkuMTQ0DQoJCQkJCQljOC4xMzYsMy4zNiw4Ljg4LDMuNjcyLDE1LjI0LDkuMDI0YzIxLjE0NCwxNy43MzYsNzEuNCw2MS41MzYsNzIsNjIuMDRsMCwwbDEwLjQxNiw5LjE2OGwyLjkwNCwyLjU0NGwzLjQzMi0xLjc1Mg0KCQkJCQkJbDIwLjg4LTEwLjYwOGwxLjI3Miw0LjQ4OGw1LjQ3Mi0xLjU2bDQ1LjA5Ni0xMi43NjhsNS40OTYtMS41Nkw0MjkuMDIsMjU0LjQyNEw0MjkuMDIsMjU0LjQyNHogTTM1MC42MzYsMjY5Ljk3NmwtNy41MTItNi42DQoJCQkJCQlIMzQzLjFjLTAuMTQ0LTAuMTItNTEuNjI0LTQ1LTcyLjE5Mi02Mi4yMzJjLTcuNzA0LTYuNDU2LTguNTY4LTYuODE2LTE4LjM2LTEwLjg3MmwtMC4yNC0wLjA5NmwtMC41MjgtMC4xOTINCgkJCQkJCWMtMjEuMzYtNi40NTYtMzEuNjA4LDEuOTItNDIuOTg0LDExLjIwOGMtNi43NjgsNS41Mi0xMy45OTIsMTEuNDI0LTI0Ljc2OCwxMy4zOTJjLTEwLjA4LDEuODQ4LTEyLjc2OC0xLjAzMi0xMS45MjgtNS43ODQNCgkJCQkJCWMxLjQ4OC04LjQ3Miw4LjU0NC0yMC42NjQsMTUuMDQ4LTMxLjA1NnYtMC4wMjRjMjEuOTYtMzUuMDY0LDUyLjM5Mi0yOC40NCw4Ny40OC0yMC43ODQNCgkJCQkJCWMyMS4xOTIsNC42MDgsNDMuOTQ0LDkuNTc2LDY4LjE2LDYuOTM2bDI3LjI2NCw5Ni4yNEwzNTAuNjM2LDI2OS45NzZMMzUwLjYzNiwyNjkuOTc2eiBNMzgyLjM2NCwyNjEuNjk2TDM1MC4wNiwxNDcuNjI1DQoJCQkJCQlsMzQuMi05LjM4NGwzMi4yMzIsMTEzLjc4NEwzODIuMzY0LDI2MS42OTZ6Ii8+DQoJCQkJPC9nPg0KCQkJCTxnPg0KCQkJCQk8cGF0aCBzdHlsZT0iZmlsbC1ydWxlOmV2ZW5vZGQ7Y2xpcC1ydWxlOmV2ZW5vZGQ7ZmlsbDojMjEyMTIxOyIgZD0iTTE1NS4wMTMsMTQ1LjJsLTIuMjgsOC4wMTYNCgkJCQkJCWMxMC4yMjQsMC4yMTYsMjkuNTkyLDAuMDQ4LDQ1LjcyLTMuNmwyLjQ5NiwxMS4xMzZjLTE4Ljk2LDQuMjk2LTQxLjgwOCw0LjEwNC01MS40MDgsMy43OTJsLTI1LjQ4OCw4OS45NzYNCgkJCQkJCWM5LjY3MiwzLjA0OCwyNy44ODgsMTAuOTY4LDI5LjM1MiwyNy43MmwtMTEuNCwwLjk4NGMtMC44ODgtMTAuMTUyLTEzLjcyOC0xNS41MDQtMjEuMDcyLTE3Ljc2bC0xLjM2OCw0LjgyNGwtMS41Niw1LjQ5Ng0KCQkJCQkJbC01LjQ3Mi0xLjU2bC00NS4wOTYtMTIuNzY4bC01LjQ5Ni0xLjU2bDEuNTYtNS40NzJsMzUuMzI4LTEyNC43MDRsMS41MzYtNS40NDhsNS40NDgsMS40ODhsNDUuMjE2LDEyLjQwOGw1LjU2OCwxLjUzNg0KCQkJCQkJTDE1NS4wMTMsMTQ1LjJMMTU1LjAxMywxNDUuMkwxNTUuMDEzLDE0NS4yeiBNMTEwLjE1NywyNjEuNjk2bDMyLjMwNC0xMTQuMDcybC0zNC4yLTkuMzg0TDc2LjAyOSwyNTIuMDI0TDExMC4xNTcsMjYxLjY5NnoiLz4NCgkJCQk8L2c+DQoJCQkJPGc+DQoJCQkJCTxwYXRoIHN0eWxlPSJmaWxsLXJ1bGU6ZXZlbm9kZDtjbGlwLXJ1bGU6ZXZlbm9kZDtmaWxsOiMyMTIxMjE7IiBkPSJNMjQwLjc2NCwzMzYuNjcyTDI0MC43NjQsMzM2LjY3Mg0KCQkJCQkJYy0xLjEwNC0wLjgxNi0yLjQ0OC0xLjA4LTMuNzQ0LTAuODg4cy0yLjQ5NiwwLjg2NC0zLjMxMiwxLjk0NGwtOC44MzIsMTEuOTc2aDAuMDI0Yy0wLjgxNiwxLjEwNC0xLjEwNCwyLjQ3Mi0wLjkxMiwzLjc0NA0KCQkJCQkJYzAuMTkyLDEuMjcyLDAuODY0LDIuNDcyLDEuOTQ0LDMuMjg4bDAuMTY4LDAuMTQ0YzEuMDU2LDAuNzIsMi4zNTIsMC45NiwzLjU3NiwwLjc2OGMxLjI5Ni0wLjE5MiwyLjQ5Ni0wLjg2NCwzLjMxMi0xLjk0NA0KCQkJCQkJbDguODU2LTEyYzAuODE2LTEuMTA0LDEuMDgtMi40NDgsMC44ODgtMy43NDRDMjQyLjUxNiwzMzguNjg4LDI0MS44NDQsMzM3LjQ4OCwyNDAuNzY0LDMzNi42NzJMMjQwLjc2NCwzMzYuNjcyDQoJCQkJCQlMMjQwLjc2NCwzMzYuNjcyeiBNMTc2LjQyMSwyNjYuMjhjNC4yMjQsMy4xMiw2LjgxNiw3LjY4LDcuNTM2LDEyLjUwNGMwLjMxMiwyLjA2NCwwLjI4OCw0LjE3Ni0wLjA5Niw2LjI0DQoJCQkJCQljMS44OTYtMC45NiwzLjkzNi0xLjYwOCw2LjAyNC0xLjkyYzUuMDE2LTAuNzQ0LDEwLjI5NiwwLjM4NCwxNC42ODgsMy42MjR2MC4wMjRjNC40MTYsMy4yNCw3LjA4LDcuOTY4LDcuODI0LDEyLjk4NA0KCQkJCQkJYzAuMzEyLDEuOTkyLDAuMjg4LDQuMDMyLTAuMDI0LDYuMDQ4YzAuNi0wLjE0NCwxLjE3Ni0wLjI2NCwxLjc3Ni0wLjM2YzQuNTM2LTAuNjcyLDkuMzM2LDAuMzYsMTMuMjk2LDMuMjg4bDAuMjg4LDAuMjQNCgkJCQkJCWMzLjgxNiwyLjkyOCw2LjE0NCw3LjEyOCw2LjgxNiwxMS41MmMwLjIxNiwxLjM2OCwwLjI2NCwyLjc2LDAuMTQ0LDQuMTUyYzAuMjE2LTAuMDQ4LDAuNDA4LTAuMDcyLDAuNjI0LTAuMDk2DQoJCQkJCQljNC4xMjgtMC42MjQsOC41NDQsMC4zMzYsMTIuMTkyLDMuMDI0bDAsMGMzLjY3MiwyLjcxMiw1Ljg4LDYuNjI0LDYuNTA0LDEwLjc3NmMwLjYyNCw0LjEyOC0wLjMzNiw4LjU0NC0zLjA0OCwxMi4xOTINCgkJCQkJCWwtOC44NTYsMTJjLTIuNzEyLDMuNjcyLTYuNjI0LDUuODgtMTAuNzc2LDYuNTA0Yy00LjEyOCwwLjYyNC04LjUyLTAuMzM2LTEyLjE5Mi0zLjAyNHYwLjAyNA0KCQkJCQkJYy0zLjY0OC0yLjY4OC01Ljg4LTYuNjI0LTYuNTA0LTEwLjhjLTAuMDcyLTAuNDgtMC4xMi0wLjk2LTAuMTQ0LTEuNDRjLTEuMDA4LDAuMzM2LTIuMDQsMC42LTMuMDcyLDAuNzQ0DQoJCQkJCQljLTQuNTEyLDAuNjcyLTkuMzEyLTAuMzYtMTMuMjk2LTMuMzEybDAsMGMtMy45ODQtMi45NTItNi40MDgtNy4yMjQtNy4wOC0xMS43MzZjLTAuMTQ0LTAuOTEyLTAuMjE2LTEuODI0LTAuMTkyLTIuNzYNCgkJCQkJCWMtMS41MTIsMC42MjQtMy4wNzIsMS4wOC00LjY4LDEuMzJjLTUuMDE2LDAuNzQ0LTEwLjI5Ni0wLjM4NC0xNC42ODgtMy42MjRsMCwwYy00LjM5Mi0zLjI0LTcuMDgtNy45OTItNy44MjQtMTMuMDA4DQoJCQkJCQljLTAuMzg0LTIuNDcyLTAuMjg4LTUuMDE2LDAuMzEyLTcuNDg4Yy0xLjU4NCwwLjcyLTMuMjY0LDEuMi00Ljk2OCwxLjQ2NGMtNC44MjQsMC43Mi05LjkxMi0wLjM4NC0xNC4xMzYtMy40OA0KCQkJCQkJYy00LjIyNC0zLjEyLTYuODE2LTcuNjgtNy41MzYtMTIuNTA0czAuMzg0LTkuOTEyLDMuNDgtMTQuMTM2aDAuMDI0bDEwLjk5Mi0xNC45MDRjMy4xMi00LjI0OCw3LjY4LTYuODE2LDEyLjQ4LTcuNTM2DQoJCQkJCQlDMTY3LjA4NSwyNjIuMDU2LDE3Mi4xNzMsMjYzLjE2LDE3Ni40MjEsMjY2LjI4TDE3Ni40MjEsMjY2LjI4TDE3Ni40MjEsMjY2LjI4TDE3Ni40MjEsMjY2LjI4eiBNMTcyLjY1MywyODAuNDY0DQoJCQkJCQljLTAuMjg4LTEuOTQ0LTEuMzItMy43NjgtMi45NzYtNC45OTJ2LTAuMDI0Yy0xLjY4LTEuMjI0LTMuNzItMS42NTYtNS42ODgtMS4zNjhjLTEuOTY4LDAuMjg4LTMuNzkyLDEuMzItNS4wMTYsMi45NzYNCgkJCQkJCWwtMTAuOTkyLDE0Ljg4aDAuMDI0Yy0xLjI0OCwxLjY4LTEuNjgsMy43NDQtMS4zOTIsNS42ODhjMC4yODgsMS45NDQsMS4zMiwzLjc2OCwyLjk3Niw0Ljk5Mg0KCQkJCQkJYzEuNjgsMS4yNDgsMy43NDQsMS42OCw1LjY4OCwxLjM5MnMzLjc2OC0xLjMyLDQuOTkyLTIuOTc2bDAuMDI0LDBsMTAuOTkyLTE0Ljg4aC0wLjAyNA0KCQkJCQkJQzE3Mi40ODUsMjg0LjQ3MiwxNzIuOTQxLDI4Mi40MDgsMTcyLjY1MywyODAuNDY0TDE3Mi42NTMsMjgwLjQ2NEwxNzIuNjUzLDI4MC40NjR6IE0yMDEuMDkyLDMwMS40MTYNCgkJCQkJCWMtMC4zMTItMi4xMzYtMS40NC00LjE1Mi0zLjI2NC01LjQ5NnYwLjAyNGMtMS44NDgtMS4zNjgtNC4xMDQtMS44NDgtNi4yNC0xLjUzNmMtMi4xNiwwLjMzNi00LjE1MiwxLjQ0LTUuNTIsMy4yNjQNCgkJCQkJCWwtMTEuNjE2LDE1Ljc0NGMtMS4zNDQsMS44NDgtMS44MjQsNC4xMDQtMS41MTIsNi4yNGMwLjMxMiwyLjEzNiwxLjQ0LDQuMTI4LDMuMjY0LDUuNDk2bDAsMA0KCQkJCQkJYzEuODQ4LDEuMzY4LDQuMTA0LDEuODQ4LDYuMjQsMS41MzZjMi4xNi0wLjMxMiw0LjE1Mi0xLjQ0LDUuNTItMy4yNjRsMCwwbDExLjYxNi0xNS43NDQNCgkJCQkJCUMyMDAuOTQ4LDMwNS44MzIsMjAxLjQyOCwzMDMuNTc2LDIwMS4wOTIsMzAxLjQxNkwyMDEuMDkyLDMwMS40MTZMMjAxLjA5MiwzMDEuNDE2eiBNMjIzLjI0NCwzMjIuMTUyDQoJCQkJCQljLTAuMjQtMS42OC0xLjEwNC0zLjI0LTIuNTItNC4yNzJ2MC4wMjRjLTEuNDQtMS4wNTYtMy4xOTItMS40NC00Ljg0OC0xLjE3NmMtMS42NTYsMC4yNC0zLjIxNiwxLjEwNC00LjI0OCwyLjU0NGwtMC4xOTIsMC4yNA0KCQkJCQkJbC05Ljg4OCwxMy40MTZ2MC4wMjRjLTEuMDU2LDEuNDE2LTEuNDE2LDMuMTY4LTEuMTUyLDQuODI0YzAuMjY0LDEuNjgsMS4xMjgsMy4yNCwyLjU0NCw0LjI3MmwwLDANCgkJCQkJCWMxLjQxNiwxLjA1NiwzLjE2OCwxLjQxNiw0Ljg0OCwxLjE1MmMxLjY4LTAuMjY0LDMuMjQtMS4xMjgsNC4yNzItMi41NDRMMjIyLjE0MSwzMjcNCgkJCQkJCUMyMjMuMTI0LDMyNS41ODQsMjIzLjUwOCwzMjMuODMyLDIyMy4yNDQsMzIyLjE1MnoiLz4NCgkJCQk8L2c+DQoJCQk8L2c+DQoJCTwvZz4NCgk8L2c+DQo8L2c+DQo8L3N2Zz4NCg==\",";

        uri = string.concat(name, description, image, attributes);
    }

    function readNameWithDefaultValue(address token) internal view returns (string memory name) {
        // NOTE: this will not take into account the correct symbol on many chains
        if (token == address(0)) {
            return "Ether";
        }

        name = token.readName();
        if (bytes(name).length == 0) {
            name = "unknown token";
        }
    }

    function readSymbolWithDefaultValue(address token) internal view returns (string memory symbol) {
        // NOTE: this will not take into account the correct symbol on many chains
        if (token.isNullAddress()) {
            return "ETH";
        }

        symbol = token.readSymbol();
        if (bytes(symbol).length == 0) {
            symbol = "???";
        }
    }

    function readDecimalsWithDefaultValue(address token) internal view returns (string memory decimals) {
        if (token.isNullAddress()) {
            return "18";
        }
        return uint256(token.readDecimals()).toString();
    }

    function toAttributeString(string memory trait, string memory value, bool terminal) internal pure returns (string memory attribute) {
        return string.concat("{\"trait_type\": \"", trait, "\", \"value\": \"", value, "\"}", terminal ? "" : ",");
    }
}
