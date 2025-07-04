import type { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox-viem";
import "@nomicfoundation/hardhat-foundry";
import "hardhat-gas-reporter";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      evmVersion: "cancun",
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 4_294_967_295,
      },
    },
  },
  gasReporter: {
    enabled: true,
    outputFile: "./snapshots/hardhat-gas-report.txt",
  },
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true,
      enableRip7212: true,
      enableTransientStorage: true,
      hardfork: "prague",
    },
  },
  paths: {
    sources: "./src",
    tests: "./test/hardhat",
    cache: "./cache/hardhat",
    artifacts: "./artifacts",
  },
};

export default config;
