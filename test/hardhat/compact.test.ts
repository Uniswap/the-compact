import { loadFixture } from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre from "hardhat";
import { formatEther, parseEther, toHex, zeroAddress } from "viem";
import {
  getAllocatorId,
  getClaimPayload,
  getLockTag,
  getSignedCompact,
  getTokenId,
} from "./helpers";

describe("Compact Protocol E2E", function () {
  async function deployCompactFixture() {
    const [deployer, sponsor, arbiter, filler] =
      await hre.viem.getWalletClients();
    const compactContract = await hre.viem.deployContract("TheCompact", []);

    // Deploy and register AlwaysOKAllocator
    const alwaysOKAllocator = await hre.viem.deployContract(
      "AlwaysOKAllocator",
      []
    );
    await compactContract.write.__registerAllocator(
      [alwaysOKAllocator.address, "0x"],
      { account: deployer.account }
    );

    // Deploy mock tokens
    const mockToken1 = await hre.viem.deployContract("BasicERC20Token", [
      "Mock Token 1",
      "MOCK1",
      18,
    ]);
    const mockToken2 = await hre.viem.deployContract("BasicERC20Token", [
      "Mock Token 2",
      "MOCK2",
      18,
    ]);

    // Mint tokens and approve the protocol
    for (const token of [mockToken1, mockToken2]) {
      const mintAmount = parseEther("100");
      await token.write.mint([sponsor.account.address, mintAmount]);
      await token.write.approve([compactContract.address, mintAmount], {
        account: sponsor.account,
      });
    }

    const publicClient = await hre.viem.getPublicClient();

    return {
      compactContract,
      alwaysOKAllocator,
      mockToken1,
      mockToken2,
      deployer,
      sponsor,
      arbiter,
      filler,
      publicClient,
    };
  }

  it("should deploy the protocol", async function () {
    const { compactContract } = await loadFixture(deployCompactFixture);
    expect(await compactContract.read.name()).to.equal("The Compact");
  });

  it("should process a simple claim", async function () {
    const {
      compactContract,
      alwaysOKAllocator,
      sponsor,
      arbiter,
      filler,
      publicClient,
    } = await loadFixture(deployCompactFixture);

    const sponsorAddress = sponsor.account.address;
    const scope = 0n; // Scope.Multichain
    const resetPeriod = 3n; // ResetPeriod.TenMinutes
    const depositAmount = parseEther("1.0"); // 1 ETH
    const allocatorId = getAllocatorId(alwaysOKAllocator.address);
    const lockTag = getLockTag(allocatorId, scope, resetPeriod);
    const tokenId = getTokenId(lockTag, 0n);

    // 1. Sponsor deposits native tokens
    await compactContract.write.depositNative(
      [toHex(lockTag), sponsorAddress],
      {
        account: sponsor.account,
        value: depositAmount,
      }
    );

    const transferEvents = await compactContract.getEvents.Transfer({
      from: zeroAddress,
      to: sponsorAddress,
      id: tokenId,
    });
    expect(
      transferEvents.length > 0,
      "ERC6909 Transfer event for depositNative not found or has incorrect parameters."
    ).to.be.true;
    expect(
      await compactContract.read.balanceOf([sponsorAddress, tokenId]),
      `Sponsor should have ${formatEther(depositAmount)} tokens in the lock`
    ).to.equal(depositAmount);

    // 2. Sponsor creates a compact
    const compactData = {
      arbiter: arbiter.account.address,
      sponsor: sponsor.account.address,
      nonce: 0n,
      expires: BigInt(Math.floor(Date.now() / 1000) + 600 + 60), // 11 minutes from now
      id: tokenId,
      amount: depositAmount,
      mandate: {
        witnessArgument: 42n,
      },
    };

    const sponsorSignature = await getSignedCompact(
      compactContract.address,
      sponsor.account.address,
      compactData
    );

    // 3. Arbiter submits a claim
    const claimPayload = getClaimPayload(compactData, sponsorSignature, [
      {
        lockTag: 0n, // withdraw underlying
        claimant: filler.account.address,
        amount: compactData.amount,
      },
    ]);

    const fillerBalanceBefore = await publicClient.getBalance({
      address: filler.account.address,
    });
    const contractBalanceBefore = await publicClient.getBalance({
      address: compactContract.address,
    });

    await compactContract.write.claim([claimPayload], {
      account: arbiter.account,
    });

    // TODO: fix the claim event signature in the contract
    // const claimEvents = await compactContract.getEvents.Claim({
    //   sponsor: sponsor.account.address,
    //   allocator: alwaysOKAllocatorAddress,
    //   arbiter: arbiter.account.address,
    // });
    // expect(
    //   claimEvents.length > 0,
    //   "Claim event not found or has incorrect parameters."
    // ).to.be.true;

    const fillerBalanceAfter = await publicClient.getBalance({
      address: filler.account.address,
    });
    expect(fillerBalanceAfter).to.equal(
      fillerBalanceBefore + compactData.amount
    );

    const contractBalanceAfter = await publicClient.getBalance({
      address: compactContract.address,
    });
    expect(contractBalanceAfter).to.equal(
      contractBalanceBefore - compactData.amount
    );

    const sponsorLockBalanceAfterClaim = await compactContract.read.balanceOf([
      sponsorAddress,
      tokenId,
    ]);
    expect(
      sponsorLockBalanceAfterClaim,
      "Sponsor should have 0 tokens in the lock"
    ).to.equal(0n);
  });
});
