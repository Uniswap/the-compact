import { loadFixture } from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre from "hardhat";
import {
  boolToHex,
  formatEther,
  hexToBool,
  keccak256,
  parseEther,
  toBytes,
  toHex,
  zeroAddress,
  zeroHash,
} from "viem";
import {
  getAllocatorId,
  getClaimHash,
  getClaimPayload,
  getLockTag,
  getRegistrationSlot,
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
      lockTag: lockTag,
      token: 0n,
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

    const claimEvents = await compactContract.getEvents.Claim({
      sponsor: sponsor.account.address,
      allocator: alwaysOKAllocator.address,
      arbiter: arbiter.account.address,
    });
    expect(
      claimEvents.length > 0,
      "Claim event not found or has incorrect parameters."
    ).to.be.true;

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

  it("should process a simple claim with no witness", async function () {
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
      lockTag: BigInt(lockTag),
      token: 0n,
      amount: depositAmount,
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

    const claimEvents = await compactContract.getEvents.Claim({
      sponsor: sponsor.account.address,
      allocator: alwaysOKAllocator.address,
      arbiter: arbiter.account.address,
    });
    expect(
      claimEvents.length > 0,
      "Claim event not found or has incorrect parameters."
    ).to.be.true;

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

  it("should process a claim with a registered compact", async function () {
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
    const compactData = {
      arbiter: arbiter.account.address,
      sponsor: sponsor.account.address,
      nonce: 0n,
      expires: BigInt(Math.floor(Date.now() / 1000) + 600 + 60), // 11 minutes from now
      id: tokenId,
      lockTag: lockTag,
      token: 0n,
      amount: depositAmount,
    };

    const claimHash = getClaimHash(compactData);
    const typehash = keccak256(
      toBytes(
        "Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address token,uint256 amount)"
      )
    );

    // 1. Sponsor deposits native tokens
    await compactContract.write.depositNativeAndRegister(
      [toHex(lockTag), claimHash, typehash],
      {
        account: sponsor.account,
        value: depositAmount,
      }
    );

    const calculatedSlot = getRegistrationSlot(
      sponsorAddress,
      claimHash,
      typehash
    );
    expect(await compactContract.read.extsload([calculatedSlot])).to.equal(
      boolToHex(true, { size: 32 })
    );

    const isRegistered = await compactContract.read.isRegistered([
      sponsorAddress,
      claimHash,
      typehash,
    ]);
    expect(isRegistered, "Compact should be registered after deposit").to.be
      .true;

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

    const sponsorSignature = await getSignedCompact(
      compactContract.address,
      sponsor.account.address,
      compactData
    );

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

    const claimEvents = await compactContract.getEvents.Claim({
      sponsor: sponsor.account.address,
      allocator: alwaysOKAllocator.address,
      arbiter: arbiter.account.address,
    });
    expect(
      claimEvents.length === 1,
      "Claim event not found or has incorrect parameters."
    ).to.be.true;

    expect(claimEvents[0].args.claimHash, "Claim hash should match registered claim hash").to.equal(
      claimHash
    );

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

    const storageSlot = await compactContract.read.extsload([calculatedSlot]);
    expect(storageSlot, "Storage slot should be 0 after claim").to.equal(
      boolToHex(false, { size: 32 })
    );

    const isRegisteredAfterClaim = await compactContract.read.isRegistered([
      sponsorAddress,
      claimHash,
      typehash,
    ]);
    expect(isRegisteredAfterClaim, "Compact should be unregistered after claim")
      .to.be.false;
  });
});
