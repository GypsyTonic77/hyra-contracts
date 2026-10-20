import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("HyraTimelock proxy-admin validation regressions", function () {
  async function deployTimelock() {
    const signers = await ethers.getSigners();
    const [admin, proposer, executor] = signers;
    const proxyAdmin = signers[signers.length - 1];

    const factory = await ethers.getContractFactory("HyraTimelock");
    const implementation = await factory.deploy();
    await implementation.waitForDeployment();
    const initData = factory.interface.encodeFunctionData("initialize", [
      0,
      [proposer.address],
      [executor.address],
      admin.address,
    ]);
    const proxyFactory = await ethers.getContractFactory("HyraTransparentUpgradeableProxy");
    const proxy = await proxyFactory.deploy(
      await implementation.getAddress(),
      proxyAdmin.address,
      initData,
    );
    await proxy.waitForDeployment();

    const target = await (await ethers.getContractFactory("MultiSigRoleManager")).deploy();
    await target.waitForDeployment();
    const newImplementation = await (await ethers.getContractFactory("ProxyAdminValidator")).deploy();
    await newImplementation.waitForDeployment();

    return {
      timelock: factory.attach(await proxy.getAddress()),
      proposer,
      executor,
      proxyAdmin,
      target,
      newImplementation,
    };
  }

  async function scheduleAndWait(ctx: Awaited<ReturnType<typeof deployTimelock>>) {
    await ctx.timelock.connect(ctx.proposer).scheduleUpgrade(
      await ctx.target.getAddress(),
      await ctx.newImplementation.getAddress(),
      "0x",
      false,
    );
    await time.increase(7 * 24 * 60 * 60 + 1);
  }

  it("rejects executeUpgrade when the validator is unset", async function () {
    const ctx = await deployTimelock();
    await scheduleAndWait(ctx);
    await expect(
      ctx.timelock.connect(ctx.executor).executeUpgrade(
        ctx.proxyAdmin.address,
        await ctx.target.getAddress(),
      ),
    ).to.be.revertedWithCustomError(ctx.timelock, "InvalidProxyAdmin");
  });

  it("rejects executeUpgradeWithCall when the validator is unset", async function () {
    const ctx = await deployTimelock();
    await scheduleAndWait(ctx);
    await expect(
      ctx.timelock.connect(ctx.executor).executeUpgradeWithCall(
        ctx.proxyAdmin.address,
        await ctx.target.getAddress(),
        "0x",
      ),
    ).to.be.revertedWithCustomError(ctx.timelock, "InvalidProxyAdmin");
  });
});
