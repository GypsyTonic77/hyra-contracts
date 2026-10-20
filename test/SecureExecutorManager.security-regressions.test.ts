import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("SecureExecutorManager security regressions", function () {
  async function deployManager() {
    const signers = await ethers.getSigners();
    const admin = signers[0];
    const executorA = signers[1];
    const executorB = signers[2];
    const proxyAdmin = signers[signers.length - 1];

    const factory = await ethers.getContractFactory("SecureExecutorManager");
    const implementation = await factory.deploy();
    await implementation.waitForDeployment();
    const initData = factory.interface.encodeFunctionData("initialize", [
      admin.address,
      [executorA.address, executorB.address],
    ]);
    const proxyFactory = await ethers.getContractFactory("HyraTransparentUpgradeableProxy");
    const proxy = await proxyFactory.deploy(
      await implementation.getAddress(),
      proxyAdmin.address,
      initData,
    );
    await proxy.waitForDeployment();
    return { manager: factory.attach(await proxy.getAddress()), admin, executorA, executorB };
  }

  it("tracks the real executor count and prevents removing the last executor", async function () {
    const { manager, admin, executorA, executorB } = await deployManager();
    expect(await manager.activeExecutorCount()).to.equal(2);

    await manager.connect(admin).removeExecutor(executorA.address);
    expect(await manager.activeExecutorCount()).to.equal(1);
    await expect(manager.connect(admin).removeExecutor(executorB.address))
      .to.be.revertedWithCustomError(manager, "InsufficientExecutors");
  });

  it("allows retrying an operation after the target call fails", async function () {
    const { manager, executorA } = await deployManager();
    const operationId = ethers.id("retry-after-failure");
    const failedCall = manager.interface.encodeFunctionData("updateExecutorLimit", [0]);

    const [success] = await manager.connect(executorA).executeOperation.staticCall(
      operationId,
      await manager.getAddress(),
      failedCall,
      0,
    );
    expect(success).to.equal(false);
    await manager.connect(executorA).executeOperation(
      operationId,
      await manager.getAddress(),
      failedCall,
      0,
    );
    expect(await manager.executedOperations(operationId)).to.equal(false);

    const [nextSuccess] = await manager.connect(executorA).executeOperation.staticCall(
      operationId,
      executorBAddress(await ethers.getSigners()),
      "0x",
      0,
    );
    expect(nextSuccess).to.equal(true);
    await manager.connect(executorA).executeOperation(
      operationId,
      executorBAddress(await ethers.getSigners()),
      "0x",
      0,
    );
    expect(await manager.executedOperations(operationId)).to.equal(true);
  });

  it("resets the executor quota on the next UTC day", async function () {
    const { manager, admin, executorA, executorB } = await deployManager();
    await manager.connect(admin).updateExecutorLimit(1);
    const target = executorB.address;

    await manager.connect(executorA).executeOperation(ethers.id("day-1"), target, "0x", 0);
    expect(await manager.executorUsageCount(executorA.address)).to.equal(1);

    await time.increaseTo((Math.floor((await time.latest()) / 86400) + 1) * 86400 + 1);
    await time.increase(3600);
    await manager.connect(executorA).executeOperation(ethers.id("day-2"), target, "0x", 0);
    expect(await manager.executorUsageCount(executorA.address)).to.equal(1);
  });
});

function executorBAddress(signers: Awaited<ReturnType<typeof ethers.getSigners>>) {
  return signers[2].address;
}
