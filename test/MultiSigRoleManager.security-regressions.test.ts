import { expect } from "chai";
import { ethers } from "hardhat";

describe("MultiSigRoleManager security regressions", function () {
  async function deployProxy(adminAddress?: string) {
    const signers = await ethers.getSigners();
    const admin = signers[0];
    const factory = await ethers.getContractFactory("MultiSigRoleManager");
    const implementation = await factory.deploy();
    await implementation.waitForDeployment();

    const initData = factory.interface.encodeFunctionData("initialize", [
      adminAddress ?? admin.address,
    ]);
    const proxyAdmin = signers[signers.length - 1];
    const proxyFactory = await ethers.getContractFactory("HyraTransparentUpgradeableProxy");
    const proxy = await proxyFactory.deploy(
      await implementation.getAddress(),
      proxyAdmin.address,
      initData,
    );
    await proxy.waitForDeployment();

    return factory.attach(await proxy.getAddress());
  }

  it("revokes the old signers' AccessControl roles when a signer set is replaced", async function () {
    const [admin, signerA, signerB, signerC, signerD] = await ethers.getSigners();
    const manager = await deployProxy(admin.address);
    const role = ethers.id("REGRESSION_TEST_ROLE");

    await manager.configureRoleMultiSig(role, 2, [signerA.address, signerB.address]);
    expect(await manager.hasRole(role, signerA.address)).to.equal(true);
    expect(await manager.hasRole(role, signerB.address)).to.equal(true);

    await manager.configureRoleMultiSig(role, 2, [signerC.address, signerD.address]);

    expect(await manager.hasRole(role, signerA.address)).to.equal(false);
    expect(await manager.hasRole(role, signerB.address)).to.equal(false);
    expect(await manager.hasRole(role, signerC.address)).to.equal(true);
    expect(await manager.hasRole(role, signerD.address)).to.equal(true);
  });

  it("rejects initialization with the zero address as admin", async function () {
    const factory = await ethers.getContractFactory("MultiSigRoleManager");
    const implementation = await factory.deploy();
    await implementation.waitForDeployment();

    const signers = await ethers.getSigners();
    const proxyAdmin = signers[signers.length - 1];
    const proxyFactory = await ethers.getContractFactory("HyraTransparentUpgradeableProxy");
    const initData = factory.interface.encodeFunctionData("initialize", [ethers.ZeroAddress]);
    await expect(
      proxyFactory.deploy(await implementation.getAddress(), proxyAdmin.address, initData),
    ).to.be.reverted;
  });

  it("does not let a non-admin replace a role's signer set", async function () {
    const [admin, signerA, signerB, outsider] = await ethers.getSigners();
    const manager = await deployProxy(admin.address);
    const role = ethers.id("REGRESSION_TEST_ROLE");

    await manager.configureRoleMultiSig(role, 2, [signerA.address, signerB.address]);
    await expect(
      manager.connect(outsider).configureRoleMultiSig(role, 2, [outsider.address, signerB.address]),
    ).to.be.reverted;
    expect(await manager.hasRole(role, signerA.address)).to.equal(true);
    expect(await manager.hasRole(role, outsider.address)).to.equal(false);
  });
});
