import { expect } from "chai";
import { ethers } from "hardhat";

describe("HyraToken distribution initialization security regressions", function () {
  async function deployUninitializedProxy() {
    const signers = await ethers.getSigners();
    const proxyAdmin = signers[signers.length - 1];
    const factory = await ethers.getContractFactory("HyraToken");
    const implementation = await factory.deploy();
    await implementation.waitForDeployment();
    const proxyFactory = await ethers.getContractFactory("HyraTransparentUpgradeableProxy");
    const proxy = await proxyFactory.deploy(
      await implementation.getAddress(),
      proxyAdmin.address,
      "0x",
    );
    await proxy.waitForDeployment();
    return factory.attach(await proxy.getAddress());
  }

  it("does not let an arbitrary caller claim distribution config before initialization", async function () {
    const [attacker] = await ethers.getSigners();
    const token = await deployUninitializedProxy();
    await expect(
      token.connect(attacker).setDistributionConfig(
        attacker.address,
        attacker.address,
        attacker.address,
        attacker.address,
        attacker.address,
        attacker.address,
      ),
    ).to.be.reverted;
    expect(await token.configSet()).to.equal(false);
  });

  it("still permits the legitimate deployer to set distribution atomically", async function () {
    const signers = await ethers.getSigners();
    const [governance] = signers;
    const proxyAdmin = signers[signers.length - 1];
    const contractFactory = await ethers.getContractFactory("ProxyAdminValidator");
    const contracts = [];
    for (let i = 0; i < 7; i++) {
      const deployed = await contractFactory.deploy();
      await deployed.waitForDeployment();
      contracts.push(await deployed.getAddress());
    }

    const tokenFactory = await ethers.getContractFactory("HyraToken");
    const implementation = await tokenFactory.deploy();
    await implementation.waitForDeployment();
    const initData = tokenFactory.interface.encodeFunctionData("initializeWithDistribution", [
      "Hyra",
      "HYRA",
      0,
      governance.address,
      governance.address,
      contracts[0],
      contracts[1],
      contracts[2],
      contracts[3],
      contracts[4],
      contracts[5],
      contracts[6],
    ]);
    const proxyFactory = await ethers.getContractFactory("HyraTransparentUpgradeableProxy");
    const proxy = await proxyFactory.deploy(
      await implementation.getAddress(),
      proxyAdmin.address,
      initData,
    );
    await proxy.waitForDeployment();

    const token = tokenFactory.attach(await proxy.getAddress());
    expect(await token.configSet()).to.equal(true);
    expect(await token.owner()).to.equal(governance.address);
  });
});
