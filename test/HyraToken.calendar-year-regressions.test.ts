import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("HyraToken calendar-year mint-cap regressions", function () {
  async function deployToken() {
    const signers = await ethers.getSigners();
    const [governance] = signers;
    const proxyAdmin = signers[signers.length - 1];

    const validatorFactory = await ethers.getContractFactory("ProxyAdminValidator");
    const privilegedWallet = await validatorFactory.deploy();
    await privilegedWallet.waitForDeployment();

    const tokenFactory = await ethers.getContractFactory("HyraToken");
    const implementation = await tokenFactory.deploy();
    await implementation.waitForDeployment();
    const initData = tokenFactory.interface.encodeFunctionData("initialize", [
      "Hyra",
      "HYRA",
      0,
      governance.address,
      governance.address,
      await privilegedWallet.getAddress(),
    ]);
    const proxyFactory = await ethers.getContractFactory("HyraTransparentUpgradeableProxy");
    const proxy = await proxyFactory.deploy(
      await implementation.getAddress(),
      proxyAdmin.address,
      initData,
    );
    await proxy.waitForDeployment();
    return tokenFactory.attach(await proxy.getAddress());
  }

  it("uses the 366-day duration for the 2028 leap calendar year", async function () {
    const token = await deployToken();
    await time.increaseTo(Date.UTC(2028, 0, 1) / 1000);
    expect(await token.getTimeUntilNextMintYear()).to.equal(366 * 24 * 60 * 60);
  });

  it("returns to a 365-day duration at the start of 2029", async function () {
    const token = await deployToken();
    await time.increaseTo(Date.UTC(2029, 0, 1) / 1000);
    expect(await token.getTimeUntilNextMintYear()).to.equal(365 * 24 * 60 * 60);
  });

  it("returns zero after the 25-year minting schedule has ended", async function () {
    const token = await deployToken();
    await time.increaseTo(Date.UTC(2050, 0, 1) / 1000);
    expect(await token.getTimeUntilNextMintYear()).to.equal(0);
  });
});
