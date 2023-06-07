import { BigNumber, Wallet } from 'ethers'
import { ethers } from 'hardhat'
import { expect } from 'chai'
import { arrayify, defaultAbiCoder, hexConcat, parseEther } from 'ethers/lib/utils'
import { keccak256 } from 'ethereumjs-util'
import { hashToPoint } from '@thehubbleproject/bls/dist/mcl'
import { BytesLike, hexValue } from '@ethersproject/bytes'
import { aggregate, BlsSignerFactory, BlsVerifier } from '@thehubbleproject/bls/dist/signer'
import {
  XBitWallet,
  XBitWalletFactory,
  XBitWalletFactory__factory,
  TestUtil,
  TestUtil__factory,
  BLSOpen__factory,
  BLSSignatureAggregator,
  BLSSignatureAggregator__factory,
  EntryPoint,
  EntryPoint__factory
} from '../typechain'

import {
  AddressZero,
  createAddress,
  createAccountOwner,
  getBalance,
  isDeployed,
  ONE_ETH,
  fund,
  simulationResultWithAggregationCatch,
  createXBitWallet
} from './testutils'

import {
  fillUserOp,
  fillUserOpDefaults,
  DefaultsForUserOp,
  multiSignUserOp,
  getUserOpHash,
  packUserOp,
  signUserOp
} from './UserOp'

import { UserOperation } from './UserOperation'

describe('XBitWallet', function () {
  let accounts: string[]
  let testUtil: TestUtil
  let account1: Wallet
  let account2: Wallet
  let account3: Wallet
  let entrypoint: EntryPoint
  let XBitWallet1: XBitWallet
  let XBitWallet2: XBitWallet
  let blsSigner1: any
  let blsSigner2: any
  let blsAgg: BLSSignatureAggregator
  let blsSignerFactory: BlsSignerFactory

  const ethersSigner = ethers.provider.getSigner()
  const BLS_DOMAIN = arrayify(keccak256(Buffer.from('eip4337.bls.domain')))

  before(async function () {
    entrypoint = await new EntryPoint__factory(ethersSigner).deploy()
    const BLSOpenLib = await new BLSOpen__factory(ethersSigner).deploy()
    blsAgg = await new BLSSignatureAggregator__factory({
      'contracts/bls/lib/BLSOpen.sol:BLSOpen': BLSOpenLib.address
    }, ethers.provider.getSigner()).deploy()

    await blsAgg.addStake(entrypoint.address, 2, { value: ONE_ETH })

    accounts = await ethers.provider.listAccounts()
    // ignore in geth.. this is just a sanity test. should be refactored to use a single-account mode..
    if (accounts.length < 2) this.skip()
    testUtil = await new TestUtil__factory(ethersSigner).deploy()
    account1 = createAccountOwner()
    account2 = createAccountOwner()
    account3 = createAccountOwner()

    blsSignerFactory = await BlsSignerFactory.new()
    blsSigner1 = blsSignerFactory.getSigner(arrayify(BLS_DOMAIN), account1.privateKey)
    blsSigner2 = blsSignerFactory.getSigner(arrayify(BLS_DOMAIN), account2.privateKey);

    ({ proxy: XBitWallet1 } = await createXBitWallet(
      ethersSigner,
      blsAgg.address,
      accounts[0],
      accounts[1],
      entrypoint.address,
      AddressZero,
      blsSigner1.pubkey));

    ({ proxy: XBitWallet2 } = await createXBitWallet(
      ethersSigner,
      blsAgg.address,
      accounts[1],
      accounts[0],
      entrypoint.address,
      AddressZero,
      blsSigner2.pubkey))
  })

  it('owner should be able to call transfer', async () => {
    const { proxy: account } = await createXBitWallet(
      ethersSigner,
      blsAgg.address,
      accounts[0],
      accounts[1],
      entrypoint.address,
      AddressZero,
      blsSigner1.pubkey)
    await ethersSigner.sendTransaction({ from: accounts[0], to: account.address, value: parseEther('2') })
    await account.execute(accounts[2], ONE_ETH, '0x')
  })

  it('other account should not be able to call transfer', async () => {
    const { proxy: account } = await createXBitWallet(
      ethersSigner,
      blsAgg.address,
      accounts[0],
      accounts[1],
      entrypoint.address,
      AddressZero,
      blsSigner1.pubkey)
    await expect(account.connect(ethers.provider.getSigner(1)).execute(accounts[2], ONE_ETH, '0x'))
      .to.be.revertedWith('XBitWallet: Not Owner or EntryPoint')
  })

  it('should pack in js the same as solidity', async () => {
    const op = await fillUserOpDefaults({ sender: accounts[0] })
    const packed = packUserOp(op)
    expect(await testUtil.packUserOp(op)).to.equal(packed)
  })

  describe('#validateUserOp', () => {
    let account: XBitWallet
    let userOp: UserOperation
    let userOpHash: string
    let userOpWithSingleSignature: UserOperation
    let userOpHashWithSingleSignature: string
    let userOpWithInvalidSignature: UserOperation
    let userOpHashWithInvalidSignature: string
    let preBalance: number
    let expectedPay: number

    const actualGasPrice = 1e9

    before(async () => {
      // that's the account of ethersSigner
      const entryPoint = accounts[2];
      ({ proxy: account } = await createXBitWallet(
        await ethers.getSigner(entryPoint),
        blsAgg.address, account1.address,
        account2.address,
        entryPoint,
        AddressZero,
        blsSigner1.pubkey))
      await ethersSigner.sendTransaction({ from: accounts[0], to: account.address, value: parseEther('0.2') })
      const callGasLimit = 200000
      const verificationGasLimit = 100000
      const maxFeePerGas = 3e9
      const chainId = await ethers.provider.getNetwork().then(net => net.chainId)

      userOp = multiSignUserOp(fillUserOpDefaults({
        sender: account.address,
        callGasLimit,
        verificationGasLimit,
        maxFeePerGas
      }), account1, account2, entryPoint, chainId)
      userOpHash = await getUserOpHash(userOp, entryPoint, chainId)

      // wrong server signature
      userOpWithInvalidSignature = multiSignUserOp(fillUserOpDefaults({
        nonce: 1,
        sender: account.address,
        callGasLimit,
        verificationGasLimit,
        maxFeePerGas
      }), account1, account3, entryPoint, chainId)
      userOpHashWithInvalidSignature = await getUserOpHash(userOpWithInvalidSignature, entryPoint, chainId)

      userOpWithSingleSignature = signUserOp(fillUserOpDefaults({
        nonce: 1,
        sender: account.address,
        callGasLimit,
        verificationGasLimit,
        maxFeePerGas
      }), account1, entryPoint, chainId)
      userOpHashWithSingleSignature = await getUserOpHash(userOpWithSingleSignature, entryPoint, chainId)

      expectedPay = actualGasPrice * (callGasLimit + verificationGasLimit)
      preBalance = await getBalance(account.address)

      const ret = await account.validateUserOp(userOp, userOpHash, AddressZero, expectedPay, { gasPrice: actualGasPrice })
      await ret.wait()
    })

    it('should return 0 on valid signature', async () => {
      expect(await account.callStatic.validateUserOp(
        { ...userOp, nonce: 1 }, userOpHash, AddressZero, expectedPay, { gasPrice: actualGasPrice }))
        .to.equal(0)
    })

    it('should return NO_SIG_VALIDATION on wrong signature', async () => {
      expect(await account.callStatic.validateUserOp(
        userOpWithInvalidSignature,
        userOpHashWithInvalidSignature,
        AddressZero,
        expectedPay,
        { gasPrice: actualGasPrice }))
        .to.equal(1)
    })

    it('should return NO_SIG_VALIDATION on wrong signature length', async () => {
      expect(await account.callStatic.validateUserOp(
        userOpWithSingleSignature,
        userOpHashWithSingleSignature,
        AddressZero,
        expectedPay,
        { gasPrice: actualGasPrice }))
        .to.equal(1)
    })

    it('should pay', async () => {
      const postBalance = await getBalance(account.address)
      expect(preBalance - postBalance).to.eql(expectedPay)
    })

    it('should increment nonce', async () => {
      expect(await account.nonce()).to.equal(1)
    })

    it('should reject same TX on nonce error', async () => {
      await expect(account.validateUserOp(userOp, userOpHash, AddressZero, 1))
        .to.revertedWith('XBitWallet: Invalid nonce')
    })
  })

  describe('Aggregator', () => {
    it('#getTrailingPublicKey', async () => {
      const data = defaultAbiCoder.encode(['uint[6]'], [[1, 2, 3, 4, 5, 6]])
      const last4 = await blsAgg.getTrailingPublicKey(data)
      expect(last4.map(x => x.toNumber())).to.eql([3, 4, 5, 6])
    })

    it('#aggregateSignatures', async () => {
      const sig1 = blsSigner1.sign('0x1234')
      const sig2 = blsSigner2.sign('0x5678')
      const offChainSigResult = hexConcat(aggregate([sig1, sig2]))
      const userOp1 = { ...DefaultsForUserOp, signature: hexConcat(sig1) }
      const userOp2 = { ...DefaultsForUserOp, signature: hexConcat(sig2) }
      const solidityAggResult = await blsAgg.aggregateSignatures([userOp1, userOp2])
      expect(solidityAggResult).to.equal(offChainSigResult)
    })

    it('#userOpToMessage', async () => {
      const userOp1 = await fillUserOp({
        sender: XBitWallet1.address
      }, entrypoint)
      const requestHash = await blsAgg.getUserOpHash(userOp1)
      const solPoint: BigNumber[] = await blsAgg.userOpToMessage(userOp1)
      const messagePoint = hashToPoint(requestHash, BLS_DOMAIN)
      expect(`1 ${solPoint[0].toString()} ${solPoint[1].toString()}`).to.equal(messagePoint.getStr())
    })

    it('#validateSignatures', async function () {
      this.timeout(30000)
      const userOp1 = await fillUserOp({
        sender: XBitWallet1.address
      }, entrypoint)
      const requestHash = await blsAgg.getUserOpHash(userOp1)
      const sig1 = blsSigner1.sign(requestHash)
      userOp1.signature = hexConcat(sig1)

      const userOp2 = await fillUserOp({
        sender: XBitWallet2.address
      }, entrypoint)
      const requestHash2 = await blsAgg.getUserOpHash(userOp2)
      const sig2 = blsSigner2.sign(requestHash2)
      userOp2.signature = hexConcat(sig2)

      const aggSig = aggregate([sig1, sig2])
      const aggregatedSig = await blsAgg.aggregateSignatures([userOp1, userOp2])
      expect(hexConcat(aggSig)).to.equal(aggregatedSig)

      const pubkeys = [
        blsSigner1.pubkey,
        blsSigner2.pubkey
      ]

      const v = new BlsVerifier(BLS_DOMAIN)
      // off-chain check
      const now = Date.now()
      expect(v.verifyMultiple(aggSig, pubkeys, [requestHash, requestHash2])).to.equal(true)
      console.log('verifyMultiple (mcl code)', Date.now() - now, 'ms')
      const now2 = Date.now()
      console.log('validateSignatures gas= ',
        await blsAgg.estimateGas.validateSignatures([userOp1, userOp2], aggregatedSig))
      console.log('validateSignatures (on-chain)', Date.now() - now2, 'ms')
    })
  })

  describe('#EntryPoint.simulateValidation with aggregator', () => {
    let initCode: BytesLike
    let signer3: any
    let deployer: XBitWalletFactory
    const ownerAddr = createAddress()
    const serverAddr = createAddress()

    before(async () => {
      deployer = await new XBitWalletFactory__factory(ethersSigner).deploy(entrypoint.address, blsAgg.address, AddressZero)
      signer3 = blsSignerFactory.getSigner(arrayify(BLS_DOMAIN), '0x03')
      initCode = hexConcat([
        deployer.address,
        deployer.interface.encodeFunctionData('createAccount', [ownerAddr, serverAddr, 0, signer3.pubkey])
      ])
    })

    it('validate after simulation returns ValidationResultWithAggregation', async () => {
      const verifier = new BlsVerifier(BLS_DOMAIN)
      const senderAddress = await entrypoint.callStatic.getSenderAddress(initCode).catch(e => e.errorArgs.sender)
      await fund(senderAddress, '0.01')
      const userOp = await fillUserOp({
        sender: senderAddress,
        initCode,
        nonce: 2
      }, entrypoint)
      const requestHash = await blsAgg.getUserOpHash(userOp)
      const sigParts = signer3.sign(requestHash)
      userOp.signature = hexConcat(sigParts)

      const { aggregatorInfo } = await entrypoint.callStatic.simulateValidation(userOp).catch(simulationResultWithAggregationCatch)
      expect(aggregatorInfo.actualAggregator).to.eq(blsAgg.address)
      expect(aggregatorInfo.stakeInfo.stake).to.eq(ONE_ETH)
      expect(aggregatorInfo.stakeInfo.unstakeDelaySec).to.eq(2)

      const [signature] = defaultAbiCoder.decode(['bytes32[2]'], userOp.signature)
      const pubkey = (await blsAgg.getUserOpPublicKey(userOp)).map(n => hexValue(n)) // TODO: returns uint256[4], verify needs bytes32[4]
      const requestHash1 = await blsAgg.getUserOpHash(userOp)

      // @ts-ignore
      expect(verifier.verify(signature, pubkey, requestHash1)).to.equal(true)
    })
  })

  context('XBitWalletFactory', () => {
    it('sanity: check deployer', async () => {
      const ownerAddr = createAddress()
      const serverAddr = createAddress()
      const deployer = await new XBitWalletFactory__factory(ethersSigner).deploy(entrypoint.address, blsAgg.address, AddressZero)
      const target = await deployer.callStatic.createAccount(ownerAddr, serverAddr, 1234, blsSigner1.pubkey)
      expect(await isDeployed(target)).to.eq(false)
      await deployer.createAccount(ownerAddr, serverAddr, 1234, blsSigner1.pubkey)
      expect(await isDeployed(target)).to.eq(true)
    })
  })
})
