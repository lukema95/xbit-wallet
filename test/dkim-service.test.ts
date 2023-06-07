import { ethers } from 'hardhat'
import { expect } from 'chai'
import { promisify } from 'util'
import * as fs from 'fs'
import * as path from 'path'
import {
  DKIMService,
  DKIMService__factory,
  TestDKIMAccount
} from '../typechain'
import { deployTestDKIMAccount } from './testutils'

const parseEmail = require('./parse-email')
const readFile = promisify(fs.readFile)
const emailsPath = path.join(__dirname, 'emails')
const recordsPath = path.join(__dirname, 'records')

describe('DKIMService', () => {
  let accounts: string[]
  let dkimService: DKIMService
  let dkimAccount: TestDKIMAccount
  let emailParsedData: any
  const gmailDomain = 'gmail.com'
  const icloudDomain = 'icloud.com'
  const email = 'lukema95@gmail.com'
  const emailSubject = '0xe494891ecf8f64ba335c1bc157500b09c4b2f9cbd9e2fd6c1c402779d0b6b7c5'
  const testEmail = 'test@gmail.com'
  const testAddress = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
  const testOwnerAddress = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
  const ethersSigner = ethers.provider.getSigner()
  const { exponent, modulus } = require(path.join(recordsPath, 'gmail.json'))

  before(async function () {
    accounts = await ethers.provider.listAccounts()
    dkimService = await new DKIMService__factory(ethersSigner).deploy()

    dkimAccount = await deployTestDKIMAccount()
    await dkimAccount.setOwner(testOwnerAddress)
    await dkimAccount.setDKIMService(dkimService.address)

    await dkimService.setAccountInfo(email, dkimAccount.address, 1)
    await dkimService.setRecord(gmailDomain, exponent, modulus)

    const emailRawData = await readFile(path.join(emailsPath, 'gmail.eml'), {
      encoding: 'ascii'
    })
    emailParsedData = await parseEmail(emailRawData)
  })

  context('Record', () => {
    it('should set record successfully by owner', async () => {
      await dkimService.setRecord(icloudDomain, exponent, modulus)
    })

    it('should fail to set record by non-owner', async () => {
      await expect(dkimService.connect(accounts[1]).setRecord(icloudDomain, exponent, modulus))
        .to.be.revertedWith('Ownable: caller is not the owner')
    })

    it('should remove record successfully by owner', async () => {
      await dkimService.removeRecord(icloudDomain)
      await expect(dkimService.getRecord(accounts[1])).to.be.revertedWith('DKIMService: Record not found')
    })

    it('should fail to remove record by non-owner', async () => {
      await expect(dkimService.connect(accounts[1]).removeRecord(icloudDomain))
        .to.be.revertedWith('Ownable: caller is not the owner')
    })

    it('should fail to remove non-existing record', async () => {
      await expect(dkimService.removeRecord(icloudDomain))
        .to.be.revertedWith('DKIMService: Record not found')
    })
  })

  context('AccountInfo', () => {
    it('should set account info successfully by owner', async () => {
      await dkimService.setAccountInfo(testEmail, testAddress, 1)
      expect(await dkimService.getAccountNonce(testEmail)).to.equal(1)
    })

    it('should fail to set account info by non-owner', async () => {
      await expect(dkimService.connect(accounts[1]).setAccountInfo(testEmail, testAddress, 1))
        .to.be.revertedWith('Ownable: caller is not the owner')
    })

    it('should remove account info successfully by owner', async () => {
      await dkimService.removeAccountInfo(testEmail)
      await expect(dkimService.getAccountInfo(testEmail)).to.be.revertedWith('DKIMService: Account not found')
    })

    it('should fail to remove account info by non-owner', async () => {
      await expect(dkimService.connect(accounts[1]).removeAccountInfo(testEmail))
        .to.be.revertedWith('Ownable: caller is not the owner')
    })

    it('should fail to remove non-existing account info', async () => {
      await expect(dkimService.removeAccountInfo(testEmail))
        .to.be.revertedWith('DKIMService: Account not found')
    })
  })

  context('Recover', () => {
    it('#getEmailRecoverySubject', async () => {
      const subject = await dkimService.getEmailRecoverySubject(email)
      expect(subject).to.equal(emailSubject)
    })

    it('should fail to recover with invalid signature', async () => {
      const { algorithm, processHeader } = emailParsedData[0].solidityData
      const { signature } = emailParsedData[1].solidityData

      await expect(dkimService.recover(algorithm, dkimAccount.address, processHeader, signature))
        .to.be.revertedWith('DKIMService: Invalid signature')
    })

    it('should recover successfully with valid Gmail signature', async () => {
      const { algorithm, processHeader, signature } = emailParsedData[0].solidityData

      expect(await dkimAccount.owner()).to.equal(testOwnerAddress)
      await dkimService.recover(algorithm, testAddress, processHeader, signature)
      expect(await dkimAccount.owner()).to.equal(testAddress)
      expect(await dkimService.getAccountNonce(email)).to.equal(2)
    })

    it('should recover failed with repeated Gmail signature', async () => {
      const { algorithm, processHeader, signature } = emailParsedData[0].solidityData

      await expect(dkimService.recover(algorithm, testAddress, processHeader, signature))
        .to.be.revertedWith('DKIMService: Invalid email subject')
    })
  })
})
