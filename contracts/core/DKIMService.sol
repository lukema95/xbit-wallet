// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import "./DKIM.sol";
import "../utils/EmailParser.sol";
import "../utils/Bytes.sol";
import "../interfaces/IAccountRecovery.sol";

/**
 * @title DKIMService
 * @notice This contract is used to store DKIM records for accounts and verify signatures.
 */
contract DKIMService is DKIM, UUPSUpgradeable, Initializable, Ownable, EmailParser {
    using Bytes for bytes;
    struct Record {
        bytes exponent;
        bytes modulus;
    }

    struct AccountInfo {
        address account;
        uint256 nonce;
    }

    // domain => record
    mapping (string => Record) public records;

    // email adress => account info
    mapping (string => AccountInfo) public accountInfo;

    string public emailReceiver;

    event Recover(address indexed account, address indexed newOwner);

    constructor() {
        emailReceiver = "nathanma@baas.com";
    }

    function initialize() public initializer {
        // TODO
    }

    function setEmailReceiver(string calldata email) external onlyOwner {
        emailReceiver = email;
    }

    function setAccountInfo(string calldata email, address account, uint256 nounce) external onlyOwner {
        return _setAccountInfo(email, account, nounce);
    }

    function removeAccountInfo(string calldata email) external onlyOwner {
        _removeAccountInfo(email);
    }

    function getAccountInfo(string memory email) external view returns(AccountInfo memory) {
        return _getAccountInfo(email);
    }

    function getAccountNonce(string calldata email) external view returns(uint256) {
        AccountInfo memory info = _getAccountInfo(email);
        return info.nonce;
    }

    function setRecord(
        string calldata domain,
        bytes calldata exponent,
        bytes calldata modulus
    )
        external
        onlyOwner
    {
        require(records[domain].exponent.length == 0, "DKIMService: Record already exists");
        records[domain] = Record(exponent, modulus);
    }

    function getRecord(string calldata domain) external view returns(Record memory) {
        return _getRecord(domain);
    }

    function removeRecord(string calldata domain) external onlyOwner {
        _getRecord(domain);
        delete records[domain];
    }

    /**
     * @dev Recover account owner.
     * @param algorithm The signing algorithm to use
     * @param newOwner The new owner address of the account
     * @param header The DKIM-Signature process header
     * @param signature The signature to verify
     */
    function recover(
        Algorithms algorithm,
        address newOwner,
        bytes calldata header,
        bytes calldata signature
    )
        external
    {
        (newOwner);
        DKIMSignFields memory signFileds = parseHeaderFileds(header);
        string memory email = extractEmailAddress(signFileds.from);
        require(verifySignFields(signFileds, email), "DKIMService: Invalid email header");

        string memory domain = parseEmailDomain(email);
        Record memory record = _getRecord(domain);

        bytes32 hash = _hash(algorithm, signFileds);

        require(
            verifySignature(algorithm, hash, signature, record.exponent, record.modulus),
            "DKIMService: Invalid signature"
        );

        updateAccountNonce(email);

        IAccountRecovery(accountInfo[email].account).recover(newOwner);

        emit Recover(accountInfo[email].account, newOwner);
    }

    function getEmailRecoverySubject(string memory email) external view returns(string memory) {
        AccountInfo memory info = _getAccountInfo(email);
        return bytes32ToHexString(keccak256(abi.encodePacked(info.account, info.nonce)));
    }

    function verifySignFields(DKIMSignFields memory signFileds, string memory from) internal view returns (bool) {
        require(
            isEqualStr(signFileds.to, emailReceiver),
            "DKIMService: Invalid email receiver"
        );
        require(
            verifyEmailSubject(signFileds.subject, from),
            "DKIMService: Invalid email subject"
        );
        return true;
    }

    function verifyEmailSubject(string memory actualSubject, string memory from) internal view returns (bool) {
        AccountInfo memory info = _getAccountInfo(from);

        string memory expectedSubject = bytes32ToHexString(keccak256(abi.encodePacked(info.account, info.nonce)));
        require(
            isEqualStr(actualSubject, expectedSubject),
            "DKIMService: Invalid email subject"
        );
        return true;
    }

    function isEqualStr(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }

    function bytes32ToHexString(bytes32 data) internal pure returns (string memory) {
        bytes16 hexAlphabet = "0123456789abcdef";
        bytes memory hexString = new bytes(64);
        for (uint i = 0; i < 32; i++) {
            bytes1 b = bytes1(uint8(uint(data) / (2**(8*(31 - i)))));
            bytes2 hexChars = bytes2(hexAlphabet[uint(uint8(b) >> 4)]);
            hexString[2*i] = hexChars[0];
            hexChars = bytes2(hexAlphabet[uint(uint8(b) & 0x0f)]);
            hexString[2*i+1] = hexChars[0];
        }
        return string(abi.encodePacked("0x", hexString));
    }

    function _hash(Algorithms algorithm, DKIMSignFields memory signFields) internal pure returns (bytes32) {
        if (algorithm == Algorithms.RSASHA256) {
            bytes memory signMsg = getSignMsg(signFields);
            return sha256(signMsg);
        } else if (algorithm == Algorithms.RSASHA1) {
            // TODO: Support RSASHA1
            revert("DKIMService: Don't support RSASHA1");
        } else {
            revert("DKIMService: Unsupported algorithm");
        }
    }

    function updateAccountNonce(string memory email) internal {
        AccountInfo storage info = accountInfo[email];
        info.nonce += 1;
    }

    function _getRecord(string memory domain) internal view returns (Record memory) {
        require(records[domain].exponent.length > 0, "DKIMService: Record not found");
        return records[domain];
    }

    function _setAccountInfo(
        string calldata email,
        address account,
        uint256 nounce
    )
        internal
    {
        require(account != address(0), "DKIMService: Account is zero address");
        accountInfo[email] = AccountInfo(account, nounce);
    }

    function _getAccountInfo(string memory email) internal view returns (AccountInfo memory) {
        require(accountInfo[email].account != address(0), "DKIMService: Account not found");
        return accountInfo[email];
    }

    function _removeAccountInfo(string calldata email) internal {
        _getAccountInfo(email);
        delete accountInfo[email];
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}