// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import "../interfaces/IAggregator.sol";
import "../interfaces/IAccountRecovery.sol";
import "../bls/IBLSAccount.sol";
import "../core/BaseAccount.sol";
import "../utils/SignatureDecoder.sol";

/**
 * @title  XBitWallet
 * @dev    This contract is a wallet that impliments the BaseAccount interface. 
 */
contract XBitWallet is IBLSAccount, IAccountRecovery, BaseAccount, SignatureDecoder, UUPSUpgradeable, Initializable {
    using ECDSA for bytes32;

    //explicit sizes of nonce, to fit a single storage cell with "owner"
    uint96 private _nonce;

    address public owner;

    address public immutable dkimService;

    IAggregator public immutable aggregator;
    
    // the public key of the aggregate signature
    uint256[4] private publicKey;

    // the address of multi-signature server
    address private _server;
    
    // the multi-signature threshold, default is 2
    uint256 private _threshold; 

    IEntryPoint private immutable _entryPoint;

    function nonce() public view virtual override returns (uint256) {
        return _nonce;
    }

    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    event XBitWalletInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event PublicKeyChanged(uint256[4] oldPublicKey, uint256[4] newPublicKey);

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint, IAggregator anAggregator, address dkim) {
        aggregator = anAggregator;
        _entryPoint = anEntryPoint;
        dkimService = dkim;
    }

    /**
     * change entry-point:
     * an account must have a method for replacing the entryPoint, in case the the entryPoint is
     * upgraded to a newer version.
     */
    function initialize(address anOwner, address server, uint256[4] memory aPublicKey) public virtual initializer {
        _initialize(anOwner, server, aPublicKey);
    }

    function _initialize(address anOwner, address server, uint256[4] memory aPublicKey) internal virtual {
        owner = anOwner;
        _server = server;
        publicKey = aPublicKey;
        _threshold = 2;

        emit XBitWalletInitialized(_entryPoint, owner);
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    modifier onlyDKIM() {
        require(msg.sender == dkimService, "only DKIM");
        _;
    }

    function _onlyOwner() internal view {
        //directly from EOA owner, or through the entryPoint (which gets redirected through execFromEntryPoint)
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    /**
     * execute a transaction (called directly from owner, not by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transaction
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "XBitWallet: Wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /**
     * validate the userOp is correct.
     * revert if it doesn't.
     * - must only be called from the entryPoint.
     * - make sure the signature is of our supported signer.
     * - validate current nonce matches request nonce, and increment it.
     * - pay prefund, in case current deposit is not enough
     */
    function _requireFromEntryPointOrOwner() internal view {
        require(msg.sender == address(entryPoint()) || msg.sender == owner, "XBitWallet: Not Owner or EntryPoint");
    }

    /// implement template method of BaseAccount
    function _validateAndUpdateNonce(UserOperation calldata userOp) internal override {
        require(_nonce++ == userOp.nonce, "XBitWallet: Invalid nonce");
    }

    /// implement template method of BaseAccount
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash, address userOpAggregator)
        internal 
        override 
        virtual 
        returns (uint256 sigTimeRange) 
    {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (userOpAggregator != address(0)) {
            sigTimeRange =  _validateSignatureWithAggregator(userOp, userOpHash, userOpAggregator);
        }else if (_isMultiSign()) {
            sigTimeRange = _validateMultiSignature(userOp, hash);
        }else {
            sigTimeRange = _validateSingleSignature(userOp, hash);
        }
    }

    function _validateSignatureWithAggregator(UserOperation calldata userOp, bytes32 userOpHash, address userOpAggregator)
        internal 
        view 
        returns (uint256) 
    {
        (userOp, userOpHash);
        require(userOpAggregator == address(aggregator), "XBitWallet: Wrong aggregator");
        return 0;
    }

    function _validateSingleSignature(UserOperation calldata userOp, bytes32 hash)
        internal 
        view 
        returns (uint256) 
    {
        if (owner != hash.recover(userOp.signature))
            return SIG_VALIDATION_FAILED;
        return 0;
    }

    function _validateMultiSignature(UserOperation calldata userOp, bytes32 hash)
        internal 
        view 
        returns (uint256) 
    {
        // check signature length, each signature is 65 bytes
        if (userOp.signature.length != _threshold * 65) {
            return SIG_VALIDATION_FAILED;
        }
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint8 i;
        for(i = 0; i < _threshold; i++) {
            (v, r, s) = signatureSplit(userOp.signature, i);
            address signer = ecrecover(hash, v, r, s);
            // default first signature is signed by owner and second signature is signed by server
            if (i == 0 && owner != signer) {
                return SIG_VALIDATION_FAILED;
            }else if (i == 1 && signer != _server) {
                return SIG_VALIDATION_FAILED;
            }

        }
        return 0;
    }

    function _isMultiSign() internal view returns (bool) {
        if (_server != address(0)) {
            return true;
        }

        return false;
    }

    function recover(address newOwner) external onlyDKIM {
        owner = newOwner;
    }

    function setBlsPublicKey(uint256[4] memory newPublicKey) external onlyOwner {
        emit PublicKeyChanged(publicKey, newPublicKey);
        publicKey = newPublicKey;
    }

    function getAggregator() external view returns (address) {
        return address(aggregator);
    }

    function getBlsPublicKey() external override view returns (uint256[4] memory) {
        return publicKey;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value : value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        (bool req,) = address(entryPoint()).call{value : msg.value}("");
        require(req);
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }
}

