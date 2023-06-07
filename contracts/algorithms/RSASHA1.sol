// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../utils/Bytes.sol";
import "./RSAVerify.sol";

/**
* @dev Implements the RSASHA1 algorithm.
*/
library RSASHA1 {
    using Bytes for *;

    function verify(bytes32 hash, bytes calldata sig, bytes memory exponent, bytes memory modulus) internal view returns (bool) {
        // Recover the message from the signature
        bool ok;
        bytes memory result;
        (ok, result) = RSAVerify.rsarecover(modulus, exponent, sig);

        // Verify it ends with the hash of our data
        return ok && hash == result.readBytes20(result.length - 20);
    }
}
