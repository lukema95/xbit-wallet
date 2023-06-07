// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../algorithms/RSASHA1.sol";
import "../algorithms/RSASHA256.sol";

/**
 * @title DKIM
 * @notice DKIM is a contract that contains functions to verify DKIM signatures.
 */
contract DKIM {
    enum Algorithms {
        RSASHA1,
        RSASHA256
    }
    /**
     * @dev Verifies a signature.
     * @param algorithm The signing algorithm to use.
     * @param hash The hash of data that needs to be verified.
     * @param signature The signature to verify.
     * @param exponent The exponent of a public key.
     * @param modulus The modulus of a public key.
     * @return True if the signature is valid.
     */
    function verifySignature(
        Algorithms algorithm,
        bytes32 hash,
        bytes calldata signature,
        bytes memory exponent,
        bytes memory modulus
    )
        internal
        view
        returns (bool)
    {
        if (algorithm == Algorithms.RSASHA1) {
            return RSASHA1.verify(hash, signature, exponent, modulus);
        } else {
            return RSASHA256.verify(hash, signature, exponent, modulus);
        }
    }
}