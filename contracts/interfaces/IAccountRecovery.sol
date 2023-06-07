// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./UserOperation.sol";

interface IAccountRecovery {
    /**
     * @notice Recover the account to a new owner
     * @param newOwner The new owner of the account
     */
    function recover(address newOwner) external;
}
