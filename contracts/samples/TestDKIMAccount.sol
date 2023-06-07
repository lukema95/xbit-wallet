// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../interfaces/IAccountRecovery.sol";

contract TestDKIMAccount is IAccountRecovery {
    address public dkimService;
    address public owner;

    modifier onlyDKIMService() {
        require(msg.sender == dkimService, "DKIMAccount: only DKIMService");
        _;
    }

    function setDKIMService(address aDKIMService) external {
        dkimService = aDKIMService;
    }

    function setOwner(address anOwner) external {
        owner = anOwner;
    }

    function recover(address newOwner) external onlyDKIMService {
        owner = newOwner;
    }
}