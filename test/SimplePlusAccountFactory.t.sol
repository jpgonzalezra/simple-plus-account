// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import { Test } from "forge-std/src/Test.sol";

import { EntryPoint } from "@account-abstraction/contracts/core/EntryPoint.sol";

import { SimplePlusAccount } from "../src/SimplePlusAccount.sol";
import { SimplePlusAccountFactory } from "../src/SimplePlusAccountFactory.sol";

contract SimplePlusAccountFactoryTest is Test {
    address public constant OWNER_ADDRESS = address(0x100);
    SimplePlusAccountFactory public factory;
    EntryPoint public entryPoint;

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new SimplePlusAccountFactory(entryPoint);
    }

    function testReturnsAddressWhenAccountAlreadyExists() public {
        SimplePlusAccount account = factory.createAccount(OWNER_ADDRESS, 1);
        SimplePlusAccount otherAccount = factory.createAccount(OWNER_ADDRESS, 1);
        assertEq(address(account), address(otherAccount));
    }

    function testGetAddress() public {
        address counterfactual = factory.getAddress(OWNER_ADDRESS, 1);
        assertEq(counterfactual.codehash, bytes32(0));
        SimplePlusAccount factual = factory.createAccount(OWNER_ADDRESS, 1);
        assertTrue(address(factual).codehash != bytes32(0));
        assertEq(counterfactual, address(factual));
    }

    /// @dev Receive funds from withdraw.
    receive() external payable { }
}
