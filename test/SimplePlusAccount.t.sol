// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "forge-std/src/Test.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { SimplePlusAccount } from "../src/SimplePlusAccount.sol";
import { SimplePlusAccountFactory } from "../src/SimplePlusAccountFactory.sol";
import { EntryPoint } from "@account-abstraction/contracts/core/EntryPoint.sol";
import { SimpleAccount } from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import { AccountTest } from "./AccountTest.sol";

contract SimplePlusAccountTest is AccountTest {
    uint256 public constant EOA_PRIVATE_KEY = 1;
    address payable public constant BENEFICIARY = payable(address(0xbe9ef1c1a2ee));
    address public eoaAddress;
    SimplePlusAccount public account;
    EntryPoint public entryPoint;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        eoaAddress = vm.addr(EOA_PRIVATE_KEY);
        entryPoint = new EntryPoint();
        SimplePlusAccountFactory factory = new SimplePlusAccountFactory(entryPoint);
        account = factory.createAccount(eoaAddress, 1);
        vm.deal(address(account), 1 << 128);
    }

    function testOwnerCanTransferOwnership() public {
        _transferOwnership(eoaAddress, address(0x100));
    }

    function testEntryPointCanExecuteTransferOwnership() public {
        address newOwner = address(0x100);
        PackedUserOperation memory op = getSignedOp(
            entryPoint,
            uint8(SimplePlusAccount.SignatureType.EOA),
            abi.encodeCall(SimplePlusAccount.transferOwnership, (newOwner)),
            EOA_PRIVATE_KEY,
            address(account)
        );
        _executeOperation(op);
        assertEq(account.owner(), newOwner);
    }

    function testSelfExecuteCanTransferOwnership() public {
        address newOwner = address(0x100);
        PackedUserOperation memory op = getSignedOp(
            entryPoint,
            uint8(SimplePlusAccount.SignatureType.EOA),
            abi.encodeCall(
                SimpleAccount.execute,
                (address(account), 0, abi.encodeCall(SimplePlusAccount.transferOwnership, (newOwner)))
            ),
            EOA_PRIVATE_KEY,
            address(account)
        );
        _executeOperation(op);
        assertEq(account.owner(), newOwner);
    }

    function testCannotTransferOwnershipToSelf() public {
        vm.prank(eoaAddress);
        vm.expectRevert(abi.encodeWithSelector(SimplePlusAccount.InvalidOwner.selector, (eoaAddress)));
        account.transferOwnership(eoaAddress);
    }

    function testUnauthorizedCannotTransferOwnership() public {
        vm.expectRevert(abi.encodeWithSelector(SimplePlusAccount.NotAuthorized.selector));
        account.transferOwnership(address(0x100));
    }

    function testCannotTransferOwnershipToZeroAddress() public {
        vm.prank(eoaAddress);
        vm.expectRevert(abi.encodeWithSelector(SimplePlusAccount.InvalidOwner.selector, (address(0))));
        account.transferOwnership(address(0));
    }

    function testCannotTransferOwnershipToContractItself() public {
        vm.prank(eoaAddress);
        vm.expectRevert(abi.encodeWithSelector(SimplePlusAccount.InvalidOwner.selector, (address(account))));
        account.transferOwnership(address(account));
    }

    function _transferOwnership(address currentOwner, address newOwner) internal {
        vm.prank(currentOwner);
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(currentOwner, newOwner);
        account.transferOwnership(newOwner);
        assertEq(account.owner(), newOwner);
    }

    function _executeOperation(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(eoaAddress, address(0x100));
        entryPoint.handleOps(ops, BENEFICIARY);
    }
}