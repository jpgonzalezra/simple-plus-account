// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "forge-std/src/Test.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { SimplePlusAccount } from "../src/SimplePlusAccount.sol";
import { SimplePlusAccountFactory } from "../src/SimplePlusAccountFactory.sol";
import { EntryPoint } from "@account-abstraction/contracts/core/EntryPoint.sol";
import { SimpleAccount } from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import { AccountTest } from "./AccountTest.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { SimpleGuardianModule } from "../src/SimpleGuardianModule.sol";
// import { console2 } from "forge-std/src/console2.sol";

contract SimplePlusAccountTest is AccountTest {
    uint256 public constant EOA_PRIVATE_KEY = 1;
    uint256 public constant GUARDIAN_PRIVATE_KEY = 2;
    address payable public constant BENEFICIARY = payable(address(0xbe9ef1c1a2ee));
    address public eoaAddress;
    address public guardianAddress;

    SimplePlusAccount public account;
    EntryPoint public entryPoint;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event GuardianUpdated(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        eoaAddress = vm.addr(EOA_PRIVATE_KEY);
        guardianAddress = vm.addr(GUARDIAN_PRIVATE_KEY);
        entryPoint = new EntryPoint();
        SimplePlusAccountFactory factory = new SimplePlusAccountFactory(entryPoint);
        account = factory.createAccount(eoaAddress, 1);
        vm.deal(address(account), 1 << 128);
        emit GuardianUpdated(address(0), guardianAddress);
        account.initGuardian(guardianAddress);
    }

    /**
     * transferOwnership test cases
     */
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

    /**
     * IsValidSignature test cases
     */
    function testIsValidSignatureForEoaOwner() public view {
        bytes32 message = keccak256("simple_plus_account");
        bytes memory signature = abi.encodePacked(
            SimplePlusAccount.SignatureType.EOA,
            sign(EOA_PRIVATE_KEY, getMessageHash(address(account), abi.encode(message)))
        );
        assertEq(account.isValidSignature(message, signature), bytes4(keccak256("isValidSignature(bytes32,bytes)")));
    }

    /**
     * Guardian test cases
     */
    function testGuardianCanTransferOwnership() public {
        uint256 nonce = account.getNonce(eoaAddress);
        address newOwner = address(0x100);
        bytes32 structHash = keccak256(abi.encode(account._RECOVER_TYPEHASH(), eoaAddress, newOwner, nonce));
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator(address(account)), structHash);

        bytes memory signature = sign(GUARDIAN_PRIVATE_KEY, digest);

        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(eoaAddress, newOwner);
        account.recoverAccount(newOwner, nonce, signature);
        assertEq(account.owner(), newOwner);
    }

    function testGuardianCannotTransferOwnershipPerInvalidNewOwner() public {
        uint256 nonce = account.getNonce(eoaAddress);

        bytes32 structHash = keccak256(abi.encode(account._RECOVER_TYPEHASH(), eoaAddress, eoaAddress, nonce));
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator(address(account)), structHash);

        bytes memory signature = sign(GUARDIAN_PRIVATE_KEY, digest);

        vm.expectRevert(abi.encodeWithSelector(SimpleGuardianModule.InvalidNewOwner.selector, eoaAddress));
        account.recoverAccount(eoaAddress, nonce, signature);
    }

    function testEntryPointExecutesRecoverAccountByGuardian() public {
        uint256 nonce = account.getNonce(eoaAddress);
        address newOwner = address(0x100);

        bytes32 structHash = keccak256(abi.encode(account._RECOVER_TYPEHASH(), eoaAddress, newOwner, nonce));
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator(address(account)), structHash);
        bytes memory signature = sign(GUARDIAN_PRIVATE_KEY, digest);

        PackedUserOperation memory op = getSignedOp(
            entryPoint,
            uint8(SimplePlusAccount.SignatureType.EOA),
            abi.encodeCall(SimpleGuardianModule.recoverAccount, (newOwner, nonce, signature)),
            EOA_PRIVATE_KEY,
            address(account)
        );

        _executeOperation(op);

        assertEq(account.owner(), newOwner);
    }

    function testSelfExecuteCanRecoverAccount() public {
        uint256 nonce = account.getNonce(eoaAddress);
        address newOwner = address(0x100);

        bytes32 structHash = keccak256(abi.encode(account._RECOVER_TYPEHASH(), eoaAddress, newOwner, nonce));
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator(address(account)), structHash);
        bytes memory signature = sign(GUARDIAN_PRIVATE_KEY, digest);

        PackedUserOperation memory op = getSignedOp(
            entryPoint,
            uint8(SimplePlusAccount.SignatureType.EOA),
            abi.encodeCall(
                SimpleAccount.execute,
                (address(account), 0, abi.encodeCall(SimpleGuardianModule.recoverAccount, (newOwner, nonce, signature)))
            ),
            EOA_PRIVATE_KEY,
            address(account)
        );

        _executeOperation(op);
        assertEq(account.owner(), newOwner);
    }

    function testRecoverAccountRevertsWithInvalidSignature() public {
        uint256 nonce = account.getNonce(eoaAddress);

        bytes32 structHash = keccak256(abi.encode(account._RECOVER_TYPEHASH(), eoaAddress, guardianAddress, nonce));
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator(address(account)), structHash);

        bytes memory signature = sign(EOA_PRIVATE_KEY, digest);

        vm.expectRevert(abi.encodeWithSelector(SimpleGuardianModule.InvalidGuardianSignature.selector));
        account.recoverAccount(guardianAddress, nonce, signature);
    }

    function testRecoverAccountPreventsReplayAttack() public {
        uint256 nonce = account.getNonce(eoaAddress);

        address newOwner = address(0x100);
        bytes32 structHash = keccak256(abi.encode(account._RECOVER_TYPEHASH(), eoaAddress, newOwner, nonce));
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator(address(account)), structHash);

        bytes memory signature = sign(GUARDIAN_PRIVATE_KEY, digest);

        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(eoaAddress, newOwner);
        account.recoverAccount(newOwner, nonce, signature);
        assertEq(account.owner(), newOwner);

        vm.expectRevert(abi.encodeWithSelector(SimpleGuardianModule.InvalidGuardianSignature.selector));
        account.recoverAccount(address(0x101), nonce, signature);
    }

    function testOwnerCanUpdateGuardian() public {
        vm.prank(eoaAddress);

        address newGuardian = address(0x200);

        vm.expectEmit(true, true, false, false);
        emit GuardianUpdated(guardianAddress, newGuardian);
        account.updateGuardian(newGuardian);
        assertEq(account.guardian(), newGuardian);
    }

    function testNonOwnerCannotUpdateGuardian() public {
        vm.prank(address(0x300));
        vm.expectRevert(abi.encodeWithSelector(SimplePlusAccount.NotAuthorized.selector));
        account.updateGuardian(address(0x200));
    }

    function testUpdateGuardianToInvalidAddress() public {
        vm.prank(eoaAddress);

        address invalidGuardian = address(0);
        vm.expectRevert(abi.encodeWithSelector(SimpleGuardianModule.InvalidGuardian.selector, address(0)));

        account.updateGuardian(invalidGuardian);
    }

    function testGuardianCannotUpdateGuardian() public {
        vm.prank(guardianAddress);

        address newGuardian = address(0x200);
        vm.expectRevert(abi.encodeWithSelector(SimplePlusAccount.NotAuthorized.selector));
        account.updateGuardian(newGuardian);
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
