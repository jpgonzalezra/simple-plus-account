// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import "forge-std/src/Test.sol";

import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { EntryPoint } from "@account-abstraction/contracts/core/EntryPoint.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract AccountTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    function getSignedOp(
        EntryPoint entryPoint,
        uint8 sigType,
        bytes memory callData,
        uint256 privateKey,
        address account
    )
        internal
        view
        returns (PackedUserOperation memory)
    {
        PackedUserOperation memory op = getUnsignedOp(callData, account);
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes32 ethSignedMessageHash = userOpHash.toEthSignedMessageHash();
        bytes memory signature = abi.encodePacked(sigType, sign(privateKey, ethSignedMessageHash));
        op.signature = signature;
        return op;
    }

    function getUnsignedOp(bytes memory callData, address account) internal pure returns (PackedUserOperation memory) {
        uint128 verificationGasLimit = 1 << 24;
        uint128 callGasLimit = 1 << 24;
        uint128 maxPriorityFeePerGas = 1 << 8;
        uint128 maxFeePerGas = 1 << 8;
        return PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: 1 << 24,
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: "",
            signature: ""
        });
    }

    function sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
