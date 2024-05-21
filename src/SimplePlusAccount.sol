// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import { SimpleAccount, IEntryPoint } from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import { SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED } from "@account-abstraction/contracts/core/Helpers.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SimpleGuardianModule } from "./modules/SimpleGuardianModule.sol";

/**
 * @title SimplePlusAccount
 * @notice A version of SimpleAccount with additional features like ownership transfer and External Wallet (guardian)
 * Recovery.
 */
contract SimplePlusAccount is SimpleAccount, SimpleGuardianModule, IERC1271, EIP712 {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    bytes32 public constant _MESSAGE_TYPEHASH = keccak256("SimplePlusAccount(bytes message)");

    // @notice Signature types used for user operation validation and ERC-1271 signature validation.
    enum SignatureType {
        EOA,
        CONTRACT
    }

    error InvalidOwner(address newOwner);
    error NotAuthorized();
    error InvalidSignatureType();

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @notice Constructor for SimplePlusAccount.
     * @param anEntryPoint The entry point address.
     */
    constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) EIP712("SimplePlusAccount", "1") { }

    /**
     * @notice Initializes the contract.
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
     * @param anOwner The initial owner address.
     */
    function initialize(address anOwner) public virtual override initializer {
        _initialize(anOwner);
    }

    /**
     * @notice Transfers ownership of the contract to a new account (`newOwner`). Can only be called by the current
     * owner or from the entry point via a user operation signed by the current owner.
     * @param newOwner The new owner.
     */
    function transferOwnership(address newOwner) public {
        _onlyAuthorized();
        if (newOwner == address(0) || newOwner == address(this) || owner == newOwner) {
            revert InvalidOwner(newOwner);
        }
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /*
    * @dev Validates the signature of a user operation.
    *
    * The signature is considered valid if:
    * - It is signed by the owner's private key (when the owner is an EOA), or
    * - It is a valid ERC-1271 signature from the owner (when the owner is a contract).
    *
    * Reverts if the signature is malformed or if the signature type is unrecognized.
    *
    * Note:
    * - This function differs from `validateUserOp` in that it does **not** wrap the hash in an
    *   "Ethereum Signed Message" envelope before checking the signature for the EOA-owner case.
    */
    function isValidSignature(bytes32 hash, bytes calldata _signature) public view virtual returns (bytes4) {
        if (_signature.length == 0) {
            revert InvalidSignatureType();
        }

        bytes32 structHash = keccak256(abi.encode(_MESSAGE_TYPEHASH, keccak256(abi.encode(hash))));
        bytes32 replaySafeHash = MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);

        return _validateSignatureWithType(uint8(_signature[0]), replaySafeHash, _signature[1:])
            ? this.isValidSignature.selector
            : bytes4(0xffffffff);
    }

    ////////////////////////
    // Internal Functions //
    ////////////////////////

    /**
     * @dev  Revert if the caller is not any of:
     *  1. The entry point
     *  2. The account itself (when redirected through `execute`, etc.)
     *  3. An owner
     */
    function _onlyAuthorized() internal view virtual override returns (bool) {
        if (msg.sender != address(entryPoint()) && msg.sender != address(this) && msg.sender != owner) {
            revert NotAuthorized();
        }
        return true;
    }

    /**
     * @dev Validates the signature of a user operation.
     * @param userOp The user operation to be validated.
     * @param userOpHash The hash of the user operation.
     * @return validationData The validation data.
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        if (userOp.signature.length == 0) {
            revert InvalidSignatureType();
        }

        return _validateSignatureWithType(
            uint8(userOp.signature[0]), userOpHash.toEthSignedMessageHash(), userOp.signature[1:]
        ) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Validates a signature with a specified type.
     * @param signatureType The type of the signature.
     * @param hash The hash of the data to be signed.
     * @param signature The signature to be validated.
     * @return True if the signature is valid, otherwise false.
     */
    function _validateSignatureWithType(
        uint8 signatureType,
        bytes32 hash,
        bytes memory signature
    )
        internal
        view
        returns (bool)
    {
        if (signatureType == uint8(SignatureType.EOA)) {
            return _validateEOASignature(hash, signature) == SIG_VALIDATION_SUCCESS;
        } else if (signatureType == uint8(SignatureType.CONTRACT)) {
            return _validateContractSignature(hash, signature) == SIG_VALIDATION_SUCCESS;
        } else {
            revert InvalidSignatureType();
        }
    }

    /**
     * @notice Validates an EOA signature.
     * @param hash The hash of the data to be signed.
     * @param signature The signature to be validated.
     * @return The validation status.
     */
    function _validateEOASignature(bytes32 hash, bytes memory signature) internal view returns (uint256) {
        address recovered = hash.recover(signature);
        return recovered == owner ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Validates a contract signature.
     * @param userOpHash The hash of the user operation.
     * @param signature The signature to be validated.
     * @return The validation status.
     */
    function _validateContractSignature(bytes32 userOpHash, bytes memory signature) internal view returns (uint256) {
        return SignatureChecker.isValidERC1271SignatureNow(owner, userOpHash, signature)
            ? SIG_VALIDATION_SUCCESS
            : SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Transfers the ownership of the contract to a new owner.
     * @param newOwner The address of the new owner.
     */
    function _transferOwnership(address newOwner) internal virtual override {
        this.transferOwnership(newOwner);
    }

    /**
     * @notice Hashes the typed data.
     * @param structHash The struct hash to be hashed.
     * @return The hashed typed data.
     */
    function _hashTypedDataV4(bytes32 structHash)
        internal
        view
        virtual
        override(EIP712, SimpleGuardianModule)
        returns (bytes32)
    {
        return super._hashTypedDataV4(structHash);
    }

    /**
     * @notice Returns the owner of the contract.
     * @return The address of the owner.
     */
    function _owner() internal view virtual override returns (address) {
        return owner;
    }
}
