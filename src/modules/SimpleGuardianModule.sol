// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title SimpleGuardianModule
 * @notice This module provides functionalities for a guardian to recover the account and update the guardian.
 */
abstract contract SimpleGuardianModule {
    using ECDSA for bytes32;

    bytes32 public constant _RECOVER_TYPEHASH =
        keccak256("Recover(address currentOwner, address newOwner, uint256 nonce)");

    event NonceConsumed(address indexed owner, uint256 idx);
    event GuardianUpdated(address indexed previousGuardian, address indexed newGuardian);

    error InvalidNewOwner(address owner);
    error InvalidGuardian(address guardian);
    error InvalidGuardianSignature();
    error NotGuardian();
    error InvalidNonce();
    error GuardianAlreadyInitialized();

    address public guardian;
    mapping(address => uint256) private _nonces;

    /**
     * @notice Returns the nonce for a given address.
     * @param from The address to query the nonce for.
     * @return The current nonce for the given address.
     */
    function getNonce(address from) external view virtual returns (uint256) {
        return _nonces[from];
    }

    /**
     * @notice Initializes the guardian.
     * @param newGuardian The address of the new guardian.
     */
    function initGuardian(address newGuardian) external {
        if (guardian != address(0)) {
            revert GuardianAlreadyInitialized();
        }
        _updateGuardian(newGuardian);
    }

    /**
     * @notice Updates the guardian.
     * @param newGuardian The address of the new guardian.
     */
    function updateGuardian(address newGuardian) external {
        _onlyAuthorized();
        _updateGuardian(newGuardian);
    }

    /**
     * @notice Allows the guardian to recover the account by transferring ownership to a new owner.
     * @param newOwner The address of the new owner.
     * @param nonce The nonce to prevent replay attacks.
     * @param signature The signature of the guardian.
     */
    function recoverAccount(address newOwner, uint256 nonce, bytes calldata signature) external {
        if (newOwner == address(0) || _owner() == newOwner || newOwner == address(this)) {
            revert InvalidNewOwner(newOwner);
        }

        _verifyAndConsumeNonce(newOwner, nonce);
        bytes32 structHash = keccak256(abi.encode(_RECOVER_TYPEHASH, _owner(), newOwner, nonce));
        bytes32 digest = _hashTypedDataV4(structHash);

        address recoveredAddress = digest.recover(signature);
        if (recoveredAddress != guardian) {
            revert InvalidGuardianSignature();
        }

        _transferOwnership(newOwner);
    }

    ////////////////////////
    // Internals function //
    ///////////////////////

    /**
     * @notice Verifies and consumes a nonce for a given owner.
     * @param owner The address of the owner.
     * @param nonce The nonce to be verified and consumed.
     */
    function _verifyAndConsumeNonce(address owner, uint256 nonce) internal virtual {
        if (nonce != _nonces[owner]++) {
            revert InvalidNonce();
        }
        emit NonceConsumed(owner, nonce);
    }

    /**
     * @notice Internal function to update the guardian.
     * @param newGuardian The address of the new guardian.
     */
    function _updateGuardian(address newGuardian) internal {
        if (newGuardian == address(0) || guardian == newGuardian || newGuardian == address(this)) {
            revert InvalidGuardian(newGuardian);
        }

        address oldGuardian = guardian;
        guardian = newGuardian;
        emit GuardianUpdated(oldGuardian, newGuardian);
    }

    /**
     * @notice Transfers the ownership of the contract to a new owner.
     * @param newOwner The address of the new owner.
     */
    function _transferOwnership(address newOwner) internal virtual;

    /**
     * @notice Hashes the typed data.
     * @param structHash The struct hash to be hashed.
     * @return The hashed typed data.
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32);

    /**
     * @notice Checks if the sender is authorized.
     * @return True if the sender is authorized, otherwise false.
     */
    function _onlyAuthorized() internal view virtual returns (bool);

    /**
     * @notice Returns the owner of the contract.
     * @return The address of the owner.
     */
    function _owner() internal view virtual returns (address);

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     */
    uint256[49] private __gap;
}
