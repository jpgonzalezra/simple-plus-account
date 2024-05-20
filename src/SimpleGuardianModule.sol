// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
// import { console2 } from "forge-std/src/console2.sol";

abstract contract SimpleGuardianModule {
    using ECDSA for bytes32;

    bytes32 public constant _RECOVER_TYPEHASH =
        keccak256("Recover(address currentOwner, address newOwner, uint256 nonce)");

    event NonceConsumed(address indexed owner, uint256 idx);
    event GuardianUpdated(address indexed previousGuardian, address indexed newGuardian);

    address public guardian;
    mapping(address => uint256) private _nonces;

    modifier onlyGuardian() {
        require(msg.sender == guardian, "Not the guardian");
        _;
    }

    /**
     * @notice Retuns a nonce for a given address.
     * @param   from  Address.
     * @return  uint256 Nonce Value.
     */
    function getNonce(address from) external view virtual returns (uint256) {
        return _nonces[from];
    }

    function _verifyAndConsumeNonce(address owner, uint256 nonde) internal virtual {
        require(nonde == _nonces[owner]++, "invalid nonce");
        emit NonceConsumed(owner, nonde);
    }

    function initGuardian(address newGuardian) external {
        require(guardian == address(0));
        _updateGuardian(newGuardian);
    }

    function updateGuardian(address newGuardian) external {
        require(_onlyAuthorized(), "Not authorized");
        _updateGuardian(newGuardian);
    }

    function _updateGuardian(address newGuardian) internal {
        require(
            newGuardian != address(0) && guardian != newGuardian && newGuardian != address(this),
            "Invalid guardian address"
        );
        address oldGuardian = guardian;
        guardian = newGuardian;
        emit GuardianUpdated(oldGuardian, newGuardian);
    }

    function recoverAccount(address newOwner, uint256 nonce, bytes calldata signature) external {
        require(
            newOwner != address(0) && _owner() != newOwner && newOwner != address(this), "Invalid new owner address"
        );

        _verifyAndConsumeNonce(newOwner, nonce);
        bytes32 structHash = keccak256(abi.encode(_RECOVER_TYPEHASH, _owner(), newOwner, nonce));
        bytes32 digest = _hashTypedDataV4(structHash);

        address recoveredAddress = digest.recover(signature);

        require(recoveredAddress == guardian, "Invalid guardian signature");

        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal virtual;

    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32);

    function _onlyAuthorized() internal view virtual returns (bool);

    function _owner() internal view virtual returns (address);

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     */
    uint256[49] private __gap;
}