// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ISignatureTransfer} from "@permit2/src/interfaces/IPermit2.sol";
import {PermitHash} from "@permit2/src/libraries/PermitHash.sol";

import {Vm} from "forge-std/Vm.sol";

import {ERC20ForwarderPermit2} from "../../src/ERC20ForwarderPermit2.sol";

library Permit2Signature {
    using Permit2Signature for Vm;

    function permitWitnessTransferFromSignature(
        Vm vm,
        bytes32 domainSeparator,
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        uint256 privateKey,
        bytes32 witness
    ) internal pure returns (bytes memory signature) {
        bytes32 digest = permitWitnessTransferFromDigest({
            domainSeparator: domainSeparator,
            permit: permit,
            spender: spender,
            witness: witness
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    /// @notice Computes the `permitWitnessTransferFrom` digest.
    /// @param permit The permit data constituted by the token address, token amount, nonce, and deadline.
    /// @param spender The address being allowed to execute the `permitWitnessTransferFrom` call.
    /// @param witness The witness obtained from the hashed witness struct.
    /// @return digest The digest.
    function permitWitnessTransferFromDigest(
        bytes32 domainSeparator,
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        bytes32 witness
    ) internal pure returns (bytes32 digest) {
        bytes32 dataHash = hashWithWitness({
            permit: permit,
            witness: witness,
            witnessTypeString: ERC20ForwarderPermit2._WITNESS_TYPE_STRING,
            spender: spender
        });
        digest = hashTypedData(domainSeparator, dataHash);
    }

    function hashTypedData(
        bytes32 domainSeparator,
        bytes32 dataHash
    ) internal pure returns (bytes32 hash) {
        hash = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, dataHash)
        );
    }

    /// @dev Modified version of https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/libraries/PermitHash.sol#L85-L94.
    /// where `msg.sender` has been replaced by `spender`.
    function hashWithWitness(
        ISignatureTransfer.PermitTransferFrom memory permit,
        bytes32 witness,
        string memory witnessTypeString,
        address spender
    ) private pure returns (bytes32 hash) {
        bytes32 typeHash = keccak256(
            abi.encodePacked(
                PermitHash._PERMIT_TRANSFER_FROM_WITNESS_TYPEHASH_STUB,
                witnessTypeString
            )
        );

        hash = keccak256(
            abi.encode(
                typeHash,
                _hashTokenPermissions(permit.permitted),
                spender,
                permit.nonce,
                permit.deadline,
                witness
            )
        );
    }

    /// @dev Copied from https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/libraries/PermitHash.sol#L127-L133.
    function _hashTokenPermissions(
        ISignatureTransfer.TokenPermissions memory permitted
    ) private pure returns (bytes32 hash) {
        hash = keccak256(
            abi.encode(PermitHash._TOKEN_PERMISSIONS_TYPEHASH, permitted)
        );
    }
}
