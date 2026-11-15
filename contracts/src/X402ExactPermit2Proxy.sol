// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

interface IERC20PermitLike {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external;
}

/// @notice Local x402 exact Permit2 proxy matching the interface the x402 Go
/// SDK calls (go/mechanisms/evm/constants.go X402ExactPermit2Proxy*ABI) and its
/// EIP-712 witness type (Permit2WitnessTypes: to, validAfter, extra). The
/// reference source in the scheme document lists the witness fields in another
/// order and takes an extra amount argument; the SDK is what clients sign, so
/// this contract follows the SDK. Funds can only move to witness.to.
contract X402ExactPermit2Proxy {
    struct Witness {
        address to;
        uint256 validAfter;
        bytes extra;
    }

    struct EIP2612Permit {
        uint256 value;
        uint256 deadline;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    string public constant WITNESS_TYPE_STRING =
        "Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter,bytes extra)";
    bytes32 public constant WITNESS_TYPEHASH = keccak256("Witness(address to,uint256 validAfter,bytes extra)");

    ISignatureTransfer public immutable PERMIT2;

    event X402PermitTransfer(address indexed from, address indexed to, uint256 amount, address indexed asset);

    error PaymentNotYetValid();
    error InvalidDestination();

    constructor(ISignatureTransfer permit2) {
        PERMIT2 = permit2;
    }

    function settle(
        ISignatureTransfer.PermitTransferFrom calldata permit,
        address owner,
        Witness calldata witness,
        bytes calldata signature
    ) external {
        _settle(permit, owner, witness, signature);
    }

    /// @dev EIP-2612 extension: first lets Permit2 spend the owner's tokens.
    function settleWithPermit(
        EIP2612Permit calldata permit2612,
        ISignatureTransfer.PermitTransferFrom calldata permit,
        address owner,
        Witness calldata witness,
        bytes calldata signature
    ) external {
        // Anyone may submit the same EIP-2612 permit first. A failed permit
        // must not block settlement; Permit2 still fails if the allowance is short.
        try IERC20PermitLike(permit.permitted.token)
            .permit(
                owner, address(PERMIT2), permit2612.value, permit2612.deadline, permit2612.v, permit2612.r, permit2612.s
            ) {}
            catch {}
        _settle(permit, owner, witness, signature);
    }

    function _settle(
        ISignatureTransfer.PermitTransferFrom calldata permit,
        address owner,
        Witness calldata witness,
        bytes calldata signature
    ) private {
        if (block.timestamp < witness.validAfter) revert PaymentNotYetValid();
        if (witness.to == address(0)) revert InvalidDestination();
        bytes32 witnessHash =
            keccak256(abi.encode(WITNESS_TYPEHASH, witness.to, witness.validAfter, keccak256(witness.extra)));
        PERMIT2.permitWitnessTransferFrom(
            permit,
            ISignatureTransfer.SignatureTransferDetails({to: witness.to, requestedAmount: permit.permitted.amount}),
            owner,
            witnessHash,
            WITNESS_TYPE_STRING,
            signature
        );
        emit X402PermitTransfer(owner, witness.to, permit.permitted.amount, permit.permitted.token);
    }
}
