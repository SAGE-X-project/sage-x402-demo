// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC1271} from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

interface IPermit2Domain {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @notice A user-owned account that lets SAGE agents pay through the x402
/// exact Permit2 path without holding the user's funds. The owner names each
/// agent payment key, the agent DID it belongs to, one token, a per-payment
/// cap, an expiry and the recipients it may pay. The total budget is the
/// ERC-20 allowance this account gives Permit2, so the chain enforces it on
/// every settlement. EIP-3009 and any other signature use are refused.
///
/// The agent signs the Permit2 digest and sends it together with the fields of
/// that digest, so this account can check them before accepting.
contract SageDelegatedAccount is IERC1271 {
    using SafeERC20 for IERC20;

    struct Delegation {
        string did;
        address token;
        uint256 perPaymentCap;
        uint64 expires;
        bool active;
    }

    /// Fields of one PermitWitnessTransferFrom signed by an agent payment key.
    struct PaymentAuthorization {
        address token;
        uint256 amount;
        address spender;
        uint256 nonce;
        uint256 deadline;
        address to;
        uint256 validAfter;
        bytes extra;
    }

    bytes4 private constant MAGIC = IERC1271.isValidSignature.selector;
    bytes4 private constant INVALID = 0xffffffff;
    bytes32 private constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 private constant WITNESS_TYPEHASH = keccak256("Witness(address to,uint256 validAfter,bytes extra)");
    bytes32 private constant PERMIT_WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)"
        "TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter,bytes extra)"
    );

    address public immutable owner;
    address public immutable permit2;
    address public immutable proxy;

    mapping(address key => Delegation) private _delegations;
    mapping(address key => mapping(address payTo => bool)) public allowedPayTo;
    mapping(address key => address[]) private _payTos;

    event Delegated(
        address indexed key, string did, address indexed token, uint256 perPaymentCap, uint64 expires, address[] payTos
    );
    event DelegationRevoked(address indexed key);
    event BudgetSet(address indexed token, uint256 amount);

    error NotOwner();
    error InvalidDelegation();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_, address permit2_, address proxy_) {
        if (owner_ == address(0) || permit2_ == address(0) || proxy_ == address(0)) revert InvalidDelegation();
        owner = owner_;
        permit2 = permit2_;
        proxy = proxy_;
    }

    /// Replaces any earlier delegation of the same key.
    function delegate(
        address key,
        string calldata did,
        address token,
        uint256 perPaymentCap,
        uint64 expires,
        address[] calldata payTos
    ) external onlyOwner {
        if (
            key == address(0) || bytes(did).length == 0 || token == address(0) || perPaymentCap == 0
                || expires <= block.timestamp || payTos.length == 0
        ) revert InvalidDelegation();
        _clearPayTos(key);
        for (uint256 i; i < payTos.length; ++i) {
            if (payTos[i] == address(0)) revert InvalidDelegation();
            allowedPayTo[key][payTos[i]] = true;
            _payTos[key].push(payTos[i]);
        }
        _delegations[key] = Delegation(did, token, perPaymentCap, expires, true);
        emit Delegated(key, did, token, perPaymentCap, expires, payTos);
    }

    function revoke(address key) external onlyOwner {
        _clearPayTos(key);
        delete _delegations[key];
        emit DelegationRevoked(key);
    }

    /// Sets the total amount all delegates together may still spend in token.
    function setBudget(address token, uint256 amount) external onlyOwner {
        IERC20(token).forceApprove(permit2, amount);
        emit BudgetSet(token, amount);
    }

    function withdraw(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(to, amount);
    }

    function delegation(address key) external view returns (Delegation memory, address[] memory payTos) {
        return (_delegations[key], _payTos[key]);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (signature.length < 64) return INVALID;
        (PaymentAuthorization memory payment, bytes memory agentSignature) =
            abi.decode(signature, (PaymentAuthorization, bytes));
        if (_digest(payment) != hash) return INVALID;
        (address key, ECDSA.RecoverError error,) = ECDSA.tryRecover(hash, agentSignature);
        if (error != ECDSA.RecoverError.NoError) return INVALID;
        Delegation storage d = _delegations[key];
        bool allowed = d.active && block.timestamp < d.expires && payment.deadline <= d.expires
            && payment.spender == proxy && payment.token == d.token && payment.amount <= d.perPaymentCap
            && allowedPayTo[key][payment.to];
        return allowed ? MAGIC : INVALID;
    }

    function _digest(PaymentAuthorization memory p) private view returns (bytes32) {
        bytes32 permitted = keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, p.token, p.amount));
        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, p.to, p.validAfter, keccak256(p.extra)));
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_WITNESS_TYPEHASH, permitted, p.spender, p.nonce, p.deadline, witness));
        return keccak256(abi.encodePacked("\x19\x01", IPermit2Domain(permit2).DOMAIN_SEPARATOR(), structHash));
    }

    function _clearPayTos(address key) private {
        address[] storage list = _payTos[key];
        for (uint256 i; i < list.length; ++i) {
            delete allowedPayTo[key][list[i]];
        }
        delete _payTos[key];
    }
}
