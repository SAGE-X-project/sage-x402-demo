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
/// The agent does not sign the bare Permit2 digest: that digest names neither
/// this account nor the delegation, so it could be replayed against another
/// account that delegates the same key. The agent signs agentDigest(), an
/// EIP-712 wrapper bound to this account, the chain and the key's current
/// delegation epoch, and sends it with the Permit2 fields so this account can
/// check them. The signature is abi.encode(PaymentAuthorization, key || ecdsa)
/// where key is the 20-byte payment key and ecdsa its 65-byte signature over
/// agentDigest(). Revoking or re-delegating a key starts a new epoch, so
/// earlier signatures stop working.
contract SageDelegatedAccount is IERC1271 {
    using SafeERC20 for IERC20;

    struct Delegation {
        string did;
        address token;
        uint256 perPaymentCap;
        uint64 expires;
        uint64 epoch;
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
    uint256 public constant MAX_PAY_TOS = 16;
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant AUTHORIZATION_TYPEHASH =
        keccak256("SagePaymentAuthorization(bytes32 permit2Digest,uint64 epoch)");
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
    mapping(address key => uint64) private _epochs;

    event Delegated(
        address indexed key,
        string did,
        address indexed token,
        uint256 perPaymentCap,
        uint64 expires,
        uint64 epoch,
        address[] payTos
    );
    event DelegationRevoked(address indexed key, uint64 epoch);
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
                || expires <= block.timestamp || payTos.length == 0 || payTos.length > MAX_PAY_TOS
        ) revert InvalidDelegation();
        _clearPayTos(key);
        for (uint256 i; i < payTos.length; ++i) {
            if (payTos[i] == address(0) || allowedPayTo[key][payTos[i]]) revert InvalidDelegation();
            allowedPayTo[key][payTos[i]] = true;
            _payTos[key].push(payTos[i]);
        }
        uint64 epoch = ++_epochs[key];
        _delegations[key] = Delegation(did, token, perPaymentCap, expires, epoch, true);
        emit Delegated(key, did, token, perPaymentCap, expires, epoch, payTos);
    }

    function revoke(address key) external onlyOwner {
        _clearPayTos(key);
        delete _delegations[key];
        emit DelegationRevoked(key, ++_epochs[key]);
    }

    /// Sets the total amount all delegates together may still spend in token.
    /// An unlimited allowance never decreases, so it is refused.
    function setBudget(address token, uint256 amount) external onlyOwner {
        if (amount == type(uint256).max) revert InvalidDelegation();
        IERC20(token).forceApprove(permit2, amount);
        emit BudgetSet(token, amount);
    }

    function withdraw(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(to, amount);
    }

    function delegation(address key) external view returns (Delegation memory, address[] memory payTos) {
        return (_delegations[key], _payTos[key]);
    }

    /// The digest a delegated key signs for one payment from this account.
    function agentDigest(PaymentAuthorization calldata payment, address key) external view returns (bytes32) {
        return _agentDigest(_digest(payment), _delegations[key].epoch);
    }

    /// Decodes the signature format; external so a malformed input can be caught.
    function decodeAuthorization(bytes calldata signature)
        external
        pure
        returns (PaymentAuthorization memory, bytes memory)
    {
        return abi.decode(signature, (PaymentAuthorization, bytes));
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        PaymentAuthorization memory payment;
        bytes memory agentSignature;
        try this.decodeAuthorization(signature) returns (PaymentAuthorization memory p, bytes memory sig) {
            (payment, agentSignature) = (p, sig);
        } catch {
            return INVALID;
        }
        if (_digest(payment) != hash) return INVALID;
        // The agent signature names its key so the account can pick that key's
        // epoch before recovering; recovery must then return the same key.
        return _authorized(payment, hash, agentSignature) ? MAGIC : INVALID;
    }

    function _authorized(PaymentAuthorization memory payment, bytes32 permit2Digest, bytes memory agentSignature)
        private
        view
        returns (bool)
    {
        if (agentSignature.length != 85) return false;
        // Signature layout: 20-byte key address followed by the 65-byte ECDSA signature.
        address key;
        assembly ("memory-safe") {
            key := shr(96, mload(add(agentSignature, 32)))
        }
        bytes memory ecdsaSignature = new bytes(65);
        for (uint256 i; i < 65; ++i) {
            ecdsaSignature[i] = agentSignature[i + 20];
        }
        Delegation storage d = _delegations[key];
        if (!d.active) return false;
        (address signer, ECDSA.RecoverError error,) =
            ECDSA.tryRecover(_agentDigest(permit2Digest, d.epoch), ecdsaSignature);
        return error == ECDSA.RecoverError.NoError && signer == key && block.timestamp < d.expires
            && payment.deadline <= d.expires && payment.spender == proxy && payment.token == d.token
            && payment.amount <= d.perPaymentCap && allowedPayTo[key][payment.to];
    }

    function _agentDigest(bytes32 permit2Digest, uint64 epoch) private view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("SageDelegatedAccount"), keccak256("1"), block.chainid, address(this))
        );
        return keccak256(
            abi.encodePacked("\x19\x01", domain, keccak256(abi.encode(AUTHORIZATION_TYPEHASH, permit2Digest, epoch)))
        );
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
