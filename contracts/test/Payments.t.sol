// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {DemoUSD} from "../src/DemoUSD.sol";
import {X402ExactPermit2Proxy} from "../src/X402ExactPermit2Proxy.sol";
import {SageDelegatedAccount} from "../src/SageDelegatedAccount.sol";

interface IPermit2Errors {
    error InvalidContractSignature();
    error InvalidNonce();
}

interface IPermit2Like {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

contract PaymentsTest is Test {
    bytes32 private constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 private constant WITNESS_TYPEHASH = keccak256("Witness(address to,uint256 validAfter,bytes extra)");
    bytes32 private constant PERMIT_WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)"
        "TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter,bytes extra)"
    );
    string private constant DID = "did:sage:eip155:31337:0x2279b7a0a67db372996a5fab50d91eaa73d2ebe6:payment-agent";

    DemoUSD private token;
    address private permit2;
    X402ExactPermit2Proxy private proxy;
    SageDelegatedAccount private account;

    uint256 private userKey = 0xA11CE;
    uint256 private agentKey = 0xA6E17;
    uint256 private strangerKey = 0xBAD;
    address private user;
    address private agent;
    address private merchant = address(0x3E7C);
    address private other = address(0x07E7);

    function setUp() public {
        vm.warp(1_800_000_000);
        user = vm.addr(userKey);
        agent = vm.addr(agentKey);
        token = new DemoUSD(address(this));
        permit2 = deployCode("Permit2.sol:Permit2");
        proxy = new X402ExactPermit2Proxy(ISignatureTransfer(permit2));
        account = new SageDelegatedAccount(user, permit2, address(proxy));
        token.mint(user, 1_000e6);
        token.mint(address(account), 1_000e6);
        address[] memory payTos = new address[](1);
        payTos[0] = merchant;
        vm.startPrank(user);
        account.delegate(agent, DID, address(token), 10e6, uint64(block.timestamp + 1 days), payTos);
        account.setBudget(address(token), 25e6);
        vm.stopPrank();
    }

    // ---- Model A: EIP-3009 from an account the agent controls ----

    function test_ModelA_TransferWithAuthorization() public {
        bytes32 nonce = keccak256("a-1");
        (uint8 v, bytes32 r, bytes32 s) = _sign3009(userKey, user, merchant, 5e6, nonce);
        token.transferWithAuthorization(user, merchant, 5e6, block.timestamp - 1, block.timestamp + 60, nonce, v, r, s);
        assertEq(token.balanceOf(merchant), 5e6);
        vm.expectRevert(DemoUSD.AuthorizationAlreadyUsed.selector);
        token.transferWithAuthorization(user, merchant, 5e6, block.timestamp - 1, block.timestamp + 60, nonce, v, r, s);
    }

    function test_ModelA_TamperedRecipientRejected() public {
        bytes32 nonce = keccak256("a-2");
        (uint8 v, bytes32 r, bytes32 s) = _sign3009(userKey, user, merchant, 5e6, nonce);
        vm.expectRevert(DemoUSD.InvalidAuthorizationSignature.selector);
        token.transferWithAuthorization(user, other, 5e6, block.timestamp - 1, block.timestamp + 60, nonce, v, r, s);
    }

    // ---- Model B: delegated account through the x402 Permit2 proxy ----

    function test_ModelB_PaysWithinLimits() public {
        _settle(_payment(4e6, merchant, 1), agentKey);
        assertEq(token.balanceOf(merchant), 4e6);
        assertEq(token.allowance(address(account), permit2), 21e6);
    }

    function test_ModelB_RejectsOverPerPaymentCap() public {
        _expectRefusal(_payment(11e6, merchant, 2), agentKey, _aclRefusal());
    }

    function test_ModelB_RejectsRecipientOutsideAcl() public {
        _expectRefusal(_payment(1e6, other, 3), agentKey, _aclRefusal());
    }

    function test_ModelB_RejectsUndelegatedKey() public {
        _expectRefusal(_payment(1e6, merchant, 4), strangerKey, _aclRefusal());
    }

    function test_ModelB_RejectsAfterRevocation() public {
        vm.prank(user);
        account.revoke(agent);
        _expectRefusal(_payment(1e6, merchant, 5), agentKey, _aclRefusal());
    }

    function test_ModelB_RejectsAfterExpiry() public {
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(1e6, merchant, 6);
        vm.warp(block.timestamp + 2 days);
        p.deadline = vm.getBlockTimestamp() + 60;
        _expectRefusal(p, agentKey, _aclRefusal());
    }

    function test_ModelB_TotalBudgetEnforcedByAllowance() public {
        _settle(_payment(10e6, merchant, 7), agentKey);
        _settle(_payment(10e6, merchant, 8), agentKey);
        _expectRefusal(
            _payment(10e6, merchant, 9), agentKey, abi.encodeWithSignature("Error(string)", "TRANSFER_FROM_FAILED")
        );
        assertEq(token.balanceOf(merchant), 20e6);
    }

    function test_ModelB_NonceCannotBeReplayed() public {
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(1e6, merchant, 10);
        _settle(p, agentKey);
        _expectRefusal(p, agentKey, abi.encodeWithSelector(IPermit2Errors.InvalidNonce.selector));
    }

    function test_ModelB_RejectsEip3009FromAccount() public {
        bytes32 nonce = keccak256("b-3009");
        (uint8 v, bytes32 r, bytes32 s) = _sign3009(agentKey, address(account), merchant, 1e6, nonce);
        vm.expectRevert(DemoUSD.InvalidAuthorizationSignature.selector);
        token.transferWithAuthorization(
            address(account), merchant, 1e6, block.timestamp - 1, block.timestamp + 60, nonce, abi.encodePacked(r, s, v)
        );
    }

    function test_ModelB_OnlyOwnerChangesDelegation() public {
        address[] memory payTos = new address[](1);
        payTos[0] = other;
        vm.prank(agent);
        vm.expectRevert(SageDelegatedAccount.NotOwner.selector);
        account.delegate(agent, DID, address(token), 1_000e6, uint64(block.timestamp + 1 days), payTos);
    }

    // ---- helpers ----

    function _payment(uint256 amount, address to, uint256 nonce)
        private
        view
        returns (SageDelegatedAccount.PaymentAuthorization memory)
    {
        return SageDelegatedAccount.PaymentAuthorization({
            token: address(token),
            amount: amount,
            spender: address(proxy),
            nonce: nonce,
            deadline: block.timestamp + 60,
            to: to,
            validAfter: block.timestamp - 1,
            extra: ""
        });
    }

    function _accountSignature(SageDelegatedAccount.PaymentAuthorization memory p, uint256 key)
        private
        view
        returns (bytes memory)
    {
        bytes32 permitted = keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, p.token, p.amount));
        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, p.to, p.validAfter, keccak256(p.extra)));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                IPermit2Like(permit2).DOMAIN_SEPARATOR(),
                keccak256(abi.encode(PERMIT_WITNESS_TYPEHASH, permitted, p.spender, p.nonce, p.deadline, witness))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encode(p, abi.encodePacked(r, s, v));
    }

    function _call(SageDelegatedAccount.PaymentAuthorization memory p, uint256 key)
        private
        returns (bool, bytes memory)
    {
        ISignatureTransfer.PermitTransferFrom memory permit =
            ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({token: p.token, amount: p.amount}),
                nonce: p.nonce,
                deadline: p.deadline
            });
        X402ExactPermit2Proxy.Witness memory witness =
            X402ExactPermit2Proxy.Witness({to: p.to, validAfter: p.validAfter, extra: p.extra});
        return address(proxy)
            .call(abi.encodeCall(proxy.settle, (permit, address(account), witness, _accountSignature(p, key))));
    }

    function _settle(SageDelegatedAccount.PaymentAuthorization memory p, uint256 key) private {
        (bool ok,) = _call(p, key);
        assertTrue(ok, "settlement refused");
    }

    /// The refusal must come from the named check, not from an unrelated failure.
    function _expectRefusal(SageDelegatedAccount.PaymentAuthorization memory p, uint256 key, bytes memory reason)
        private
    {
        uint256 before = token.balanceOf(address(account));
        (bool ok, bytes memory data) = _call(p, key);
        assertFalse(ok, "settlement accepted");
        assertEq(data, reason, "unexpected refusal reason");
        assertEq(token.balanceOf(address(account)), before);
    }

    function _aclRefusal() private pure returns (bytes memory) {
        return abi.encodeWithSelector(IPermit2Errors.InvalidContractSignature.selector);
    }

    function _sign3009(uint256 key, address from, address to, uint256 value, bytes32 nonce)
        private
        view
        returns (uint8, bytes32, bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(),
                from,
                to,
                value,
                block.timestamp - 1,
                block.timestamp + 60,
                nonce
            )
        );
        return vm.sign(key, keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash)));
    }
}
