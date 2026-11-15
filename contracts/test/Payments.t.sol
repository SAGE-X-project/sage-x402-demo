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

    function test_ModelB_RejectsWellFormedEip3009FromAccount() public {
        bytes32 nonce = keccak256("b-3009-wf");
        bytes memory signature = _accountSignature(_payment(1e6, merchant, 11), agentKey);
        vm.expectRevert(DemoUSD.InvalidAuthorizationSignature.selector);
        token.transferWithAuthorization(
            address(account), merchant, 1e6, block.timestamp - 1, block.timestamp + 60, nonce, signature
        );
    }

    function test_ModelB_SignatureCannotReplayOnAnotherAccount() public {
        SageDelegatedAccount second = new SageDelegatedAccount(user, permit2, address(proxy));
        token.mint(address(second), 100e6);
        address[] memory payTos = new address[](1);
        payTos[0] = merchant;
        vm.startPrank(user);
        second.delegate(agent, DID, address(token), 10e6, uint64(block.timestamp + 1 days), payTos);
        second.setBudget(address(token), 25e6);
        vm.stopPrank();
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(4e6, merchant, 12);
        bytes memory signature = _accountSignature(p, agentKey);
        (bool ok,) = _callWith(account, p, signature);
        assertTrue(ok, "first account refused");
        (bool replayed, bytes memory reason) = _callWith(second, p, signature);
        assertFalse(replayed, "signature replayed on another account");
        assertEq(reason, _aclRefusal());
        assertEq(token.balanceOf(address(second)), 100e6);
    }

    function test_ModelB_RedelegationRetiresOldSignatures() public {
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(1e6, merchant, 13);
        bytes memory signature = _accountSignature(p, agentKey);
        address[] memory payTos = new address[](1);
        payTos[0] = merchant;
        vm.startPrank(user);
        account.revoke(agent);
        account.delegate(agent, DID, address(token), 10e6, uint64(block.timestamp + 1 days), payTos);
        vm.stopPrank();
        (bool ok, bytes memory reason) = _callWith(account, p, signature);
        assertFalse(ok, "old signature revived");
        assertEq(reason, _aclRefusal());
    }

    function test_ModelB_RejectsDeadlineBeyondDelegation() public {
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(1e6, merchant, 14);
        p.deadline = block.timestamp + 2 days;
        _expectRefusal(p, agentKey, _aclRefusal());
    }

    function test_ModelB_RejectsOtherToken() public {
        DemoUSD otherToken = new DemoUSD(address(this));
        otherToken.mint(address(account), 100e6);
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(1e6, merchant, 15);
        p.token = address(otherToken);
        (bool ok, bytes memory reason) = _callWith(account, p, _accountSignature(p, agentKey));
        assertFalse(ok, "other token accepted");
        assertEq(reason, _aclRefusal());
    }

    function test_ModelB_RejectsDirectPermit2Spender() public {
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(1e6, merchant, 16);
        p.spender = address(this);
        bytes memory signature = _accountSignature(p, agentKey);
        string memory witnessType = proxy.WITNESS_TYPE_STRING();
        vm.expectRevert(IPermit2Errors.InvalidContractSignature.selector);
        ISignatureTransfer(permit2)
            .permitWitnessTransferFrom(
                ISignatureTransfer.PermitTransferFrom({
                    permitted: ISignatureTransfer.TokenPermissions({token: p.token, amount: p.amount}),
                    nonce: p.nonce,
                    deadline: p.deadline
                }),
                ISignatureTransfer.SignatureTransferDetails({to: merchant, requestedAmount: p.amount}),
                address(account),
                keccak256(abi.encode(WITNESS_TYPEHASH, p.to, p.validAfter, keccak256(p.extra))),
                witnessType,
                signature
            );
    }

    function test_ModelB_RejectsHighSSignature() public {
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(1e6, merchant, 17);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentKey, account.agentDigest(p, agent));
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes memory signature = abi.encode(p, abi.encodePacked(agent, r, bytes32(n - uint256(s)), v == 27 ? 28 : 27));
        (bool ok, bytes memory reason) = _callWith(account, p, signature);
        assertFalse(ok, "malleable signature accepted");
        assertEq(reason, _aclRefusal());
    }

    function test_ModelB_RejectsTamperedRecipientAtSettle() public {
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(1e6, merchant, 18);
        bytes memory signature = _accountSignature(p, agentKey);
        p.to = other;
        (bool ok,) = _callWith(account, p, signature);
        assertFalse(ok, "tampered recipient accepted");
        assertEq(token.balanceOf(other), 0);
    }

    function test_ModelB_RejectsFutureValidAfter() public {
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(1e6, merchant, 19);
        p.validAfter = block.timestamp + 30;
        _expectRefusal(p, agentKey, abi.encodeWithSelector(X402ExactPermit2Proxy.PaymentNotYetValid.selector));
    }

    function test_ModelB_MalformedSignatureIsInvalidWithoutRevert() public view {
        assertEq(account.isValidSignature(bytes32(0), hex"deadbeef"), bytes4(0xffffffff));
        assertEq(
            account.isValidSignature(_permit2Digest(_payment(1e6, merchant, 20)), new bytes(64)), bytes4(0xffffffff)
        );
    }

    function test_ModelB_RefusesUnlimitedBudgetAndDuplicateRecipients() public {
        vm.startPrank(user);
        vm.expectRevert(SageDelegatedAccount.InvalidDelegation.selector);
        account.setBudget(address(token), type(uint256).max);
        address[] memory payTos = new address[](2);
        payTos[0] = merchant;
        payTos[1] = merchant;
        vm.expectRevert(SageDelegatedAccount.InvalidDelegation.selector);
        account.delegate(agent, DID, address(token), 1e6, uint64(block.timestamp + 1 days), payTos);
        vm.stopPrank();
    }

    function test_ModelB_RedelegationDropsOldRecipients() public {
        address[] memory payTos = new address[](1);
        payTos[0] = other;
        vm.prank(user);
        account.delegate(agent, DID, address(token), 10e6, uint64(block.timestamp + 1 days), payTos);
        _expectRefusal(_payment(1e6, merchant, 21), agentKey, _aclRefusal());
        _settle(_payment(1e6, other, 22), agentKey);
    }

    function test_SettleWithPermitSurvivesFrontRunPermit() public {
        // A plain EOA payer that never approved Permit2 uses the EIP-2612 extension.
        uint256 payerKey = 0xC0FFEE;
        address payer = vm.addr(payerKey);
        token.mint(payer, 10e6);
        (uint8 pv, bytes32 pr, bytes32 ps) = vm.sign(payerKey, _permit2612Digest(payer, 5e6, block.timestamp + 60));
        token.permit(payer, permit2, 5e6, block.timestamp + 60, pv, pr, ps); // front-run by anyone
        SageDelegatedAccount.PaymentAuthorization memory p = _payment(5e6, merchant, 23);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(payerKey, _permit2Digest(p));
        proxy.settleWithPermit(
            X402ExactPermit2Proxy.EIP2612Permit({value: 5e6, deadline: block.timestamp + 60, r: pr, s: ps, v: pv}),
            ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({token: p.token, amount: p.amount}),
                nonce: p.nonce,
                deadline: p.deadline
            }),
            payer,
            X402ExactPermit2Proxy.Witness({to: p.to, validAfter: p.validAfter, extra: p.extra}),
            abi.encodePacked(r, s, v)
        );
        assertEq(token.balanceOf(merchant), 5e6);
    }

    function test_DemoUSD_ReceiveRequiresPayee() public {
        bytes32 nonce = keccak256("recv");
        bytes32 structHash = keccak256(
            abi.encode(
                token.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(),
                user,
                merchant,
                1e6,
                block.timestamp - 1,
                block.timestamp + 60,
                nonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(userKey, keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash)));
        vm.expectRevert(DemoUSD.CallerMustBePayee.selector);
        token.receiveWithAuthorization(
            user, merchant, 1e6, block.timestamp - 1, block.timestamp + 60, nonce, abi.encodePacked(r, s, v)
        );
        vm.prank(merchant);
        token.receiveWithAuthorization(
            user, merchant, 1e6, block.timestamp - 1, block.timestamp + 60, nonce, abi.encodePacked(r, s, v)
        );
        assertEq(token.balanceOf(merchant), 1e6);
    }

    function test_DemoUSD_CanceledAuthorizationCannotBeUsed() public {
        bytes32 nonce = keccak256("cancel");
        (uint8 cv, bytes32 cr, bytes32 cs) = vm.sign(
            userKey,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    token.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(token.CANCEL_AUTHORIZATION_TYPEHASH(), user, nonce))
                )
            )
        );
        token.cancelAuthorization(user, nonce, abi.encodePacked(cr, cs, cv));
        (uint8 v, bytes32 r, bytes32 s) = _sign3009(userKey, user, merchant, 1e6, nonce);
        vm.expectRevert(DemoUSD.AuthorizationAlreadyUsed.selector);
        token.transferWithAuthorization(user, merchant, 1e6, block.timestamp - 1, block.timestamp + 60, nonce, v, r, s);
    }

    function _permit2612Digest(address owner, uint256 value, uint256 deadline) private view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                owner,
                permit2,
                value,
                token.nonces(owner),
                deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
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
        return _signFor(account, p, key);
    }

    function _signFor(SageDelegatedAccount target, SageDelegatedAccount.PaymentAuthorization memory p, uint256 key)
        private
        view
        returns (bytes memory)
    {
        address signer = vm.addr(key);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, target.agentDigest(p, signer));
        return abi.encode(p, abi.encodePacked(signer, r, s, v));
    }

    function _permit2Digest(SageDelegatedAccount.PaymentAuthorization memory p) private view returns (bytes32) {
        bytes32 permitted = keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, p.token, p.amount));
        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, p.to, p.validAfter, keccak256(p.extra)));
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                IPermit2Like(permit2).DOMAIN_SEPARATOR(),
                keccak256(abi.encode(PERMIT_WITNESS_TYPEHASH, permitted, p.spender, p.nonce, p.deadline, witness))
            )
        );
    }

    function _call(SageDelegatedAccount.PaymentAuthorization memory p, uint256 key)
        private
        returns (bool, bytes memory)
    {
        return _callWith(account, p, _accountSignature(p, key));
    }

    function _callWith(
        SageDelegatedAccount target,
        SageDelegatedAccount.PaymentAuthorization memory p,
        bytes memory signature
    ) private returns (bool, bytes memory) {
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: p.token, amount: p.amount}),
            nonce: p.nonce,
            deadline: p.deadline
        });
        X402ExactPermit2Proxy.Witness memory witness =
            X402ExactPermit2Proxy.Witness({to: p.to, validAfter: p.validAfter, extra: p.extra});
        return address(proxy).call(abi.encodeCall(proxy.settle, (permit, address(target), witness, signature)));
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
