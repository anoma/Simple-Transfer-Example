// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Parsing} from "@anoma-evm-pa-testing/libs/Parsing.sol";
import {DeployRiscZeroContracts} from "@anoma-evm-pa-testing/script/DeployRiscZeroContracts.s.sol";
import {ProtocolAdapter} from "@anoma-evm-pa/ProtocolAdapter.sol";

import {Time} from "@openzeppelin-contracts/utils/types/Time.sol";
import {IPermit2, ISignatureTransfer} from "@permit2/src/interfaces/IPermit2.sol";
import {RiscZeroGroth16Verifier} from "@risc0-ethereum/groth16/RiscZeroGroth16Verifier.sol";
import {RiscZeroVerifierRouter} from "@risc0-ethereum/RiscZeroVerifierRouter.sol";

import {Test, Vm, stdError} from "forge-std/Test.sol";

import {ERC20Forwarder} from "../src/ERC20Forwarder.sol";
import {ERC20ForwarderPermit2} from "../src/ERC20ForwarderPermit2.sol";

import {ERC20Example} from "../test/examples/ERC20.e.sol";
import {Permit2Signature} from "./libs/Permit2Signature.sol";
import {DeployPermit2} from "./script/DeployPermit2.s.sol";

contract ERC20ForwarderTest is Test {
    using ERC20ForwarderPermit2 for ERC20ForwarderPermit2.Witness;
    using Parsing for Vm;
    using Permit2Signature for Vm;

    address internal constant _EMERGENCY_COMMITTEE = address(uint160(1));
    uint128 internal constant _TRANSFER_AMOUNT = 1000;
    bytes internal constant _EXPECTED_OUTPUT = "";
    bytes32 internal constant _ACTION_TREE_ROOT = bytes32(uint256(0));

    bytes32 internal constant _CALLDATA_CARRIER_LOGIC_REF =
        0x81f8104fe367f5018a4bb0b259531be9ab35d3f1d51dea46c204bee154d5ee9e;

    address internal _alice;
    uint256 internal _alicePrivateKey;

    ProtocolAdapter internal _pa;
    ERC20Forwarder internal _fwd;
    IPermit2 internal _permit2;
    ERC20Example internal _erc20;

    ISignatureTransfer.PermitTransferFrom internal _defaultPermit;
    bytes internal _defaultPermitSig;
    bytes internal _defaultWrapInput;
    bytes internal _defaultUnwrapInput;

    // Copied since we can't `import {SignatureExpired, InvalidNonce} from "@permit2/src/PermitErrors.sol";`
    // because of the incompatible solc pragma.
    error SignatureExpired(uint256 signatureDeadline);
    error InvalidNonce();

    function setUp() public virtual {
        _alicePrivateKey = 0xc522337787f3037e9d0dcba4dc4c0e3d4eb7b1c65598d51c425574e8ce64d140;
        _alice = vm.addr(_alicePrivateKey);

        // Deploy token and mint for alice
        _erc20 = new ERC20Example();

        // Get the Permit2 contract
        _permit2 = _permit2Contract();

        // Deploy RISC Zero contracts
        (
            RiscZeroVerifierRouter router,
            ,
            RiscZeroGroth16Verifier verifier
        ) = new DeployRiscZeroContracts().run();

        // Deploy the protocol adapter
        _pa = new ProtocolAdapter(
            router,
            verifier.SELECTOR(),
            _EMERGENCY_COMMITTEE
        );

        // Deploy the ERC20 forwarder
        _fwd = new ERC20Forwarder({
            protocolAdapter: address(_pa),
            emergencyCommittee: _EMERGENCY_COMMITTEE,
            calldataCarrierLogicRef: _CALLDATA_CARRIER_LOGIC_REF
        });

        _defaultPermit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: address(_erc20),
                amount: _TRANSFER_AMOUNT
            }),
            nonce: 123,
            deadline: Time.timestamp() + 5 minutes
        });

        _defaultPermitSig = vm.permitWitnessTransferFromSignature({
            domainSeparator: _permit2.DOMAIN_SEPARATOR(),
            permit: _defaultPermit,
            privateKey: _alicePrivateKey,
            spender: address(_fwd),
            witness: ERC20ForwarderPermit2.Witness(_ACTION_TREE_ROOT).hash()
        });

        _defaultWrapInput = abi.encode(
            /*       callType */ ERC20Forwarder.CallType.Wrap,
            /*           from */ _alice,
            /*         permit */ _defaultPermit,
            /* actionTreeRoot */ _ACTION_TREE_ROOT,
            /*      signature */ _defaultPermitSig
        );

        _defaultUnwrapInput = abi.encode(
            /* callType */ ERC20Forwarder.CallType.Unwrap,
            /*    token */ address(_erc20),
            /*       to */ _alice,
            /*   amount */ _TRANSFER_AMOUNT
        );
    }

    function testFuzz_enum_panics(uint8 v) public {
        uint8 callTypeEnumLength = uint8(type(ERC20Forwarder.CallType).max) + 1;

        if (v < callTypeEnumLength) {
            ERC20Forwarder.CallType(v);
        } else {
            vm.expectRevert(stdError.enumConversionError);
            ERC20Forwarder.CallType(v);
        }
    }

    function test_unwrap_sends_funds_to_the_user() public {
        _erc20.mint({to: address(_fwd), value: _TRANSFER_AMOUNT});
        uint256 startBalanceAlice = _erc20.balanceOf(_alice);
        uint256 startBalanceForwarder = _erc20.balanceOf(address(_fwd));

        vm.prank(address(_pa));
        bytes memory output = _fwd.forwardCall({
            logicRef: _CALLDATA_CARRIER_LOGIC_REF,
            input: _defaultUnwrapInput
        });

        assertEq(keccak256(output), keccak256(_EXPECTED_OUTPUT));
        assertEq(
            _erc20.balanceOf(_alice),
            startBalanceAlice + _TRANSFER_AMOUNT
        );
        assertEq(
            _erc20.balanceOf(address(_fwd)),
            startBalanceForwarder - _TRANSFER_AMOUNT
        );
    }

    function test_unwrap_emits_the_Unwrapped_event() public {
        _erc20.mint({to: address(_fwd), value: _TRANSFER_AMOUNT});

        vm.prank(address(_pa));
        vm.expectEmit(address(_fwd));
        emit ERC20Forwarder.Unwrapped({
            token: address(_erc20),
            to: _alice,
            amount: _TRANSFER_AMOUNT
        });

        _fwd.forwardCall({
            logicRef: _CALLDATA_CARRIER_LOGIC_REF,
            input: _defaultUnwrapInput
        });
    }

    function test_wrap_reverts_if_user_did_not_approve_permit2() public {
        _erc20.mint({to: _alice, value: _TRANSFER_AMOUNT});

        vm.prank(address(_pa));
        vm.expectRevert("TRANSFER_FROM_FAILED", address(_erc20));
        _fwd.forwardCall({
            logicRef: _CALLDATA_CARRIER_LOGIC_REF,
            input: _defaultWrapInput
        });
    }

    function test_wrap_reverts_if_the_signature_expired() public {
        _erc20.mint({to: _alice, value: _TRANSFER_AMOUNT});
        vm.prank(_alice);
        _erc20.approve(address(_permit2), type(uint256).max);

        // Advance time after the deadline
        vm.warp(_defaultPermit.deadline + 1);

        vm.prank(address(_pa));
        vm.expectRevert(
            abi.encodeWithSelector(
                SignatureExpired.selector,
                _defaultPermit.deadline
            ),
            address(_permit2)
        );
        _fwd.forwardCall({
            logicRef: _CALLDATA_CARRIER_LOGIC_REF,
            input: _defaultWrapInput
        });
    }

    function test_wrap_reverts_if_the_signature_was_already_used() public {
        _erc20.mint({to: _alice, value: 2 * _TRANSFER_AMOUNT});
        vm.prank(_alice);
        _erc20.approve(address(_permit2), type(uint256).max);

        // Use the signature.
        vm.startPrank(address(_pa));
        _fwd.forwardCall({
            logicRef: _CALLDATA_CARRIER_LOGIC_REF,
            input: _defaultWrapInput
        });

        // Reuse the signature.
        vm.expectRevert(
            abi.encodeWithSelector(InvalidNonce.selector),
            address(_permit2)
        );
        _fwd.forwardCall({
            logicRef: _CALLDATA_CARRIER_LOGIC_REF,
            input: _defaultWrapInput
        });
    }

    function test_wrap_reverts_if_the_amount_to_be_wrapped_overflows() public {
        uint256 maxAmount = type(uint128).max;

        _erc20.mint({to: _alice, value: maxAmount + 1});
        vm.prank(_alice);
        _erc20.approve(address(_permit2), type(uint256).max);

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer
            .PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({
                    token: address(_erc20),
                    amount: maxAmount + 1
                }),
                nonce: 123,
                deadline: Time.timestamp() + 30 minutes
            });

        bytes memory input = abi.encode(
            /*       callType */ ERC20Forwarder.CallType.Wrap,
            /*           from */ _alice,
            /*         permit */ permit,
            /* actionTreeRoot */ _ACTION_TREE_ROOT,
            /*      signature */ _defaultPermitSig
        );

        vm.prank(address(_pa));
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC20Forwarder.TypeOverflow.selector,
                maxAmount,
                maxAmount + 1
            ),
            address(_fwd)
        );
        _fwd.forwardCall({logicRef: _CALLDATA_CARRIER_LOGIC_REF, input: input});
    }

    function test_wrap_pulls_funds_from_user() public {
        _erc20.mint({to: _alice, value: _TRANSFER_AMOUNT});
        uint256 startBalanceAlice = _erc20.balanceOf(_alice);
        uint256 startBalanceForwarder = _erc20.balanceOf(address(_fwd));

        vm.prank(_alice);
        _erc20.approve(address(_permit2), type(uint256).max);

        vm.prank(address(_pa));
        bytes memory output = _fwd.forwardCall({
            logicRef: _CALLDATA_CARRIER_LOGIC_REF,
            input: _defaultWrapInput
        });

        assertEq(keccak256(output), keccak256(_EXPECTED_OUTPUT));
        assertEq(
            _erc20.balanceOf(_alice),
            startBalanceAlice - _TRANSFER_AMOUNT
        );
        assertEq(
            _erc20.balanceOf(address(_fwd)),
            startBalanceForwarder + _TRANSFER_AMOUNT
        );
    }

    function test_wrap_emits_the_Wrapped_event() public {
        _erc20.mint({to: _alice, value: _TRANSFER_AMOUNT});

        vm.prank(_alice);
        _erc20.approve(address(_permit2), type(uint256).max);

        vm.prank(address(_pa));
        vm.expectEmit(address(_fwd));
        emit ERC20Forwarder.Wrapped({
            token: address(_erc20),
            from: _alice,
            amount: _TRANSFER_AMOUNT
        });
        _fwd.forwardCall({
            logicRef: _CALLDATA_CARRIER_LOGIC_REF,
            input: _defaultWrapInput
        });
    }

    function test_witness_typeHash_complies_with_eip712() public pure {
        assertEq(
            ERC20ForwarderPermit2._WITNESS_TYPEHASH,
            vm.eip712HashType(ERC20ForwarderPermit2._WITNESS_TYPE_DEF)
        );
    }

    function test_witness_structHash_complies_with_eip712() public pure {
        ERC20ForwarderPermit2.Witness memory witness = ERC20ForwarderPermit2
            .Witness({actionTreeRoot: bytes32(0)});
        assertEq(
            witness.hash(),
            vm.eip712HashStruct(
                ERC20ForwarderPermit2._WITNESS_TYPE_DEF,
                abi.encode(witness)
            )
        );
    }

    function _permit2Contract() internal virtual returns (IPermit2 permit2) {
        permit2 = new DeployPermit2().run();
    }
}
