// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Versioning} from "@anoma-evm-pa/libs/Versioning.sol";

import {Script} from "forge-std/Script.sol";

import {ERC20Forwarder} from "../src/ERC20Forwarder.sol";

contract DeployERC20Forwarder is Script {
    function run(
        bool isTestDeployment,
        address protocolAdapter,
        bytes32 calldataCarrierLogicRef,
        address emergencyCommittee
    ) public {
        bytes32 salt;
        if (isTestDeployment) {
            salt = bytes32(block.prevrandao);
        } else {
            salt = keccak256(
                abi.encode(
                    "ERC20Forwarder",
                    Versioning._PROTOCOL_ADAPTER_VERSION
                )
            );
        }

        vm.startBroadcast();
        new ERC20Forwarder{salt: salt}({
            protocolAdapter: protocolAdapter,
            calldataCarrierLogicRef: calldataCarrierLogicRef,
            emergencyCommittee: emergencyCommittee
        });
        vm.stopBroadcast();
    }
}
