// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import { Script, console } from "forge-std/src/Script.sol";
import { EntryPoint } from "@account-abstraction/contracts/core/EntryPoint.sol";
import { SimplePlusAccountFactory } from "../src/SimplePlusAccountFactory.sol";

contract DeploySimplePlusAccountFactory is Script {
    // Load entrypoint from env
    address public entryPointAddr = vm.envAddress("ENTRYPOINT");
    EntryPoint public entryPoint = EntryPoint(payable(entryPointAddr));

    function run() public {
        // Start broadcasting transactions using the deployer's private key
        vm.startBroadcast();

        // Log entrypoint address
        console.log("Entrypoint:", address(entryPoint));
        // ---
        console.log("Deploying:");
        console.log("");

        // Deploy the factory contract
        SimplePlusAccountFactory factory = new SimplePlusAccountFactory(entryPoint);

        // Log addresses of the deployed factory and the account implementation
        console.log("SimplePlusAccountFactory:", address(factory));
        console.log("SimplePlusAccount:", address(factory.accountImplementation()));
        console.log();

        // Stop broadcasting transactions
        vm.stopBroadcast();
    }
}
