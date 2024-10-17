// SPDX-License-Identifier: UNLICENSED
pragma solidity =0.8.26;

import "forge-std/Script.sol";
import {IAVSDirectory} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {IRegistryCoordinator} from "eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";
import {IStakeRegistry} from "@eigenlayer-middleware/src/interfaces/IStakeRegistry.sol";
import {DelegationManager} from "@eigenlayer/contracts/core/DelegationManager.sol";
import {BridgeTemplate} from "../src/templates/BridgeTemplate.sol";
import {GenericTemplate} from "../src/templates/GenericTemplate.sol";
import {HelloWorldTemplate} from "../src/templates/HelloWorldTemplate.sol";
import {
    IncredibleSquaringTemplate, IIncredibleSquaringTaskManager
} from "../src/templates/IncredibleSquaringTemplate.sol";

// forge script ./script/TemplateVerifier.s.sol --private-key $PK --rpc-url $URL --etherscan-api-key $API_KEY --broadcast -vvvv --slow --verify
contract TemplateVerifier is Script {
    function run() external {
        // Start broadcasting for deploying the contracts
        vm.startBroadcast();

        // Declare common constructor variables outside of the blocks
        IAVSDirectory avsDirectory = IAVSDirectory(0x055733000064333CaDDbC92763c58BF0192fFeBf); // Example AVSDirectory address
        IRewardsCoordinator rewardsCoordinator = IRewardsCoordinator(0x7750d328b314EfFa365A0402CcfD489B80B0adda); // Example RewardsCoordinator address
        IRegistryCoordinator registryCoordinator = IRegistryCoordinator(0x2be71952b8c308119983524d6f8B353Ce9ebb18e); // Example RegistryCoordinator address
        IStakeRegistry stakeRegistry = IStakeRegistry(0xD9d744228160E854d71Df753a2bb6BE9722196DE); // Example StakeRegistry address
        uint32 taskResponseWindowBlock = 100; // Task response window block for templates

        // Deploy HelloWorldTemplate contract
        new HelloWorldTemplate(
            address(avsDirectory), // Using the same AVSDirectory address
            address(stakeRegistry), // Using the same StakeRegistry address
            address(0xA44151489861Fe9e3055d95adC98FbD462B948e7) // DelegationManager address
        );

        // Deploy BridgeTemplate contract
        new BridgeTemplate(
            avsDirectory, rewardsCoordinator, registryCoordinator, stakeRegistry, taskResponseWindowBlock
        );

        // Deploy GenericTemplate contract
        new GenericTemplate(
            avsDirectory, rewardsCoordinator, registryCoordinator, stakeRegistry, taskResponseWindowBlock
        );

        // Deploy IncredibleSquaringTemplate contract
        new IncredibleSquaringTemplate(
            avsDirectory,
            rewardsCoordinator,
            registryCoordinator,
            stakeRegistry,
            IIncredibleSquaringTaskManager(address(0)) // Task Manager address
        );

        // End broadcasting
        vm.stopBroadcast();
    }
}
