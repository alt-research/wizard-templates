// SPDX-License-Identifier: UNLICENSED
// SEE LICENSE IN https://files.altlayer.io/Alt-Research-License-1.md
// Copyright Alt Research Ltd. 2023. All rights reserved.
//
// You acknowledge and agree that Alt Research Ltd. ("Alt Research") (or Alt
// Research's licensors) own all legal rights, titles and interests in and to the
// work, software, application, source code, documentation and any other documents
//
//        db         888             88
//       d88b         88     88      88
//      d8'`8b        88     88      88
//     d8'  `8b       88   MM88MMM   88          ,adPPYYba,  8b       d8   ,adPPYba,  8b,dPPYb
//    d8YaaaaY8b      88     88      88          ""     `Y8  `8b     d8'  a8P_____88  88P'
//   d8""""""""8b     88     88      88          ,adPPPPP88   `8b   d8'   8PP"""""""  88
//  d8'        `8b    88     88,     88          88,    ,88    `8b,d8'    "8b,   ,aa  88
// d8'          `8b  8888    "Y888   88888888888 `"8bbdP"Y8      Y88'      `"Ybbd8"'  88
//                                                               d8'
//                                                              d8'

pragma solidity =0.8.26;

import {EnumerableSetUpgradeable} from "@openzeppelin-upgrades/contracts/utils/structs/EnumerableSetUpgradeable.sol";
import {Pausable} from "eigenlayer-core/contracts/permissions/Pausable.sol";
import {IAVSDirectory} from "eigenlayer-core/contracts/interfaces/IAVSDirectory.sol";
import {ISignatureUtils} from "eigenlayer-core/contracts/interfaces/ISignatureUtils.sol";
import {IPauserRegistry} from "eigenlayer-core/contracts/interfaces/IPauserRegistry.sol";
import {IRewardsCoordinator} from "eigenlayer-core/contracts/interfaces/IRewardsCoordinator.sol";
import {IServiceManager} from "eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {IStakeRegistry} from "eigenlayer-middleware/src/interfaces/IStakeRegistry.sol";
import {IRegistryCoordinator} from "eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";
import {ServiceManagerBase} from "eigenlayer-middleware/src/ServiceManagerBase.sol";
import {TaskManager} from "./TaskManager.sol";
import {OperatorAllowlist} from "./OperatorAllowlist.sol";

contract GenericTemplate is ServiceManagerBase, TaskManager, Pausable, OperatorAllowlist {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

    constructor(
        IAVSDirectory __avsDirectory,
        IRewardsCoordinator __rewardsCoordinator,
        IRegistryCoordinator __registryCoordinator,
        IStakeRegistry __stakeRegistry,
        uint32 _taskResponseWindowBlock
    )
        ServiceManagerBase(__avsDirectory, __rewardsCoordinator, __registryCoordinator, __stakeRegistry)
        TaskManager(__registryCoordinator, _taskResponseWindowBlock)
    {
        _disableInitializers();
    }

    function initialize(
        IPauserRegistry pauserRegistry_,
        uint256 initialPausedStatus_,
        address initialOwner_,
        address rewardsInitiator_,
        address allowlistManager_,
        address aggregator_,
        address generator_
    ) external initializer {
        _initializePauser(pauserRegistry_, initialPausedStatus_);
        __ServiceManagerBase_init(initialOwner_, rewardsInitiator_);
        __OperatorAllowlist_init(allowlistManager_, true);
        __TaskManager_init(aggregator_, generator_);
    }

    //////////////////////////////////////////////////////////////////////////////
    //                          Operator Registration                           //
    //////////////////////////////////////////////////////////////////////////////

    /**
     * @inheritdoc ServiceManagerBase
     */
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) public override(ServiceManagerBase) whenNotPaused onlyRegistryCoordinator {
        if (allowlistEnabled && !isOperatorAllowed(operator)) {
            revert NotAllowed();
        }

        // Stake requirement for quorum is checked in StakeRegistry.sol
        // https://github.com/Layr-Labs/eigenlayer-middleware/src/blob/dev/src/RegistryCoordinator.sol#L488
        // https://github.com/Layr-Labs/eigenlayer-middleware/src/blob/dev/src/StakeRegistry.sol#L84
        _avsDirectory.registerOperatorToAVS(operator, operatorSignature);
    }

    /**
     * @inheritdoc ServiceManagerBase
     */
    function deregisterOperatorFromAVS(address operator)
        public
        override(ServiceManagerBase)
        whenNotPaused
        onlyRegistryCoordinator
    {
        _avsDirectory.deregisterOperatorFromAVS(operator);
    }

    /* FUNCTIONS */
    // NOTE: this function creates new task, assigns it a taskId
    function createNewTask(bytes calldata message, uint32 quorumThresholdPercentage, bytes calldata quorumNumbers)
        external
    {
        super._createNewTask(message, quorumThresholdPercentage, quorumNumbers);
    }

    // NOTE: this function responds to existing tasks.
    function respondToTask(
        Task calldata task,
        TaskResponse calldata taskResponse,
        NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external {
        super._respondToTask(task, taskResponse, nonSignerStakesAndSignature);
    }
}
