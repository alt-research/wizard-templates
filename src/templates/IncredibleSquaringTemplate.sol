// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "incredible-squaring-avs/src/IncredibleSquaringServiceManager.sol";

/**
 * @title Primary entrypoint for procuring services from IncredibleSquaring.
 * @author Layr Labs, Inc.
 */
contract IncredibleSquaringTemplate is IncredibleSquaringServiceManager {
    constructor(
        IAVSDirectory __avsDirectory,
        IRewardsCoordinator __rewardsCoordinator,
        IRegistryCoordinator __registryCoordinator,
        IStakeRegistry __stakeRegistry,
        IIncredibleSquaringTaskManager __incredibleSquaringTaskManager
    )
        IncredibleSquaringServiceManager(
            __avsDirectory,
            __rewardsCoordinator,
            __registryCoordinator,
            __stakeRegistry,
            __incredibleSquaringTaskManager
        )
    {}
}
