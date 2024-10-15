// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import {ServiceManagerBase} from "eigenlayer-middleware/src/ServiceManagerBase.sol";
import {IIncredibleSquaringTaskManager} from "../interfaces/IIncredibleSquaringTaskManager.sol";
import {IAVSDirectory} from "eigenlayer-core/contracts/interfaces/IAVSDirectory.sol";
import {IRegistryCoordinator} from "eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";
import {IStakeRegistry} from "eigenlayer-middleware/src/interfaces/IStakeRegistry.sol";
import {IRewardsCoordinator} from "eigenlayer-core/contracts/interfaces/IRewardsCoordinator.sol";

/**
 * @title Primary entrypoint for procuring services from IncredibleSquaring.
 * @author Layr Labs, Inc.
 */
contract IncredibleSquaringTemplate is ServiceManagerBase {
    IIncredibleSquaringTaskManager public immutable incredibleSquaringTaskManager;

    /// @notice when applied to a function, ensures that the function is only callable by the `registryCoordinator`.
    modifier onlyIncredibleSquaringTaskManager() {
        require(
            msg.sender == address(incredibleSquaringTaskManager),
            "onlyIncredibleSquaringTaskManager: not from credible squaring task manager"
        );
        _;
    }

    constructor(
        IAVSDirectory __avsDirectory,
        IRewardsCoordinator __rewardsCoordinator,
        IRegistryCoordinator __registryCoordinator,
        IStakeRegistry __stakeRegistry,
        IIncredibleSquaringTaskManager __incredibleSquaringTaskManager
    ) ServiceManagerBase(__avsDirectory, __rewardsCoordinator, __registryCoordinator, __stakeRegistry) {
        incredibleSquaringTaskManager = __incredibleSquaringTaskManager;
    }

    /// @notice Called in the event of challenge resolution, in order to forward a call to the Slasher, which 'freezes' the `operator`.
    /// @dev The Slasher contract is under active development and its interface expected to change.
    ///      We recommend writing slashing logic without integrating with the Slasher at this point in time.
    function freezeOperator(address operatorAddr) external onlyIncredibleSquaringTaskManager {
        // slasher.freezeOperator(operatorAddr);
    }
}
