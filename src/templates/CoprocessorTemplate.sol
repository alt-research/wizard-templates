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
//
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
import {OperatorAllowlist} from "./OperatorAllowlist.sol";
import {BLSSignatureChecker, IRegistryCoordinator} from "eigenlayer-middleware/src/BLSSignatureChecker.sol";

/// @title CoprocessorTemplate Contract
/// @dev This contract manages operator registration, verification of requests, and interactions with other Eigenlayer components. It also includes access control mechanisms for the aggregator.
contract CoprocessorTemplate is ServiceManagerBase, BLSSignatureChecker, Pausable, OperatorAllowlist {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

    /// @notice Emitted when a request is successfully verified.
    /// @param reqId The unique identifier of the request (message hash).
    /// @param sender The address that triggered the verification.
    event RequestVerified(bytes32 reqId, address sender);

    /// @notice Emitted when the aggregator address is updated.
    /// @param oldAggregator The previous aggregator address.
    /// @param newAggregator The new aggregator address.
    event AggregatorUpdated(address indexed oldAggregator, address indexed newAggregator);

    /// @dev Address of the aggregator responsible for verifying requests.
    address public aggregator;

    /// @dev Modifier to restrict function access to only the aggregator.
    modifier onlyAggregator() {
        require(msg.sender == aggregator, "Only aggregator can call this function");
        _;
    }

    /// @notice Initializes the contract with required dependencies.
    /// @param __avsDirectory Address of the AVS directory contract.
    /// @param __rewardsCoordinator Address of the rewards coordinator contract.
    /// @param __registryCoordinator Address of the registry coordinator contract.
    /// @param __stakeRegistry Address of the stake registry contract.
    constructor(
        IAVSDirectory __avsDirectory,
        IRewardsCoordinator __rewardsCoordinator,
        IRegistryCoordinator __registryCoordinator,
        IStakeRegistry __stakeRegistry
    )
        ServiceManagerBase(__avsDirectory, __rewardsCoordinator, __registryCoordinator, __stakeRegistry)
        BLSSignatureChecker(__registryCoordinator)
    {
        _disableInitializers();
    }

    /// @notice Initializes the contract with the given parameters.
    /// @param pauserRegistry_ Address of the pauser registry.
    /// @param initialPausedStatus_ Initial paused status.
    /// @param initialOwner_ Address of the contract owner.
    /// @param rewardsInitiator_ Address responsible for initiating rewards.
    /// @param allowlistManager_ Address of the allowlist manager.
    /// @param aggregator_ Initial aggregator address.
    function initialize(
        IPauserRegistry pauserRegistry_,
        uint256 initialPausedStatus_,
        address initialOwner_,
        address rewardsInitiator_,
        address allowlistManager_,
        address aggregator_
    ) external initializer {
        _initializePauser(pauserRegistry_, initialPausedStatus_);
        __ServiceManagerBase_init(initialOwner_, rewardsInitiator_);
        __OperatorAllowlist_init(allowlistManager_, true);
        _setAggregator(aggregator_);
    }

    /// @notice Sets a new aggregator address.
    /// @dev Only callable by the contract owner.
    /// @param newAggregator Address of the new aggregator.
    function setAggregator(address newAggregator) external onlyOwner {
        _setAggregator(newAggregator);
    }

    /// @dev Internal function to update the aggregator address.
    /// @param newAggregator Address of the new aggregator.
    function _setAggregator(address newAggregator) internal {
        require(newAggregator != address(0), "Aggregator cannot be the zero address");
        address oldAggregator = aggregator;
        aggregator = newAggregator;
        emit AggregatorUpdated(oldAggregator, newAggregator);
    }

    //////////////////////////////////////////////////////////////////////////////
    //                          Operator Registration                           //
    //////////////////////////////////////////////////////////////////////////////

    /**
     * @inheritdoc ServiceManagerBase
     * @dev Registers an operator to the AVS (Aggregation Verification Service).
     */
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) public override(ServiceManagerBase) whenNotPaused onlyRegistryCoordinator {
        if (allowlistEnabled && !isOperatorAllowed(operator)) {
            revert NotAllowed();
        }
        _avsDirectory.registerOperatorToAVS(operator, operatorSignature);
    }

    /**
     * @inheritdoc ServiceManagerBase
     * @dev Deregisters an operator from the AVS.
     */
    function deregisterOperatorFromAVS(address operator)
        public
        override(ServiceManagerBase)
        whenNotPaused
        onlyRegistryCoordinator
    {
        _avsDirectory.deregisterOperatorFromAVS(operator);
    }

    /// @notice Verifies the request, only callable by the aggregator.
    /// @dev Ensures that the request is signed by the required quorums.
    /// @param reqId Hash of the request message.
    /// @param quorumNumbers Byte array representing different quorum numbers.
    /// @param referenceBlockNumber Block number used for quorum signature validation.
    /// @param nonSignerStakesAndSignature Contains stakes and BLS signature of non-signers.
    function verifyRequest(
        bytes32 reqId,
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external onlyAggregator {
        // check the signature
        (QuorumStakeTotals memory quorumStakeTotals, /* bytes32 hashOfNonSigners */ ) =
            checkSignatures(reqId, quorumNumbers, referenceBlockNumber, nonSignerStakesAndSignature);

        uint256 quorumThresholdPercentage = 66;
        uint256 thresholdDenominator = 100;

        // check that signatories own at least a threshold percentage of each quorum
        for (uint256 i; i < quorumNumbers.length; i++) {
            // we don't check that the quorumThresholdPercentages are not >100 because a greater value would trivially fail the check, implying
            // signed stake > total stake
            require(
                quorumStakeTotals.signedStakeForQuorum[i] * thresholdDenominator
                    >= quorumStakeTotals.totalStakeForQuorum[i] * uint8(quorumThresholdPercentage),
                "Signatories do not own at least threshold percentage of a quorum"
            );
        }

        // emit event
        emit RequestVerified(reqId, _msgSender());
    }
}
