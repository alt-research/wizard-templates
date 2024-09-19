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
import {OperatorAllowlist} from "./OperatorAllowlist.sol";
import {BLSSignatureChecker, IRegistryCoordinator} from "eigenlayer-middleware/src/BLSSignatureChecker.sol";

contract CoprocessorTemplate is ServiceManagerBase, BLSSignatureChecker, Pausable, OperatorAllowlist {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

    event RequestVerified(bytes32 reqId, address sender);

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

    function initialize(
        IPauserRegistry pauserRegistry_,
        uint256 initialPausedStatus_,
        address initialOwner_,
        address rewardsInitiator_,
        address allowlistManager_
    ) external initializer {
        _initializePauser(pauserRegistry_, initialPausedStatus_);
        __ServiceManagerBase_init(initialOwner_, rewardsInitiator_);
        __OperatorAllowlist_init(allowlistManager_, true);
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

    function verifyRequest(
        bytes32 reqId, // msgHash
        bytes calldata quorumNumbers, // each byte is a different quorum number
            // the must have signed in the corresponding quorum in `quorumNumbers`
        uint32 referenceBlockNumber,
        NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external {
        // check the signature
        (QuorumStakeTotals memory quorumStakeTotals, /* bytes32 hashOfNonSigners */ ) = checkSignatures(
            reqId,
            quorumNumbers, // use list of uint8s instead of uint256 bitmap to not iterate 256 times
            referenceBlockNumber,
            nonSignerStakesAndSignature
        );

        uint256 quorumThresholdPercentage = 66;
        uint256 thresholdDenominator = 100;

        // check that signatories own at least a threshold percentage of each quourm
        for (uint256 i; i < quorumNumbers.length; i++) {
            // we don't check that the quorumThresholdPercentages are not >100 because a greater value would trivially fail the check, implying
            // signed stake > total stake
            require(
                quorumStakeTotals.signedStakeForQuorum[i] * thresholdDenominator
                    >= quorumStakeTotals.totalStakeForQuorum[i] * uint8(quorumThresholdPercentage),
                "Signatories do not own at least threshold percentage of a quorum"
            );
        }

        // emitting event
        emit RequestVerified(reqId, _msgSender());
    }
}
