// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.9;

import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import {BLSApkRegistry} from "eigenlayer-middleware/src/BLSApkRegistry.sol";
import {RegistryCoordinator} from "eigenlayer-middleware/src/RegistryCoordinator.sol";
import {BLSSignatureChecker, IRegistryCoordinator} from "eigenlayer-middleware/src/BLSSignatureChecker.sol";
import {ZeroAddress} from "../Errors.sol";

abstract contract TaskManager is BLSSignatureChecker, Initializable {
    event NewTaskCreated(uint32 indexed taskIndex, Task task);
    event TaskResponded(TaskResponse taskResponse, TaskResponseMetadata taskResponseMetadata);

    // STRUCTS
    struct Task {
        uint32 taskCreatedBlock;
        uint32 quorumThresholdPercentage;
        bytes message;
        bytes quorumNumbers;
    }

    // Task response is hashed and signed by operators.
    // these signatures are aggregated and sent to the contract as response.
    struct TaskResponse {
        // Can be obtained by the operator from the event NewTaskCreated.
        uint32 referenceTaskIndex;
        // This is just the response that the operator has to compute by itself.
        bytes message;
    }

    // Extra information related to taskResponse, which is filled inside the contract.
    // It thus cannot be signed by operators, so we keep it in a separate struct than TaskResponse
    // This metadata is needed by the challenger, so we emit it in the TaskResponded event
    struct TaskResponseMetadata {
        uint32 taskResponsedBlock;
        bytes32 hashOfNonSigners;
    }

    /* CONSTANT */
    uint256 internal constant _THRESHOLD_DENOMINATOR = 100;

    // The number of blocks from the task initialization within which the aggregator has to respond to
    uint32 public immutable TASK_RESPONSE_WINDOW_BLOCK;

    /* STORAGE */
    // The latest task index
    uint32 public latestTaskNum;

    // mapping of task indices to all tasks hashes
    // when a task is created, task hash is stored here,
    // and responses need to pass the actual task,
    // which is hashed onchain and checked against this mapping
    mapping(uint32 => bytes32) public allTaskHashes;

    // mapping of task indices to hash of abi.encode(taskResponse, taskResponseMetadata)
    mapping(uint32 => bytes32) public allTaskResponses;

    address public aggregator;
    address public generator;

    // storage gap for upgradeability
    // slither-disable-next-line shadowing-state
    uint256[45] private __GAP;

    /* MODIFIERS */
    modifier onlyAggregator() {
        require(msg.sender == aggregator, "Aggregator must be the caller");
        _;
    }

    // onlyTaskGenerator is used to restrict createNewTask from only being called by a permissioned entity
    // in a real world scenario, this would be removed by instead making createNewTask a payable function
    modifier onlyTaskGenerator() {
        require(msg.sender == generator, "Task generator must be the caller");
        _;
    }

    constructor(IRegistryCoordinator _registryCoordinator, uint32 _taskResponseWindowBlock)
        BLSSignatureChecker(_registryCoordinator)
    {
        TASK_RESPONSE_WINDOW_BLOCK = _taskResponseWindowBlock;
    }

    function __TaskManager_init(address _aggregator, address _generator) internal onlyInitializing {
        if (_aggregator == address(0)) {
            revert ZeroAddress();
        }
        if (_generator == address(0)) {
            revert ZeroAddress();
        }

        aggregator = _aggregator;
        generator = _generator;
    }

    /* FUNCTIONS */
    // NOTE: this function creates new task, assigns it a taskId
    function _createNewTask(bytes calldata message, uint32 quorumThresholdPercentage, bytes calldata quorumNumbers)
        internal
        onlyTaskGenerator
    {
        // create a new task struct
        Task memory newTask;
        newTask.message = message;
        newTask.taskCreatedBlock = uint32(block.number);
        newTask.quorumThresholdPercentage = quorumThresholdPercentage;
        newTask.quorumNumbers = quorumNumbers;

        // store hash of task onchain, emit event, and increase taskNum
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));
        emit NewTaskCreated(latestTaskNum, newTask);
        latestTaskNum = latestTaskNum + 1;
    }

    // NOTE: this function responds to existing tasks.
    function _respondToTask(
        Task calldata task,
        TaskResponse calldata taskResponse,
        NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) internal onlyAggregator {
        uint32 taskCreatedBlock = task.taskCreatedBlock;
        bytes calldata quorumNumbers = task.quorumNumbers;
        uint32 quorumThresholdPercentage = task.quorumThresholdPercentage;

        // check that the task is valid, hasn't been responsed yet, and is being responsed in time
        require(
            keccak256(abi.encode(task)) == allTaskHashes[taskResponse.referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );
        // some logical checks
        require(
            allTaskResponses[taskResponse.referenceTaskIndex] == bytes32(0),
            "Aggregator has already responded to the task"
        );
        require(
            uint32(block.number) <= taskCreatedBlock + TASK_RESPONSE_WINDOW_BLOCK,
            "Aggregator has responded to the task too late"
        );

        /* CHECKING SIGNATURES & WHETHER THRESHOLD IS MET OR NOT */
        // calculate message which operators signed
        bytes32 message = keccak256(abi.encode(taskResponse));

        // check the BLS signature
        (QuorumStakeTotals memory quorumStakeTotals, bytes32 hashOfNonSigners) =
            checkSignatures(message, quorumNumbers, taskCreatedBlock, nonSignerStakesAndSignature);

        // check that signatories own at least a threshold percentage of each quourm
        for (uint256 i = 0; i < quorumNumbers.length; i++) {
            // we don't check that the quorumThresholdPercentages are not >100 because a greater value would trivially fail the check, implying
            // signed stake > total stake
            require(
                quorumStakeTotals.signedStakeForQuorum[i] * _THRESHOLD_DENOMINATOR
                    >= quorumStakeTotals.totalStakeForQuorum[i] * uint8(quorumThresholdPercentage),
                "Signatories do not own at least threshold percentage of a quorum"
            );
        }

        TaskResponseMetadata memory taskResponseMetadata = TaskResponseMetadata(uint32(block.number), hashOfNonSigners);
        // updating the storage with task responsea
        allTaskResponses[taskResponse.referenceTaskIndex] = keccak256(abi.encode(taskResponse, taskResponseMetadata));

        // emitting event
        emit TaskResponded(taskResponse, taskResponseMetadata);
    }
}
