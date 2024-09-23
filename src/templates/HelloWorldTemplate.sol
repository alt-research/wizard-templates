// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "eigenlayer-core/contracts/libraries/BytesLib.sol";
import "eigenlayer-core/contracts/core/DelegationManager.sol";
import "eigenlayer-core/contracts/permissions/Pausable.sol";
import "eigenlayer-middleware/src/unaudited/ECDSAServiceManagerBase.sol";
import "eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import {IRegistryCoordinator} from "eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";
import {ECDSAUpgradeable} from "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import {OperatorAllowlist} from "./OperatorAllowlist.sol";

/**
 * @title Primary entrypoint for procuring services from HelloWorld.
 * @author Eigen Labs, Inc.
 */
contract HelloWorldTemplate is ECDSAServiceManagerBase, OperatorAllowlist {
    using BytesLib for bytes;
    using ECDSAUpgradeable for bytes32;

    // EVENTS
    event NewTaskCreated(uint32 indexed taskIndex, Task task);

    event TaskResponded(uint32 indexed taskIndex, Task task, address operator);

    // STRUCTS
    struct Task {
        string name;
        uint32 taskCreatedBlock;
    }

    /* STORAGE */
    // The latest task index
    uint32 public latestTaskNum;

    // mapping of task indices to all tasks hashes
    // when a task is created, task hash is stored here,
    // and responses need to pass the actual task,
    // which is hashed onchain and checked against this mapping
    mapping(uint32 => bytes32) public allTaskHashes;

    // mapping of task indices to hash of abi.encode(taskResponse, taskResponseMetadata)
    mapping(address => mapping(uint32 => bytes)) public allTaskResponses;

    /* MODIFIERS */
    modifier onlyOperator() {
        require(ECDSAStakeRegistry(stakeRegistry).operatorRegistered(msg.sender), "Operator must be the caller");
        _;
    }

    constructor(address __avsDirectory, address __stakeRegistry, address __delegationManager)
        ECDSAServiceManagerBase(
            __avsDirectory,
            __stakeRegistry,
            address(0), // hello-world doesn't need to deal with payments
            __delegationManager
        )
    {}

    function initialize(address initialOwner_, address rewardsInitiator_, address allowlistManager_)
        external
        initializer
    {
        __ServiceManagerBase_init(initialOwner_, rewardsInitiator_);
        __OperatorAllowlist_init(allowlistManager_, true);
    }

    /* FUNCTIONS */
    // NOTE: this function creates new task, assigns it a taskId
    function createNewTask(string memory name) external {
        // create a new task struct
        Task memory newTask;
        newTask.name = name;
        newTask.taskCreatedBlock = uint32(block.number);

        // store hash of task onchain, emit event, and increase taskNum
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));
        emit NewTaskCreated(latestTaskNum, newTask);
        latestTaskNum = latestTaskNum + 1;
    }

    // NOTE: this function responds to existing tasks.
    function respondToTask(Task calldata task, uint32 referenceTaskIndex, bytes calldata signature)
        external
        onlyOperator
    {
        require(operatorHasMinimumWeight(msg.sender), "Operator does not have match the weight requirements");
        // check that the task is valid, hasn't been responsed yet, and is being responded in time
        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );
        // some logical checks
        require(
            allTaskResponses[msg.sender][referenceTaskIndex].length == 0, "Operator has already responded to the task"
        );

        // The message that was signed
        bytes32 messageHash = keccak256(abi.encodePacked("Hello, ", task.name));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();

        // Recover the signer address from the signature
        address signer = ethSignedMessageHash.recover(signature);

        require(signer == msg.sender, "Message signer is not operator");

        // updating the storage with task responses
        allTaskResponses[msg.sender][referenceTaskIndex] = signature;

        // emitting event
        emit TaskResponded(referenceTaskIndex, task, msg.sender);
    }

    // HELPER
    function operatorHasMinimumWeight(address operator) public view returns (bool) {
        return ECDSAStakeRegistry(stakeRegistry).getOperatorWeight(operator)
            >= ECDSAStakeRegistry(stakeRegistry).minimumWeight();
    }
}
