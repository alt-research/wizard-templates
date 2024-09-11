// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "forge-std/Test.sol";

import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TaskManager} from "../src/templates/TaskManager.sol";
import {IRegistryCoordinator} from "eigenlayer-middleware/src/BLSSignatureChecker.sol";
import "../src/Errors.sol";
import {BLSMockAVSDeployer} from "eigenlayer-middleware/test/utils/BLSMockAVSDeployer.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract TaskManagerMock is TaskManager {
    constructor(IRegistryCoordinator _registryCoordinator, uint32 _taskResponseWindowBlock)
        TaskManager(_registryCoordinator, _taskResponseWindowBlock)
    {}

    function initialize(address _aggregator, address _generator) external initializer {
        __TaskManager_init(_aggregator, _generator);
    }

    function createNewTask(bytes calldata message, uint32 quorumThresholdPercentage, bytes calldata quorumNumbers)
        external
    {
        _createNewTask(message, quorumThresholdPercentage, quorumNumbers);
    }

    function respondToTask(
        Task calldata task,
        TaskResponse calldata taskResponse,
        NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external {
        _respondToTask(task, taskResponse, nonSignerStakesAndSignature);
    }
}

contract TaskManagerTest is BLSMockAVSDeployer {
    TaskManagerMock public taskManager;
    TransparentUpgradeableProxy public proxy;
    address public owner;
    address public aggregator;
    address public generator;

    uint32 public constant TASK_RESPONSE_WINDOW_BLOCK = 30;

    event NewTaskCreated(uint32 indexed taskIndex, TaskManager.Task task);
    event TaskResponded(TaskManager.TaskResponse taskResponse, TaskManager.TaskResponseMetadata taskResponseMetadata);

    function setUp() public {
        owner = address(this);
        aggregator = address(0x101);
        generator = address(0x102);
        _setUpBLSMockAVSDeployer();

        taskManager =
            new TaskManagerMock(IRegistryCoordinator(address(registryCoordinator)), TASK_RESPONSE_WINDOW_BLOCK);

        proxyAdmin = new ProxyAdmin();

        proxy = new TransparentUpgradeableProxy(address(taskManager), address(proxyAdmin), "");

        taskManager = TaskManagerMock(address(proxy));
        taskManager.initialize(aggregator, generator);
    }

    function testInitialization() public {
        assertEq(taskManager.aggregator(), aggregator);
        assertEq(taskManager.generator(), generator);
    }

    function testCreateNewTask() public {
        bytes memory message = "Test message";
        uint32 quorumThresholdPercentage = 50;
        bytes memory quorumNumbers = "Test quorum numbers";

        vm.startPrank(generator);
        vm.expectEmit(true, true, true, true);
        emit NewTaskCreated(
            0,
            TaskManager.Task({
                taskCreatedBlock: uint32(block.number),
                quorumThresholdPercentage: quorumThresholdPercentage,
                message: message,
                quorumNumbers: quorumNumbers
            })
        );
        taskManager.createNewTask(message, quorumThresholdPercentage, quorumNumbers);
        vm.stopPrank();

        assertEq(taskManager.latestTaskNum(), 1);
        assertEq(
            taskManager.allTaskHashes(0),
            keccak256(
                abi.encode(
                    TaskManager.Task({
                        taskCreatedBlock: uint32(block.number),
                        quorumThresholdPercentage: quorumThresholdPercentage,
                        message: message,
                        quorumNumbers: quorumNumbers
                    })
                )
            )
        );
    }

    function testRevertIfNotAggregator() public {
        TaskManager.Task memory task;
        TaskManager.TaskResponse memory taskResponse;
        TaskManager.NonSignerStakesAndSignature memory nonSignerStakesAndSignature;

        vm.expectRevert("Aggregator must be the caller");
        taskManager.respondToTask(task, taskResponse, nonSignerStakesAndSignature);
    }

    function testRevertIfNotGenerator() public {
        bytes memory message = "Test message";
        uint32 quorumThresholdPercentage = 50;
        bytes memory quorumNumbers = "Test quorum numbers";

        vm.expectRevert("Task generator must be the caller");
        taskManager.createNewTask(message, quorumThresholdPercentage, quorumNumbers);
    }

    function testRevertIfZeroAddressAggregator() public {
        taskManager = new TaskManagerMock(IRegistryCoordinator(address(registryCoordinator)), 10);
        proxyAdmin = new ProxyAdmin();
        proxy = new TransparentUpgradeableProxy(address(taskManager), address(proxyAdmin), "");

        taskManager = TaskManagerMock(address(proxy));
        vm.expectRevert(ZeroAddress.selector);
        taskManager.initialize(address(0), generator);
    }

    function testRevertIfZeroAddressGenerator() public {
        taskManager = new TaskManagerMock(IRegistryCoordinator(address(registryCoordinator)), 10);
        proxyAdmin = new ProxyAdmin();
        proxy = new TransparentUpgradeableProxy(address(taskManager), address(proxyAdmin), "");

        taskManager = TaskManagerMock(address(proxy));
        vm.expectRevert(ZeroAddress.selector);
        taskManager.initialize(aggregator, address(0));
    }
}
