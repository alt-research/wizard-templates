// SPDX-License-Identifier: MIT
pragma solidity =0.8.26;

import "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {OperatorAllowlist} from "../src/templates/OperatorAllowlist.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "../src/Errors.sol";

contract OperatorAllowlistMock is OperatorAllowlist {
    function initialize(address _allowlistManager, bool _allowlistEnabled) external initializer {
        __Ownable_init();
        __OperatorAllowlist_init(_allowlistManager, _allowlistEnabled);
    }
}

contract OperatorAllowlistTest is Test {
    OperatorAllowlistMock public operatorAllowlist;
    ProxyAdmin public proxyAdmin;
    TransparentUpgradeableProxy public proxy;
    address public owner;
    address public allowlistManager;

    event AllowlistUpdated(address[] operators, bool[] status);
    event AllowlistEnabled();
    event AllowlistDisabled();
    event AllowlistManagerChanged(address indexed previousManager, address indexed newManager);

    function setUp() public {
        owner = address(this);
        allowlistManager = address(0x101);

        proxyAdmin = new ProxyAdmin();

        operatorAllowlist = OperatorAllowlistMock(
            address(new TransparentUpgradeableProxy(address(new OperatorAllowlistMock()), address(proxyAdmin), ""))
        );

        operatorAllowlist.initialize(allowlistManager, true);
        operatorAllowlist.transferOwnership(owner);
    }

    function testInitialization() public {
        assertEq(operatorAllowlist.allowlistManager(), allowlistManager);
        assertTrue(operatorAllowlist.allowlistEnabled());
        assertEq(operatorAllowlist.owner(), owner);
    }

    function testSetAllowlist() public {
        address[] memory operators = new address[](2);
        bool[] memory status = new bool[](2);
        operators[0] = address(0x102);
        operators[1] = address(0x103);
        status[0] = true;
        status[1] = true;

        vm.startPrank(allowlistManager);
        vm.expectEmit(true, true, true, true);
        emit AllowlistUpdated(operators, status);
        operatorAllowlist.setAllowlist(operators, status);
        vm.stopPrank();

        assertTrue(operatorAllowlist.isOperatorAllowed(operators[0]));
        assertTrue(operatorAllowlist.isOperatorAllowed(operators[1]));
    }

    function testEnableAllowlist() public {
        vm.prank(owner);
        operatorAllowlist.disableAllowlist();
        assertFalse(operatorAllowlist.allowlistEnabled());

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit AllowlistEnabled();
        operatorAllowlist.enableAllowlist();

        assertTrue(operatorAllowlist.allowlistEnabled());
    }

    function testDisableAllowlist() public {
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit AllowlistDisabled();
        operatorAllowlist.disableAllowlist();

        assertFalse(operatorAllowlist.allowlistEnabled());
    }

    function testSetAllowlistManager() public {
        address newManager = address(0x104);

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit AllowlistManagerChanged(allowlistManager, newManager);
        operatorAllowlist.setAllowlistManager(newManager);

        assertEq(operatorAllowlist.allowlistManager(), newManager);
    }

    function testRevertIfNotAllowlistManager() public {
        address[] memory operators = new address[](1);
        bool[] memory status = new bool[](1);
        operators[0] = address(0x102);
        status[0] = true;

        vm.expectRevert(OperatorAllowlist.NotAllowlistManager.selector);
        operatorAllowlist.setAllowlist(operators, status);
    }

    function testRevertIfZeroAddress() public {
        address[] memory operators = new address[](1);
        bool[] memory status = new bool[](1);
        operators[0] = address(0);
        status[0] = true;

        vm.startPrank(allowlistManager);
        vm.expectRevert(ZeroAddress.selector);
        operatorAllowlist.setAllowlist(operators, status);
        vm.stopPrank();
    }

    function testRevertIfAlreadyEnabled() public {
        vm.prank(owner);
        vm.expectRevert(OperatorAllowlist.AlreadyEnabled.selector);
        operatorAllowlist.enableAllowlist();
    }

    function testRevertIfAlreadyDisabled() public {
        vm.prank(owner);
        operatorAllowlist.disableAllowlist();
        vm.expectRevert(OperatorAllowlist.AlreadyDisabled.selector);
        operatorAllowlist.disableAllowlist();
    }

    function testQueryOperators() public {
        address[] memory operators = new address[](3);
        bool[] memory status = new bool[](3);
        operators[0] = address(0x102);
        operators[1] = address(0x103);
        operators[2] = address(0x104);
        status[0] = true;
        status[1] = false;
        status[2] = true;

        vm.startPrank(allowlistManager);
        operatorAllowlist.setAllowlist(operators, status);
        vm.stopPrank();

        // Query all operators
        address[] memory queriedOperators = operatorAllowlist.queryOperators(0, 3);
        address[] memory expectedOperators = new address[](2);
        expectedOperators[0] = operators[0];
        expectedOperators[1] = operators[2];
        assertEq(queriedOperators.length, expectedOperators.length);

        for (uint256 i = 0; i < expectedOperators.length; i++) {
            assertEq(queriedOperators[i], expectedOperators[i]);
        }

        // Query a subset of the allowed operators
        queriedOperators = operatorAllowlist.queryOperators(0, 1);
        assertEq(queriedOperators.length, 1);
        assertTrue(queriedOperators[0] == operators[0] || queriedOperators[0] == operators[2]);
    }

    function testGetAllowlistSize() public {
        address[] memory operators = new address[](3);
        bool[] memory status = new bool[](3);
        operators[0] = address(0x102);
        operators[1] = address(0x103);
        operators[2] = address(0x104);
        status[0] = true;
        status[1] = false;
        status[2] = true;

        vm.startPrank(allowlistManager);
        operatorAllowlist.setAllowlist(operators, status);
        vm.stopPrank();

        assertEq(operatorAllowlist.getAllowlistSize(), 2);
    }

    function testGetAllowlistAtIndex() public {
        address[] memory operators = new address[](3);
        bool[] memory status = new bool[](3);
        operators[0] = address(0x102);
        operators[1] = address(0x103);
        operators[2] = address(0x104);
        status[0] = true;
        status[1] = false;
        status[2] = true;

        vm.startPrank(allowlistManager);
        operatorAllowlist.setAllowlist(operators, status);
        vm.stopPrank();

        // Since the order is not guaranteed, we will check if the address is present in the set.
        address operator = operatorAllowlist.getAllowlistAtIndex(1);
        assertTrue(operator == operators[0] || operator == operators[2]);
    }

    function testRevertIfStartIndexOutOfBoundsInQueryOperators() public {
        address[] memory operators = new address[](1);
        bool[] memory status = new bool[](1);
        operators[0] = address(0x102);
        status[0] = true;

        vm.startPrank(allowlistManager);
        operatorAllowlist.setAllowlist(operators, status);
        vm.stopPrank();

        vm.expectRevert("Start index out of bounds");
        operatorAllowlist.queryOperators(2, 1);
    }
}
