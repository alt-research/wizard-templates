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

import {ContextUpgradeable} from "@openzeppelin-upgrades/contracts/utils/ContextUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import {EnumerableSetUpgradeable} from "@openzeppelin-upgrades/contracts/utils/structs/EnumerableSetUpgradeable.sol";
import {ZeroAddress} from "../Errors.sol";
import {IOperatorAllowlist} from "../interfaces/IOperatorAllowlist.sol";

abstract contract OperatorAllowlist is IOperatorAllowlist, ContextUpgradeable, OwnableUpgradeable {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

    error NotAllowed();
    error NotAllowlistManager();
    error AlreadyEnabled();
    error AlreadyDisabled();

    /// @notice Set of operators that are allowed to register
    EnumerableSetUpgradeable.AddressSet private _allowlist;

    /// @notice Whether or not the allowlist is enabled
    bool public allowlistEnabled;

    /// @notice Role for whitelisting operators
    address public allowlistManager;

    // storage gap for upgradeability
    // slither-disable-next-line shadowing-state
    uint256[47] private __GAP;

    /**
     * @dev Ensures that the function is only callable by the `allowlistManager`.
     */
    modifier onlyAllowlistManager() {
        if (_msgSender() != allowlistManager) {
            revert NotAllowlistManager();
        }
        _;
    }

    function __OperatorAllowlist_init(address _allowlistManager, bool _allowlistEnabled) internal onlyInitializing {
        _setAllowlistManager(_allowlistManager);
        allowlistEnabled = _allowlistEnabled;
    }

    function setAllowlist(address[] calldata operators, bool[] calldata status) external onlyAllowlistManager {
        require(operators.length == status.length, "Input arrays length mismatch");

        for (uint256 i = 0; i < operators.length; ++i) {
            address operator = operators[i];

            if (operator == address(0)) {
                revert ZeroAddress();
            }

            if (status[i]) {
                _allowlist.add(operator);
            } else {
                _allowlist.remove(operator);
            }
        }
        emit AllowlistUpdated(operators, status);
    }

    function enableAllowlist() external onlyOwner {
        _setAllowlistStatus(true);
    }

    function disableAllowlist() external onlyOwner {
        _setAllowlistStatus(false);
    }

    function setAllowlistManager(address _allowlistManager) external onlyOwner {
        _setAllowlistManager(_allowlistManager);
    }

    function isOperatorAllowed(address operator) public view returns (bool) {
        return _allowlist.contains(operator);
    }

    function getAllowlistSize() public view returns (uint256) {
        return _allowlist.length();
    }

    function getAllowlistAtIndex(uint256 index) public view returns (address) {
        return _allowlist.at(index);
    }

    function queryOperators(uint256 start, uint256 count) external view returns (address[] memory operators) {
        uint256 length = _allowlist.length();
        require(start < length, "Start index out of bounds");

        uint256 end = start + count;
        if (end > length) {
            end = length;
        }

        uint256 querySize = end - start;
        operators = new address[](querySize);

        for (uint256 i = 0; i < querySize; ++i) {
            operators[i] = _allowlist.at(start + i);
        }

        return operators;
    }

    /**
     *  @dev Sets the allowlist status
     *  @param enable A boolean indicating whether to enable or disable the allowlist
     */
    function _setAllowlistStatus(bool enable) internal {
        if (enable) {
            if (allowlistEnabled) {
                revert AlreadyEnabled();
            } else {
                allowlistEnabled = true;
                emit AllowlistEnabled();
            }
        } else {
            if (!allowlistEnabled) {
                revert AlreadyDisabled();
            } else {
                allowlistEnabled = false;
                emit AllowlistDisabled();
            }
        }
    }

    /**
     *  @dev Changes the allowlistManager
     */
    function _setAllowlistManager(address allowlistManager_) internal {
        emit AllowlistManagerChanged(allowlistManager, allowlistManager_);
        allowlistManager = allowlistManager_;
    }
}
