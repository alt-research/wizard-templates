// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// @title IOperatorAllowlist Interface
/// @notice This interface defines the methods for managing and querying an operator allowlist
interface IOperatorAllowlist {
    /// @notice Emitted when the allowlist is updated with new operators and their status
    /// @param operators The list of operator addresses being updated
    /// @param status The corresponding status (allowed or disallowed) for each operator
    event AllowlistUpdated(address[] operators, bool[] status);

    /// @notice Emitted when the allowlist is enabled
    event AllowlistEnabled();

    /// @notice Emitted when the allowlist is disabled
    event AllowlistDisabled();

    /// @notice Emitted when the allowlist manager is changed
    /// @param previousManager The address of the previous allowlist manager
    /// @param newManager The address of the new allowlist manager
    event AllowlistManagerChanged(address indexed previousManager, address indexed newManager);

    /// @notice Updates the allowlist by adding or removing operators
    /// @param operators The array of operator addresses to be added or removed
    /// @param status The array of boolean values indicating whether to add (true) or remove (false) each operator
    function setAllowlist(address[] calldata operators, bool[] calldata status) external;

    /// @notice Enables the allowlist, making it active for operator registration
    function enableAllowlist() external;

    /// @notice Disables the allowlist, preventing any operator registration until re-enabled
    function disableAllowlist() external;

    /// @notice Sets the allowlist manager, who has permission to modify the allowlist
    /// @param _allowlistManager The address of the new allowlist manager
    function setAllowlistManager(address _allowlistManager) external;

    /// @notice Checks whether an operator is allowed on the allowlist
    /// @param operator The address of the operator to check
    /// @return True if the operator is allowed, false otherwise
    function isOperatorAllowed(address operator) external view returns (bool);

    /// @notice Returns the number of operators in the allowlist
    /// @return The size of the allowlist
    function getAllowlistSize() external view returns (uint256);

    /// @notice Returns the operator address at a specific index in the allowlist
    /// @param index The index of the operator in the allowlist
    /// @return The operator's address at the specified index
    function getAllowlistAtIndex(uint256 index) external view returns (address);

    /// @notice Returns a list of operators from a given starting index with a specific count
    /// @param start The index to start querying operators from
    /// @param count The number of operators to return
    /// @return operators The array of operator addresses queried
    function queryOperators(uint256 start, uint256 count) external view returns (address[] memory operators);
}
