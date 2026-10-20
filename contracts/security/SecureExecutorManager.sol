// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/**
 * @title SecureExecutorManager
 * @notice Secure executor management system that replaces address(0) executors
 * @dev Implements secure execution patterns with proper access controls
 */
contract SecureExecutorManager is Initializable, AccessControlUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable {
    // ============ Constants ============
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    
    // ============ State Variables ============
    mapping(address => bool) public authorizedExecutors;
    mapping(address => uint256) public executorLastUsed;
    mapping(address => uint256) public executorUsageCount;
    
    uint256 public maxExecutorsPerDay = 1000;
    uint256 public executorCooldownPeriod = 1 hours;
    uint256 public emergencyExecutorThreshold = 3; // Minimum executors for emergency mode
    
    // Execution tracking
    mapping(bytes32 => bool) public executedOperations;
    mapping(bytes32 => address) public operationExecutors;
    mapping(bytes32 => uint256) public operationTimestamps;

    // Appended fields preserve existing storage slots for upgradeable deployments.
    mapping(address => uint256) public executorUsageDay;
    uint256 public activeExecutorCount;
    bool private _executorCountInitialized;
    
    // ============ Events ============
    event ExecutorAdded(address indexed executor, address indexed addedBy);
    event ExecutorRemoved(address indexed executor, address indexed removedBy);
    event OperationExecuted(
        bytes32 indexed operationId,
        address indexed executor,
        address indexed target,
        uint256 timestamp
    );
    event EmergencyModeActivated(address indexed activatedBy);
    event EmergencyModeDeactivated(address indexed deactivatedBy);
    event ExecutorLimitUpdated(uint256 oldLimit, uint256 newLimit);
    event CooldownPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    
    // ============ Errors ============
    error ZeroAddress();
    error AlreadyExecutor();
    error NotExecutor();
    error ExecutorCooldownActive();
    error ExecutorLimitExceeded();
    error OperationAlreadyExecuted();
    error InvalidOperation();
    error InsufficientExecutors();
    error EmergencyModeRequired();
    error UnauthorizedExecutor();
    error InvalidParameters();
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
    
    /**
     * @notice Initialize the Secure Executor Manager
     * @param admin Initial admin address
     * @param initialExecutors Array of initial executor addresses
     */
    function initialize(
        address admin,
        address[] memory initialExecutors
    ) public initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        
        if (admin == address(0)) revert ZeroAddress();
        
        // Grant roles
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MANAGER_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);
        
        // New deployments initialize the executor count as executors are added.
        _executorCountInitialized = true;

        // Add initial executors
        for (uint256 i = 0; i < initialExecutors.length; i++) {
            if (initialExecutors[i] != address(0)) {
                _addExecutor(initialExecutors[i]);
            }
        }
        
        // Ensure we have at least one executor
        require(initialExecutors.length > 0, "At least one executor required");
    }
    
    /**
     * @notice Add a new executor
     * @param executor Address of the executor to add
     */
    function addExecutor(address executor) external onlyRole(MANAGER_ROLE) {
        if (!_executorCountInitialized) revert InvalidParameters();
        if (executor == address(0)) revert ZeroAddress();
        _addExecutor(executor);
        emit ExecutorAdded(executor, msg.sender);
    }
    
    /**
     * @notice Remove an executor
     * @param executor Address of the executor to remove
     */
    function removeExecutor(address executor) external onlyRole(MANAGER_ROLE) {
        if (!_executorCountInitialized) revert InvalidParameters();
        if (!authorizedExecutors[executor]) revert NotExecutor();
        
        // Check if removing this executor would leave insufficient executors
        uint256 executorCount = _getExecutorCount();
        if (executorCount <= 1) {
            revert InsufficientExecutors();
        }
        
        authorizedExecutors[executor] = false;
        delete executorLastUsed[executor];
        delete executorUsageCount[executor];
        delete executorUsageDay[executor];
        activeExecutorCount--;
        
        emit ExecutorRemoved(executor, msg.sender);
    }
    
    /**
     * @notice Execute an operation (replaces address(0) execution)
     * @param operationId Unique identifier for the operation
     * @param target Target contract address
     * @param data Call data
     * @param value ETH value to send
     */
    function executeOperation(
        bytes32 operationId,
        address target,
        bytes memory data,
        uint256 value
    ) external nonReentrant whenNotPaused returns (bool success, bytes memory returnData) {
        // Check if caller is authorized executor
        if (!authorizedExecutors[msg.sender]) revert UnauthorizedExecutor();
        
        // Check if operation already executed
        if (executedOperations[operationId]) revert OperationAlreadyExecuted();
        
        // Check executor cooldown
        if (block.timestamp < executorLastUsed[msg.sender] + executorCooldownPeriod) {
            revert ExecutorCooldownActive();
        }
        
        // Reset usage at the start of each UTC day.
        uint256 currentDay = block.timestamp / 1 days;
        uint256 usedToday = executorUsageDay[msg.sender] == currentDay
            ? executorUsageCount[msg.sender]
            : 0;
        if (usedToday >= maxExecutorsPerDay) {
            revert ExecutorLimitExceeded();
        }
        
        // Validate target
        if (target == address(0)) revert InvalidOperation();
        
        // Execute first. A failed target call must not consume the operation ID
        // or the executor's quota; nonReentrant prevents callback replay.
        (success, returnData) = target.call{value: value}(data);
        if (success) {
            executedOperations[operationId] = true;
            operationExecutors[operationId] = msg.sender;
            operationTimestamps[operationId] = block.timestamp;
            executorLastUsed[msg.sender] = block.timestamp;
            executorUsageDay[msg.sender] = currentDay;
            executorUsageCount[msg.sender] = usedToday + 1;
            emit OperationExecuted(operationId, msg.sender, target, block.timestamp);
        }
        
        return (success, returnData);
    }
    
    /**
     * @notice Emergency execution (bypasses some restrictions)
     * @param operationId Unique identifier for the operation
     * @param target Target contract address
     * @param data Call data
     * @param value ETH value to send
     */
    function emergencyExecute(
        bytes32 operationId,
        address target,
        bytes memory data,
        uint256 value
    ) external onlyRole(EMERGENCY_ROLE) nonReentrant returns (bool success, bytes memory returnData) {
        // Check if operation already executed
        if (executedOperations[operationId]) revert OperationAlreadyExecuted();
        
        // Validate target
        if (target == address(0)) revert InvalidOperation();
        
        // Failed emergency calls remain retryable; only record successful execution.
        (success, returnData) = target.call{value: value}(data);
        if (success) {
            executedOperations[operationId] = true;
            operationExecutors[operationId] = msg.sender;
            operationTimestamps[operationId] = block.timestamp;
            emit OperationExecuted(operationId, msg.sender, target, block.timestamp);
        }
        
        return (success, returnData);
    }
    
    /**
     * @notice Activate emergency mode (anyone can execute)
     */
    function activateEmergencyMode() external onlyRole(EMERGENCY_ROLE) {
        _pause();
        emit EmergencyModeActivated(msg.sender);
    }
    
    /**
     * @notice Deactivate emergency mode
     */
    function deactivateEmergencyMode() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
        emit EmergencyModeDeactivated(msg.sender);
    }
    
    /**
     * @notice Update executor daily limit
     * @param newLimit New daily limit
     */
    function updateExecutorLimit(uint256 newLimit) external onlyRole(MANAGER_ROLE) {
        uint256 oldLimit = maxExecutorsPerDay;
        maxExecutorsPerDay = newLimit;
        emit ExecutorLimitUpdated(oldLimit, newLimit);
    }
    
    /**
     * @notice Update executor cooldown period
     * @param newPeriod New cooldown period in seconds
     */
    function updateCooldownPeriod(uint256 newPeriod) external onlyRole(MANAGER_ROLE) {
        uint256 oldPeriod = executorCooldownPeriod;
        executorCooldownPeriod = newPeriod;
        emit CooldownPeriodUpdated(oldPeriod, newPeriod);
    }
    
    // ============ Internal Functions ============
    
    function _addExecutor(address executor) internal {
        if (authorizedExecutors[executor]) revert AlreadyExecutor();
        authorizedExecutors[executor] = true;
        activeExecutorCount++;
        _grantRole(EXECUTOR_ROLE, executor);
    }

    /**
     * @notice Initialize executor counting on an existing proxy after upgrading.
     * @dev Pass every currently authorized executor exactly once. New deployments
     *      initialize this counter automatically in initialize().
     */
    function initializeExecutorCount(address[] calldata currentExecutors)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (_executorCountInitialized) revert InvalidParameters();
        if (currentExecutors.length == 0) revert InsufficientExecutors();

        uint256 count;
        for (uint256 i = 0; i < currentExecutors.length; i++) {
            address executor = currentExecutors[i];
            if (executor == address(0) || !authorizedExecutors[executor]) {
                revert InvalidParameters();
            }
            for (uint256 j = 0; j < i; j++) {
                if (currentExecutors[j] == executor) revert InvalidParameters();
            }
            count++;
        }

        if (count == 0) revert InsufficientExecutors();
        activeExecutorCount = count;
        _executorCountInitialized = true;
    }

    function _getExecutorCount() internal view returns (uint256) {
        return activeExecutorCount;
    }
    
    // ============ View Functions ============
    
    /**
     * @notice Check if an address is an authorized executor
     */
    function isAuthorizedExecutor(address executor) external view returns (bool) {
        return authorizedExecutors[executor];
    }
    
    /**
     * @notice Check if executor can execute (not in cooldown, within limits)
     */
    function canExecute(address executor) external view returns (bool) {
        if (!authorizedExecutors[executor]) return false;
        if (block.timestamp < executorLastUsed[executor] + executorCooldownPeriod) return false;
        uint256 usedToday = executorUsageDay[executor] == block.timestamp / 1 days
            ? executorUsageCount[executor]
            : 0;
        if (usedToday >= maxExecutorsPerDay) return false;
        return true;
    }
    
    /**
     * @notice Get executor usage information
     */
    function getExecutorInfo(address executor) external view returns (
        bool authorized,
        uint256 lastUsed,
        uint256 usageCount,
        bool canExecuteNow
    ) {
        authorized = authorizedExecutors[executor];
        lastUsed = executorLastUsed[executor];
        usageCount = executorUsageDay[executor] == block.timestamp / 1 days
            ? executorUsageCount[executor]
            : 0;
        canExecuteNow = authorized &&
                       block.timestamp >= lastUsed + executorCooldownPeriod &&
                       usageCount < maxExecutorsPerDay;
    }
    
    /**
     * @notice Check if operation was executed
     */
    function wasOperationExecuted(bytes32 operationId) external view returns (bool) {
        return executedOperations[operationId];
    }
    
    /**
     * @notice Get operation details
     */
    function getOperationDetails(bytes32 operationId) external view returns (
        bool executed,
        address executor,
        uint256 timestamp
    ) {
        executed = executedOperations[operationId];
        executor = operationExecutors[operationId];
        timestamp = operationTimestamps[operationId];
    }
}
