// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControl {
    struct AccessPolicy {
        string resourceId;
        string[] allowedActions;
        string[] requiredCredentials;
        bool isActive;
    }
    
    struct AccessLog {
        string proofId;
        string resourceId;
        string action;
        bool granted;
        uint256 timestamp;
    }
    
    address public owner;
    mapping(string => AccessPolicy) public policies;
    AccessLog[] public accessLogs;
    
    event PolicyAdded(string resourceId);
    event PolicyUpdated(string resourceId);
    event PolicyRevoked(string resourceId);
    event AccessGranted(string proofId, string resourceId, string action);
    event AccessDenied(string proofId, string resourceId, string action);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    function addPolicy(
        string memory resourceId,
        string[] memory allowedActions,
        string[] memory requiredCredentials
    ) public onlyOwner {
        policies[resourceId] = AccessPolicy({
            resourceId: resourceId,
            allowedActions: allowedActions,
            requiredCredentials: requiredCredentials,
            isActive: true
        });
        
        emit PolicyAdded(resourceId);
    }
    
    function updatePolicy(
        string memory resourceId,
        string[] memory allowedActions,
        string[] memory requiredCredentials
    ) public onlyOwner {
        require(policies[resourceId].isActive, "Policy does not exist");
        
        policies[resourceId].allowedActions = allowedActions;
        policies[resourceId].requiredCredentials = requiredCredentials;
        
        emit PolicyUpdated(resourceId);
    }
    
    function revokePolicy(string memory resourceId) public onlyOwner {
        require(policies[resourceId].isActive, "Policy does not exist");
        
        policies[resourceId].isActive = false;
        
        emit PolicyRevoked(resourceId);
    }
    
    function checkAccess(
        string memory proofId,
        string memory resourceId,
        string memory action,
        string[] memory presentedCredentials
    ) public returns (bool) {
        require(policies[resourceId].isActive, "Policy does not exist");
        
        AccessPolicy memory policy = policies[resourceId];
        
        // Check if action is allowed
        bool actionAllowed = false;
        for (uint i = 0; i < policy.allowedActions.length; i++) {
            if (keccak256(bytes(policy.allowedActions[i])) == keccak256(bytes(action))) {
                actionAllowed = true;
                break;
            }
        }
        
        if (!actionAllowed) {
            accessLogs.push(AccessLog({
                proofId: proofId,
                resourceId: resourceId,
                action: action,
                granted: false,
                timestamp: block.timestamp
            }));
            emit AccessDenied(proofId, resourceId, action);
            return false;
        }
        
        // Check if all required credentials are presented
        for (uint i = 0; i < policy.requiredCredentials.length; i++) {
            bool credentialFound = false;
            for (uint j = 0; j < presentedCredentials.length; j++) {
                if (keccak256(bytes(policy.requiredCredentials[i])) == keccak256(bytes(presentedCredentials[j]))) {
                    credentialFound = true;
                    break;
                }
            }
            if (!credentialFound) {
                accessLogs.push(AccessLog({
                    proofId: proofId,
                    resourceId: resourceId,
                    action: action,
                    granted: false,
                    timestamp: block.timestamp
                }));
                emit AccessDenied(proofId, resourceId, action);
                return false;
            }
        }
        
        accessLogs.push(AccessLog({
            proofId: proofId,
            resourceId: resourceId,
            action: action,
            granted: true,
            timestamp: block.timestamp
        }));
        emit AccessGranted(proofId, resourceId, action);
        return true;
    }
    
    function getAccessLogs() public view returns (AccessLog[] memory) {
        return accessLogs;
    }
} 