// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./zkbank/verifier.sol";

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ConfidentialBank is IConfidentialTransaction {
    struct Deposit {
        uint256 amount;
        address token;
        uint256 timestamp;
        bytes32 merkleRoot;
    }
    
    mapping(address => Deposit[]) public deposits;
    mapping(bytes32 => bool) public usedNonces;
    address public owner;
    address public verifier;
    
    event DepositEvent(address indexed account, uint256 amount, address token, uint256 timestamp, bytes32 merkleRoot);
    event WithdrawEvent(address indexed account, uint256 amount, address token);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    constructor(address _verifier) {
        owner = msg.sender;
        verifier = _verifier;
    }
    
    function encryptData(bytes memory _data, address _recipient) public view override returns (bytes memory) {
        return Verifier(verifier).encrypt(_data, _recipient);
    }
    
    function decryptData(bytes memory _encryptedData) public view override returns (bytes memory) {
        return Verifier(verifier).decrypt(_encryptedData);
    }
    
    function verifySignature(bytes memory _data, bytes memory _signature, address _signer) public view override returns (bool) {
        return Verifier(verifier).verify(_data, _signature, _signer);
    }
    
    function deposit(uint256 _amount, address _token, uint256 _timestamp, bytes32 _merkleRoot, bytes memory _proof) public {
        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "Transfer failed");
        require(!usedNonces[_merkleRoot], "Merkle root already used");
        require(Verifier(verifier).verifyDepositProof(_amount, _token, _timestamp, _merkleRoot, _proof), "Invalid proof");
        usedNonces[_merkleRoot] = true;
        deposits[msg.sender].push(Deposit(_amount, _token, _timestamp, _merkleRoot));
        emit DepositEvent(msg.sender, _amount, _token, _timestamp, _merkleRoot);
    }
    
    function withdraw(uint256 _index, bytes memory _encryptedData) public {
        Deposit memory depositItem = deposits[msg.sender][_index];
        require(IERC20(depositItem.token).balanceOf(address(this)) >= depositItem.amount, "Not enough balance");
        require(!usedNonces[depositItem.merkleRoot], "Merkle root already used");
        bytes memory decryptedData = decryptData(_encryptedData);
        require(verifySignature(decryptedData, abi.encode(msg.sender, depositItem.amount, depositItem.token), msg.sender), "Invalid signature");
        usedNonces[depositItem.merkleRoot] = true;
        require(IERC20(depositItem.token).transfer(msg.sender, depositItem.amount), "Transfer failed");
        emit WithdrawEvent(msg.sender, depositItem.amount, depositItem.token);
    }
    
    function setVerifier(address _verifier) public onlyOwner {
        verifier = _verifier;
    }
}
