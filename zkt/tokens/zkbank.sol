// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./zkbank/Verifier.sol";
import "./zkbank/MerkleProof.sol";

interface IVerifier {
    function verify(bytes calldata _data, bytes calldata _signature, address _signer) external view returns (bool);
    function encryptData(bytes calldata _data, address _recipient) external view returns (bytes memory);
    function verifyDepositProof(uint256 _amount, address _token, uint256 _timestamp, bytes32 _merkleRoot, bytes calldata _merkleProof) external view returns (bool);
}

contract ZkBank {
    using SafeMath for uint256;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public nullifiers;
    uint256 public totalDeposits;

    event Deposit(address indexed account, uint256 amount, bytes32 indexed nullifier);
    event Transfer(address indexed token, uint256 amount, address indexed recipient, bytes encryptedData);

    function deposit(bytes32 _nullifier) public payable {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        balances[msg.sender] = balances[msg.sender].add(msg.value);
        nullifiers[_nullifier] = true;
        totalDeposits = totalDeposits.add(1);
        emit Deposit(msg.sender, msg.value, _nullifier);
    }

    function transfer(address _token, uint256 _amount, address _recipient, bytes memory _data, bytes memory _signature, bytes32 _merkleRoot, bytes memory _proof, address verifier) public {
        require(IVerifier(verifier).verify(_data, _signature, msg.sender), "Invalid signature");
        bytes memory encryptedData = IVerifier(verifier).encryptData(_data, _recipient);
        require(IVerifier(verifier).verifyDepositProof(_amount, _token, block.timestamp, _merkleRoot, _proof), "Invalid proof");
        require(IERC20(_token).transferFrom(msg.sender, _recipient, _amount), "Transfer failed");
        emit Transfer(_token, _amount, _recipient, encryptedData);
    }
}
