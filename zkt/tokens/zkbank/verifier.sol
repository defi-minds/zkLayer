// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
library Verifier {
    function verifyDepositProof(
        uint256 _amount,
        address _token,
        uint256 _timestamp,
        bytes32 _merkleRoot,
        bytes memory _proof
    ) public pure returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(_amount, _token, _timestamp));
        return MerkleProof.verify(_proof, _merkleRoot, leaf);
    }
    
    function encrypt(bytes memory _data, address _recipient) public pure returns (bytes memory) {
        bytes memory encodedData = abi.encodePacked(_data, _recipient);
        return encodedData;
    }
    
    function decrypt(bytes memory _encryptedData) public pure returns (bytes memory) {
        (bytes memory data, ) = abi.decode(_encryptedData, (bytes, address));
        return data;
    }
    
    function verify(bytes memory _data, bytes memory _signature, address _signer) public pure returns (bool) {
        bytes32 messageHash = keccak256(_data);
        address recoveredSigner = ECDSA.recover(messageHash, _signature);
        return recoveredSigner == _signer;
    }
}

library MerkleProof {
    function verify(
        bytes memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i += 32) {
            bytes32 proofElement;
            assembly {
                proofElement := mload(add(proof, add(32, i)))
            }
            if (computedHash < proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash == root;
    }
}
