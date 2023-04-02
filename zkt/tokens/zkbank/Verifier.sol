// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Verifier {
    function verifyDepositProof(uint256 _amount, address _token, uint256 _timestamp, bytes32 _merkleRoot, bytes memory _proof) public pure returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(_amount, _token, _timestamp));
        return MerkleProof.verify(_proof, _merkleRoot, leaf);
    }
    
    function encrypt(bytes memory _data, address _recipient) public pure returns (bytes memory) {
        return abi.encode(_data, _recipient);
    }
    
    function decrypt(bytes memory _encryptedData) public pure returns (bytes memory, address) {
        (bytes memory data, address recipient) = abi.decode(_encryptedData, (bytes, address));
        return (data, recipient);
    }
    
    function verify(bytes memory _data, bytes memory _signature, address _signer) public pure returns (bool) {
        bytes32 messageHash = keccak256(_data);
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address recoveredAddress = ecrecover(prefixedHash, uint8(_signature[0]), abi.decode(_signature[1:33], uint256), abi.decode(_signature[33:65], uint256));
        return recoveredAddress == _signer;
    }
}

library MerkleProof {
    function verify(bytes memory proof, bytes32 root, bytes32 leaf) public pure returns (bool) {
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
