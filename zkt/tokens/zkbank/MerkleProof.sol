// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

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
