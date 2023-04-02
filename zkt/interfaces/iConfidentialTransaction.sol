// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IConfidentialTransaction {
    function encryptData(bytes memory _data, address _recipient) external view returns (bytes memory);
    function decryptData(bytes memory _encryptedData) external view returns (bytes memory);
    function verifySignature(bytes memory _data, bytes memory _signature, address _signer) external view returns (bool);
}
