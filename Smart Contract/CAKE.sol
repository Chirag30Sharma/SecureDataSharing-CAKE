// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CAKE {
    struct Document {
        string ipfsHash;
        string encryptionPolicy;
        address owner;
    }

    mapping(uint256 => Document) public documents;
    uint256 public documentCount;

    event DocumentStored(uint256 indexed documentId, address indexed owner, string ipfsHash, string encryptionPolicy);

    function storeDocument(string memory _ipfsHash, string memory _encryptionPolicy) public {
        documentCount++;
        documents[documentCount] = Document(_ipfsHash, _encryptionPolicy, msg.sender);
        emit DocumentStored(documentCount, msg.sender, _ipfsHash, _encryptionPolicy);
    }

    function getDocument(uint256 _documentId) public view returns (string memory, string memory, address) {
        require(_documentId <= documentCount && _documentId > 0, "Invalid document ID");
        Document memory doc = documents[_documentId];
        return (doc.ipfsHash, doc.encryptionPolicy, doc.owner);
    }

    function getDocumentCount() public view returns (uint256) {
        return documentCount;
    }

    function getDocumentsByOwner(address _owner) public view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](documentCount);
        uint256 counter = 0;
        for (uint256 i = 1; i <= documentCount; i++) {
            if (documents[i].owner == _owner) {
                result[counter] = i;
                counter++;
            }
        }
        
        // Resize the array to remove empty elements
        uint256[] memory finalResult = new uint256[](counter);
        for (uint256 i = 0; i < counter; i++) {
            finalResult[i] = result[i];
        }
        
        return finalResult;
    }
}