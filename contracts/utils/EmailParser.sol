// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

contract EmailParser {
    struct DKIMSignFields {
        string to;
        string from;
        string subject;
        string messageId;
        string date;
        string mimeVersion;
        string dkimSignature;
    }

    function getSignMsg(DKIMSignFields memory signFields) internal pure returns (bytes memory) {
        string memory crlf = "\r\n";
        return abi.encodePacked(
            string.concat("to:", signFields.to, crlf),
            string.concat("subject:", signFields.subject, crlf),
            string.concat("message-id:", signFields.messageId, crlf),
            string.concat("date:", signFields.date, crlf),
            string.concat("from:", signFields.from, crlf),
            string.concat("mime-version:", signFields.mimeVersion, crlf),
            string.concat("dkim-signature:", signFields.dkimSignature)
        );
    }

    function parseHeaderFileds(bytes calldata header) internal pure returns (DKIMSignFields memory) {
        // parse the first 4 bytes to get the length of the original string
        require(header.length >= 4, "EmailParser: Invalid header length");
        uint32 length = uint32(uint8(header[0])) * 0x1000000 + uint32(uint8(header[1])) * 0x10000 + uint32(uint8(header[2])) * 0x100 + uint32(uint8(header[3]));
        require(header.length == length + 4, "EmailParser: Invalid header length");

        // convert the byte array to a UTF-8 encoded string
        string memory headerStr = string(header[4:]);

        DKIMSignFields memory signFileds =  parseProcessHeader(headerStr);
        return signFileds;
    }

    function parseProcessHeader(string memory header) internal pure returns (DKIMSignFields memory) {
        DKIMSignFields memory signFields = DKIMSignFields("", "", "", "", "", "", "");
        string[] memory lines = split(header, "\r\n");
        for (uint i = 0; i < lines.length; i++) {
            string memory line = lines[i];
            (string memory key, string memory value) = parseField(line);
            if (isEqual(key, "to")) {            
                signFields.to = value;
            }else if(isEqual(key, "from")){
                signFields.from = value;
            }else if(isEqual(key, "subject")){
                signFields.subject = value;
            }else if(isEqual(key, "message-id")){
                signFields.messageId = value;
            }else if(isEqual(key, "date")){
                signFields.date = value;
            }else if(isEqual(key, "mime-version")){
                signFields.mimeVersion = value;
            }else if(isEqual(key, "dkim-signature")){
                signFields.dkimSignature = value;
            }else {
                revert("EmailParser: Invalid header field");
            }
        }

        return signFields;
    }

    function isEqual(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(abi.encodePacked((a))) == keccak256(abi.encodePacked((b)));
    }
    
    function parseField(string memory field) internal pure returns (string memory, string memory) {
        uint colonIndex = indexOf(field, ":");
        if (colonIndex == 0) {
            return ("", "");
        }
        string memory key = substring(field, 0, colonIndex);
        string memory value = substring(field, colonIndex + 1);
        return (key, value);
    }

    function parseEmailDomain(string memory email) internal pure returns (string memory) {
        bytes memory emailBytes = bytes(email);
        uint atIndex = 0;
        for (uint i = 0; i < emailBytes.length; i++) {
            if (emailBytes[i] == "@") {
                atIndex = i;
                break;
            }
        }
        bytes memory domainBytes = new bytes(emailBytes.length - atIndex - 1);
        for (uint i = atIndex + 1; i < emailBytes.length; i++) {
            domainBytes[i - atIndex - 1] = emailBytes[i];
        }
        return string(domainBytes);
    }

    /**
     * @dev Extracts the email address from the `From` field value, like `Cool Man <coolman@gmail.com>`
     * @param input The email `From` field value
     */
    function extractEmailAddress(string memory input) internal pure returns (string memory) {
        bytes memory inputBytes = bytes(input);
        uint256 atIndex = 0;
        uint256 dotIndex = 0;
        for (uint256 i = 0; i < inputBytes.length; i++) {
            if (inputBytes[i] == bytes1("<")) {
                atIndex = i + 1;
            } else if (inputBytes[i] == bytes1("@")) {
                atIndex = atIndex == 0 ? 0 : atIndex;
            } else if (inputBytes[i] == bytes1(">")) {
                dotIndex = i - 1;
                break;
            }
        }
        bytes memory resultBytes = new bytes(dotIndex - atIndex + 1);
        for (uint256 i = 0; i < resultBytes.length; i++) {
            resultBytes[i] = inputBytes[atIndex + i];
        }
        return string(resultBytes);
    }
    
    function split(string memory text, string memory delimiter) internal pure returns (string[] memory) {
        uint partsCount = count(text, delimiter) + 1;
        string[] memory parts = new string[](partsCount);
        uint lastIndex = 0;
        for (uint i = 0; i < partsCount - 1; i++) {
            uint delimiterIndex = indexOf(text, delimiter, lastIndex);
            parts[i] = substring(text, lastIndex, delimiterIndex);
            lastIndex = delimiterIndex + bytes(delimiter).length;
        }
        parts[partsCount - 1] = substring(text, lastIndex);
        return parts;
    }
    
    function count(string memory text, string memory pattern) internal pure returns (uint) {
        uint counter = 0;
        uint cursor = 0;
        while (true) {
            uint index = indexOf(text, pattern, cursor);
            if (index == type(uint256).max) {
                break;
            }
            counter++;
            cursor = index + bytes(pattern).length;
        }
        return counter;
    }
    
    function indexOf(string memory text, string memory pattern) internal pure returns (uint) {
        return indexOf(text, pattern, 0);
    }
    
    function indexOf(string memory text, string memory pattern, uint start) internal pure returns (uint) {
        bytes memory bytesText = bytes(text);
        bytes memory bytesPattern = bytes(pattern);
        uint patternLength = bytesPattern.length;
        for (uint i = start; i <= bytesText.length - patternLength; i++) {
            bool matched = true;
            for (uint j = 0; j < patternLength; j++) {
                if (bytesText[i + j] != bytesPattern[j]) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                return i;
            }
        }
        return type(uint256).max;
    }
    
    function substring(string memory text, uint start) internal pure returns (string memory) {
        return substring(text, start, bytes(text).length);
    }
    
    function substring(string memory text, uint start, uint end) internal pure returns (string memory) {
        bytes memory bytesText = bytes(text);
        require(start <= bytesText.length && end <= bytesText.length, "EmailParser: Index out of range");
        require(end >= start, "EmailParser: End index must be greater than or equal to start index");
        bytes memory result = new bytes(end - start);
        for (uint i = start; i < end; i++) {
            result[i - start] = bytesText[i];
        }
        return string(result);
    }
}
