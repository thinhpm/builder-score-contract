// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";  // Includes ERC721import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract BuilderScoreNFT is ERC721, ERC721URIStorage, Ownable, EIP712 {
    using ECDSA for bytes32;
    using Strings for uint256;

    uint256 private _nextTokenId;
    mapping(address => uint256) public builderScores;
    mapping(address => uint256) public walletToToken;

    // EIP-712 domain separator for signatures
    bytes32 private constant _MINT_TYPEHASH =
    keccak256(
        bytes(
            "MintRequest(address wallet,uint256 score,uint256 nonce)"
        )
    );

    mapping(address => uint256) public nonces;  // Prevent replay attacks

    event DebugSigner(address signer);

    constructor() 
        ERC721("Builder Score", "BUILD") 
        Ownable(msg.sender) 
        EIP712("BuilderScoreNFT", "1")  // Domain name/version
    {}

    // Public function: User calls this with sig from BE
    function mintWithSignature(
        address wallet,  // Their wallet (must == msg.sender)
        uint256 score,   // From sig
        uint256 nonce,   // From sig
        bytes memory sig // BE-signed message
    ) external {
        // require(wallet == msg.sender, "Only self-mint");
        require(walletToToken[wallet] == 0, "Already has NFT");
        require(score > 0, "Invalid score");
        

        // Verify sig
        bytes32 structHash = keccak256(
            abi.encode(
                _MINT_TYPEHASH,
                wallet,
                score,
                nonce
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(sig);
        emit DebugSigner(signer);
        require(signer == owner(), "Invalid sig");  // Only owner signs
        require(nonces[wallet] == nonce, "Invalid nonce");  // One-time use
        nonces[wallet]++;

        // Mint & set score
        uint256 tokenId = ++_nextTokenId;
        _safeMint(wallet, tokenId);  // Safe mint!
        builderScores[wallet] = score;
        walletToToken[wallet] = tokenId;

        string memory uri = generateTokenURI(score, tokenId);
        _setTokenURI(tokenId, uri);
    }

    function mint(
        uint256 score,   // From sig
        uint256 nonce   // From sig
    ) external {
        address wallet = msg.sender;
        // require(wallet == msg.sender, "Only self-mint");
        require(walletToToken[wallet] == 0, "Already has NFT");
        require(score > 0, "Invalid score");

        // Verify sig
        require(nonces[wallet] == nonce, "Invalid nonce");  // One-time use
        nonces[wallet]++;

        // Mint & set score
        uint256 tokenId = ++_nextTokenId;
        _safeMint(wallet, tokenId);  // Safe mint!
        builderScores[wallet] = score;
        walletToToken[wallet] = tokenId;

        string memory uri = generateTokenURI(score, tokenId);
        _setTokenURI(tokenId, uri);
    }

    // Keep your updateScore for future owner updates
    function updateScore(address builder, uint256 newScore) external onlyOwner {
        require(walletToToken[builder] != 0, "No NFT yet");
        builderScores[builder] = newScore;
        uint256 tokenId = walletToToken[builder];
        string memory uri = generateTokenURI(newScore, tokenId);
        _setTokenURI(tokenId, uri);
    }

    // Your existing generateTokenURI, generateSVG, getLevel unchanged...
    function generateTokenURI(uint256 score, uint256 tokenId)
        internal
        pure
        returns (string memory)
    {
        string memory level = getLevel(score);
        string memory image = Base64.encode(bytes(generateSVG(score, level)));
        return string(
            abi.encodePacked(
                "data:application/json;base64,",
                Base64.encode(
                    bytes(
                        abi.encodePacked(
                            '{"name":"Builder Score #', tokenId.toString(),
                            '","description":"On-chain builder reputation score",',
                            '"image":"', image, '",',
                            '"attributes":['
                                '{"trait_type":"Score","value":', score.toString(), '},'
                                '{"trait_type":"Level","value":"', level, '"}'
                            ']}'
                        )
                    )
                )
            )
        );
    }

    function generateSVG(uint256 score, string memory level) internal pure returns (string memory) {
        return string(
            abi.encodePacked(
                '<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500" style="background:#0f172a">',
                '<rect x="0" y="0" width="500" height="500" fill="#1e293b"/>',
                '<text x="250" y="180" font-family="Arial" font-size="60" fill="#60a5fa" text-anchor="middle">',
                score.toString(), '</text>',
                '<text x="250" y="280" font-family="Arial" font-size="36" fill="#94a3b8" text-anchor="middle">',
                level, '</text>',
                '<text x="250" y="320" font-family="Arial" font-size="20" fill="#64748b" text-anchor="middle">',
                'Builder Score</text></svg>'
            )
        );
    }

    function getLevel(uint256 score) public pure returns (string memory) {
        if (score >= 400) return "God Tier";
        if (score >= 300)  return "Diamond Builder";
        if (score >= 200)  return "Gold Builder";
        if (score >= 100)  return "Silver Builder";
        return "Bronze Builder";
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}