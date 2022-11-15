// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "openzeppelin-contracts/utils/cryptography/EIP712.sol";

abstract contract Permit is EIP712 {
    mapping(address => uint256) public nonces;
    /// 'keccak256("Permit(address owner,address spender,uint256 nonce,bool approved,uint256 deadline)")'
    bytes32 public constant PERMIT_TYPEHASH =
        0x9402ec7ae9ab70ad0c02eb5cf78333ebe1377e1ce02139ed740d10a3240bd739;

    // solhint-disable-next-line empty-blocks
    constructor(string memory name, string memory version) EIP712(name, version) {}

    function permit(
        address _owner,
        address _operator,
        bool _approved,
        uint256 _deadline,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public {
        require(_deadline >= block.timestamp, "expired");

        bytes32 digest = _buildDigest(_owner, _operator, _approved, _deadline);
        address signer = ECDSA.recover(digest, _v, _r, _s);
        require(signer == _owner, "Not Owner");

        _setApprovalForAll(_owner, _operator, _approved);
    }

    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function _buildDigest(
        address _owner,
        address _operator,
        bool _approved,
        uint256 _deadline
    ) internal returns (bytes32) {
        bytes memory typedData = abi.encode(
            PERMIT_TYPEHASH,
            _owner,
            _operator,
            nonces[_owner]++,
            _approved,
            _deadline
        );
        return _hashTypedDataV4(keccak256(typedData));
    }

    function _setApprovalForAll(address, address, bool) internal virtual;
}
