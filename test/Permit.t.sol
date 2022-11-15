// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Permit.sol";

import "openzeppelin-contracts/utils/cryptography/EIP712.sol";

contract PermitImplementation is Permit {
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    constructor() Permit("Permit", "1") {}

    function _setApprovalForAll(
        address _owner,
        address _operator,
        bool _approved
    ) internal override {
        isApprovedForAll[_owner][_operator] = _approved;
    }
}

contract PermitTest is Test {
    PermitImplementation public permit;
    uint256 public alicePk = 111;
    address public alice = vm.addr(alicePk);

    function setUp() public {
        permit = new PermitImplementation();
        vm.label(alice, "Alice");
    }

    function testTrue() public {
        assertTrue(true);
    }

    function signPermit(
        address _owner,
        address _operator,
        bool _bool,
        uint256 _nonce,
        uint256 _deadline
    ) public view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(
            abi.encode(permit.PERMIT_TYPEHASH, _owner, _operator, _bool, _nonce, _deadline)
        );

        (v, r, s) = vm.sign(
            alicePk,
            keccak256(abi.encode("\x19\x01", permit.DOMAIN_SEPARATOR(), structHash))
        );
    }
}
