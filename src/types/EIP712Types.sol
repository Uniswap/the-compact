// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Message signed by the sponsor that specifies the conditions under which their
// tokens can be claimed; the specified arbiter verifies that those conditions
// have been met and specifies a set of beneficiaries that will receive up to the
// specified amount of tokens.
struct Compact {
    address arbiter; // The account tasked with verifying and submitting the claim.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    uint256 id; // The token ID of the ERC6909 token to allocate.
    uint256 amount; // The amount of ERC6909 tokens to allocate.
        // Optional witness may follow.
}

// keccak256(bytes("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"))
bytes32 constant COMPACT_TYPEHASH = 0xcdca950b17b5efc016b74b912d8527dfba5e404a688cbc3dab16cb943287fec2;

// abi.decode(bytes("Compact(address arbiter,address "), (bytes32))
bytes32 constant COMPACT_TYPESTRING_FRAGMENT_ONE = 0x436f6d70616374286164647265737320617262697465722c6164647265737320;

// abi.decode(bytes("sponsor,uint256 nonce,uint256 ex"), (bytes32))
bytes32 constant COMPACT_TYPESTRING_FRAGMENT_TWO = 0x73706f6e736f722c75696e74323536206e6f6e63652c75696e74323536206578;

// abi.decode(bytes("pires,uint256 id,uint256 amount,"), (bytes32))
bytes32 constant COMPACT_TYPESTRING_FRAGMENT_THREE = 0x70697265732c75696e743235362069642c75696e7432353620616d6f756e742c;

// uint192(abi.decode(bytes("Mandate mandate)Mandate("), (bytes24)))
uint192 constant COMPACT_TYPESTRING_FRAGMENT_FOUR = 0x4d616e64617465206d616e64617465294d616e6461746528;

// Message signed by the sponsor that specifies the conditions under which a set of
// tokens, each sharing an allocator, can be claimed; the specified arbiter verifies
// that those conditions have been met and specifies a set of beneficiaries that will
// receive up to the specified amounts of each token.
struct BatchCompact {
    address arbiter; // The account tasked with verifying and submitting the claim.
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    uint256[2][] idsAndAmounts; // The allocated token IDs and amounts.
        // Optional witness may follow.
}

// keccak256(bytes("BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts)"))
bytes32 constant BATCH_COMPACT_TYPEHASH = 0x5a7fee8000a237929ef9be08f2933c4b4f320b00b38809f3c7aa104d5421049f;

// abi.decode(bytes("BatchCompact(address arbiter,add"), (bytes32))
bytes32 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x4261746368436f6d70616374286164647265737320617262697465722c616464;

// abi.decode(bytes("ress sponsor,uint256 nonce,uint2"), (bytes32))
bytes32 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x726573732073706f6e736f722c75696e74323536206e6f6e63652c75696e7432;

// abi.decode(bytes("56 expires,uint256[2][] idsAndAm"), (bytes32))
bytes32 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x353620657870697265732c75696e743235365b325d5b5d20696473416e64416d;

// uint240(abi.decode(bytes("ounts,Mandate mandate)Mandate("), (bytes30)))
uint240 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR = 0x6f756e74732c4d616e64617465206d616e64617465294d616e6461746528;

// A multichain compact can declare tokens and amounts to allocate from multiple chains,
// each designated by their chainId. Any allocated tokens on an exogenous domain (e.g. all
// but the first element) must designate the Multichain scope. Each element may designate
// a unique arbiter for the chain in question. Note that the witness data is distinct for
// each element, but all elements must share the same EIP-712 "Mandate" witness typestring.
struct Element {
    address arbiter; // The account tasked with verifying and submitting the claim.
    uint256 chainId; // The chainId where the tokens are located.
    uint256[2][] idsAndAmounts; // The allocated token IDs and amounts.
        // Mandate (witness) must follow.
}

// Message signed by the sponsor that specifies the conditions under which a set of
// tokens across a number of different chains can be claimed; the specified arbiter on
// each chain verifies that those conditions have been met and specifies a set of
// beneficiaries that will receive up to the specified amounts of each token.
struct MultichainCompact {
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    Element[] elements; // Arbiter, chainId, ids & amounts, and mandate for each chain.
}

// abi.decode(bytes("MultichainCompact(address sponso"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x4d756c7469636861696e436f6d7061637428616464726573732073706f6e736f;

// abi.decode(bytes("r,uint256 nonce,uint256 expires,"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x722c75696e74323536206e6f6e63652c75696e7432353620657870697265732c;

// abi.decode(bytes("Element[] elements)Element(addre"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x456c656d656e745b5d20656c656d656e747329456c656d656e74286164647265;

// abi.decode(bytes("ss arbiter,uint256 chainId,uint2"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x737320617262697465722c75696e7432353620636861696e49642c75696e7432;

// abi.decode(bytes("56[2][] idsAndAmounts,Mandate ma"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE =
    0x35365b325d5b5d20696473416e64416d6f756e74732c4d616e64617465206d61;

// uint112(abi.decode(bytes("ndate)Mandate("), (bytes14)))
uint112 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX = 0x6e64617465294d616e6461746528;

/// @dev `keccak256(bytes("CompactDeposit(bytes12 lockTag,address recipient)"))`.
bytes32 constant PERMIT2_DEPOSIT_WITNESS_FRAGMENT_HASH =
    0xaced9f7c53bfda31d043cbef88f9ee23b8171ec904889af3d5d0b9b81914a404;

/// @dev `keccak256(bytes("Activation(uint256 id,Compact compact)Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"))`.
bytes32 constant COMPACT_ACTIVATION_TYPEHASH = 0x2bf981c42c7f423b06fa49ba996d2930887e2f1f53d9a26b8c7423ac1cf83e61;

/// @dev `keccak256(bytes("Activation(uint256 id,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts)"))`.
bytes32 constant BATCH_COMPACT_ACTIVATION_TYPEHASH = 0xd14445d78213a5acddfa89171b0199de521c3b36738b835264cae18f5a53dbf3;

/// @dev `keccak256(bytes("BatchActivation(uint256[] ids,Compact compact)Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"))`.
bytes32 constant COMPACT_BATCH_ACTIVATION_TYPEHASH = 0x45012d42fad8c9e937cff5a2d750ee18713dd45aadcd718660d5523056618d99;

/// @dev `keccak256(bytes("BatchActivation(uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts)"))`.
bytes32 constant BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH =
    0xc2e16a823b8cdddfdf889991d7a461f0a19faf1f8e608f1c164495a52151cc3e;

// abi.decode(bytes("Activation witness)Activation(ui"), (bytes32))
bytes32 constant PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE =
    0x41637469766174696f6e207769746e6573732941637469766174696f6e287569;

// uint72(abi.decode(bytes("nt256 id,"), (bytes9)))
uint72 constant PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO = 0x6e743235362069642c;

// abi.decode(bytes("BatchActivation witness)BatchAct"), (bytes32))
bytes32 constant PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE =
    0x426174636841637469766174696f6e207769746e657373294261746368416374;

// uint176(abi.decode(bytes("ivation(uint256[] ids,"), (bytes22)))
uint176 constant PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO =
    0x69766174696f6e2875696e743235365b5d206964732c;

// abi.decode(bytes("Compact compact)Compact(address "), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x436f6d7061637420636f6d7061637429436f6d70616374286164647265737320;

// abi.decode(bytes("arbiter,address sponsor,uint256 "), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x617262697465722c616464726573732073706f6e736f722c75696e7432353620;

// abi.decode(bytes("nonce,uint256 expires,uint256 id"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x6e6f6e63652c75696e7432353620657870697265732c75696e74323536206964;

// abi.decode(bytes(",uint256 amount,Mandate mandate)"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x2c75696e7432353620616d6f756e742c4d616e64617465206d616e6461746529;

// uint64(abi.decode(bytes("Mandate("), (bytes8)))
uint64 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FIVE = 0x4d616e6461746528;

// abi.decode(bytes("BatchCompact compact)BatchCompac"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x4261746368436f6d7061637420636f6d70616374294261746368436f6d706163;

// abi.decode(bytes("t(address arbiter,address sponso"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x74286164647265737320617262697465722c616464726573732073706f6e736f;

// abi.decode(bytes("r,uint256 nonce,uint256 expires,"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x722c75696e74323536206e6f6e63652c75696e7432353620657870697265732c;

// abi.decode(bytes("uint256[2][] idsAndAmounts,Manda"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x75696e743235365b325d5b5d20696473416e64416d6f756e74732c4d616e6461;

// uint216(abi.decode(bytes("te mandate)Mandate("), (bytes19)))
uint216 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE = 0x7465206d616e64617465294d616e6461746528;

// abi.decode(bytes(")TokenPermissions(address token,"), (bytes32))
bytes32 constant TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE =
    0x29546f6b656e5065726d697373696f6e73286164647265737320746f6b656e2c;

// uint120(abi.decode(bytes("uint256 amount)"), (bytes15)))
uint120 constant TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO = 0x75696e7432353620616d6f756e7429;

// abi.decode(bytes("CompactDeposit witness)CompactDe"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_ONE =
    0x436f6d706163744465706f736974207769746e65737329436f6d706163744465;

// abi.decode(bytes("posit(bytes12 lockTag,address re"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_TWO =
    0x706f7369742862797465733132206c6f636b5461672c61646472657373207265;

// abi.decode(bytes("cipient)TokenPermissions(address"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_THREE =
    0x63697069656e7429546f6b656e5065726d697373696f6e732861646472657373;

// uint176(abi.decode(bytes(" token,uint256 amount)"), (bytes22)))
uint176 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FOUR = 0x20746f6b656e2c75696e7432353620616d6f756e7429;
