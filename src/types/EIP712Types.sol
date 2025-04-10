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

// uint48(abi.decode(bytes("ounts,"), (bytes6)))
uint48 constant BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR = 0x6f756e74732c;

// A multichain compact can declare tokens and amounts to allocate from multiple chains,
// each designated by their chainId. Any allocated tokens on an exogenous domain (e.g. all
// but the first segment) must designate the Multichain scope. Each segment may designate
// a unique arbiter for the chain in question. Note that the witness data is distinct for
// each segment, but all segments must share the same EIP-712 witness typestring.
struct Segment {
    address arbiter; // The account tasked with verifying and submitting the claim.
    uint256 chainId; // The chainId where the tokens are located.
    uint256[2][] idsAndAmounts; // The allocated token IDs and amounts.
        // Optional witness may follow.
}

// keccak256(bytes("Segment(address arbiter,uint256 chainId,uint256[2][] idsAndAmounts)"))
bytes32 constant SEGMENT_TYPEHASH = 0x295feb095767cc67d7e74695da0adaddede54d7b7194a8a5426fe8f0351e0337;

// Message signed by the sponsor that specifies the conditions under which a set of
// tokens across a number of different chains can be claimed; the specified arbiter on
// each chain verifies that those conditions have been met and specifies a set of
// beneficiaries that will receive up to the specified amounts of each token.
struct MultichainCompact {
    address sponsor; // The account to source the tokens from.
    uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
    uint256 expires; // The time at which the claim expires.
    Segment[] segments; // Arbiter, chainId, ids & amounts, and witness for each chain.
}

// keccak256(bytes("MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Segment[] segments)Segment(address arbiter,uint256 chainId,uint256[2][] idsAndAmounts)"))
bytes32 constant MULTICHAIN_COMPACT_TYPEHASH = 0x5ca9a66b8bbf0d2316e90dfa3df465f0790b277b25393a3ef4d67e1f50865057;

// abi.decode(bytes("MultichainCompact(address sponso"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x4d756c7469636861696e436f6d7061637428616464726573732073706f6e736f;

// abi.decode(bytes("r,uint256 nonce,uint256 expires,"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x722c75696e74323536206e6f6e63652c75696e7432353620657870697265732c;

// abi.decode(bytes("Segment[] segments)Segment(addre"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x5365676d656e745b5d207365676d656e7473295365676d656e74286164647265;

// abi.decode(bytes("ss arbiter,uint256 chainId,uint2"), (bytes32))
bytes32 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x737320617262697465722c75696e7432353620636861696e49642c75696e7432;

// uint176(abi.decode(bytes("56[2][] idsAndAmounts,"), (bytes22)))
uint176 constant MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE = 0x35365b325d5b5d20696473416e64416d6f756e74732c;

// The allocator can optionally attest to arbitrary parameters. Any EIP-712 data
// type can be utilized as long as the first argument is the message hash of the
// associated compact signed by the sponsor, which will be supplied by The Compact.
// If additional parameters are not required, the allocator instead signs the same
// payload as the sponsor.

// An Emissary is an account that is authorized by a sponsor to register claims.
// This could be a contract that facilitates the creation of dynamic claims, or
// could relay multichain claims registerd on other domains.
struct EmissaryAssignment {
    address emissary; // The account to assign as the emissary.
    uint256 nonce; // A parameter to enforce replay protection, scoped to sponsor.
    uint256 expires; // The time at which the assignment expires.
    bool assigned; // Whether to assign the emissary or to unassign them.
}

// keccak256(bytes("EmissaryAssignment(address emissary,uint256 nonce,uint256 expires)"))
bytes32 constant EMISSARY_ASSIGNMENT_TYPEHASH = 0x5ca9a66b8bbf0d2316e90dfa3df465f0790b277b25393a3ef4d67e1f50865057;

/// @dev `keccak256(bytes("CompactDeposit(address allocator,uint8 resetPeriod,uint8 scope,address recipient)"))`.
bytes32 constant PERMIT2_DEPOSIT_WITNESS_FRAGMENT_HASH =
    0xe055493563385cc588fffacbffe2dab023fef807baa449530431169b0eeb5b69;

/// @dev `keccak256(bytes("Activation(uint256 id,Compact compact)Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"))`.
bytes32 constant COMPACT_ACTIVATION_TYPEHASH = 0x2bf981c42c7f423b06fa49ba996d2930887e2f1f53d9a26b8c7423ac1cf83e61;

/// @dev `keccak256(bytes("Activation(uint256 id,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts)"))`.
bytes32 constant BATCH_COMPACT_ACTIVATION_TYPEHASH = 0xd14445d78213a5acddfa89171b0199de521c3b36738b835264cae18f5a53dbf3;

/// @dev `keccak256(bytes("Activation(uint256 id,MultichainCompact compact)MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Segment[] segments)Segment(address arbiter,uint256 chainId,uint256[2][] idsAndAmounts)"))`.
bytes32 constant MULTICHAIN_COMPACT_ACTIVATION_TYPEHASH =
    0x329b3c527a3c74b8cabc51c304669d1866b87352cafdf440ef2becd6dc261d1e;

/// @dev `keccak256(bytes("BatchActivation(uint256[] ids,Compact compact)Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"))`.
bytes32 constant COMPACT_BATCH_ACTIVATION_TYPEHASH = 0x45012d42fad8c9e937cff5a2d750ee18713dd45aadcd718660d5523056618d99;

/// @dev `keccak256(bytes("BatchActivation(uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts)"))`.
bytes32 constant BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH =
    0xc2e16a823b8cdddfdf889991d7a461f0a19faf1f8e608f1c164495a52151cc3e;

/// @dev `keccak256(bytes("BatchActivation(uint256[] ids,MultichainCompact compact)MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Segment[] segments)Segment(address arbiter,uint256 chainId,uint256[2][] idsAndAmounts)"))`.
bytes32 constant MULTICHAIN_COMPACT_BATCH_ACTIVATION_TYPEHASH =
    0xd2f6ad391328936f118250f231e63c7e639f9756a9ebf972d81763870a772d87;

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

// uint128(abi.decode(bytes(",uint256 amount,"), (bytes16)))
uint128 constant PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FOUR = 0x2c75696e7432353620616d6f756e742c;

// abi.decode(bytes("BatchCompact compact)BatchCompac"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x4261746368436f6d7061637420636f6d70616374294261746368436f6d706163;

// abi.decode(bytes("t(address arbiter,address sponso"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x74286164647265737320617262697465722c616464726573732073706f6e736f;

// abi.decode(bytes("r,uint256 nonce,uint256 expires,"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x722c75696e74323536206e6f6e63652c75696e7432353620657870697265732c;

// uint216(abi.decode(bytes("uint256[2][] idsAndAmounts,"), (bytes27)))
uint216 constant PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x75696e743235365b325d5b5d20696473416e64416d6f756e74732c;

// abi.decode(bytes("MultichainCompact compact)Multic"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE =
    0x4d756c7469636861696e436f6d7061637420636f6d70616374294d756c746963;

// abi.decode(bytes("hainCompact(address sponsor,uint"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO =
    0x6861696e436f6d7061637428616464726573732073706f6e736f722c75696e74;

// abi.decode(bytes("256 nonce,uint256 expires,Segmen"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE =
    0x323536206e6f6e63652c75696e7432353620657870697265732c5365676d656e;

// abi.decode(bytes("t[] segments)Segment(address arb"), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR =
    0x745b5d207365676d656e7473295365676d656e74286164647265737320617262;

// abi.decode(bytes("iter,uint256 chainId,uint256[2]["), (bytes32))
bytes32 constant PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE =
    0x697465722c75696e7432353620636861696e49642c75696e743235365b325d5b;

// uint128(abi.decode(bytes("] idsAndAmounts,"), (bytes16)))
uint128 constant PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX = 0x5d20696473416e64416d6f756e74732c;

// abi.decode(bytes(")TokenPermissions(address token,"), (bytes32))
bytes32 constant TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE =
    0x29546f6b656e5065726d697373696f6e73286164647265737320746f6b656e2c;

// uint120(abi.decode(bytes("uint256 amount)"), (bytes15)))
uint120 constant TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO = 0x75696e7432353620616d6f756e7429;

// abi.decode(bytes("CompactDeposit witness)CompactDe"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_ONE =
    0x436f6d706163744465706f736974207769746e65737329436f6d706163744465;

// abi.decode(bytes("posit(address allocator,uint8 re"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_TWO =
    0x706f736974286164647265737320616c6c6f6361746f722c75696e7438207265;

// abi.decode(bytes("setPeriod,uint8 scope,address re"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_THREE =
    0x736574506572696f642c75696e74382073636f70652c61646472657373207265;

// abi.decode(bytes("cipient)TokenPermissions(address"), (bytes32))
uint256 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FOUR =
    0x63697069656e7429546f6b656e5065726d697373696f6e732861646472657373;

// uint176(abi.decode(bytes(" token,uint256 amount)"), (bytes32))
uint176 constant COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FIVE = 0x20746f6b656e2c75696e7432353620616d6f756e7429;
