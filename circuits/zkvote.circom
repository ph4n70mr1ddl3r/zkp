pragma circom 2.1.6;

include "./vendor/circomlib/poseidon.circom";
include "./vendor/circom-ecdsa/ecdsa.circom";

template ZKVote(DEPTH, LIMB_BITS, LIMB_COUNT) {
    signal input root_pubkeys;
    signal input proposalId;
    signal input nullifier;
    signal input voteHash;

    signal input pk_x_limbs[LIMB_COUNT];
    signal input pk_y_limbs[LIMB_COUNT];
    signal input sig_r_limbs[LIMB_COUNT];
    signal input sig_s_limbs[LIMB_COUNT];

    signal input merkle_siblings[DEPTH];
    signal input merkle_pos[DEPTH];

    assert(LIMB_COUNT == 4);
    var ID_MSG_LIMBS[LIMB_COUNT];
    ID_MSG_LIMBS[0] = 6404780487488123880;
    ID_MSG_LIMBS[1] = 10749193852579334735;
    ID_MSG_LIMBS[2] = 9757315438606064353;
    ID_MSG_LIMBS[3] = 18328163512369336476;

    component ecdsa = ECDSAVerifyNoPubkeyCheck(LIMB_BITS, LIMB_COUNT);
    for (var i = 0; i < LIMB_COUNT; i++) {
        ecdsa.r[i] <== sig_r_limbs[i];
        ecdsa.s[i] <== sig_s_limbs[i];
        ecdsa.msghash[i] <== ID_MSG_LIMBS[i];
        ecdsa.pubkey[0][i] <== pk_x_limbs[i];
        ecdsa.pubkey[1][i] <== pk_y_limbs[i];
    }
    ecdsa.result === 1;

    component pkxPack = Poseidon(LIMB_COUNT);
    component pkyPack = Poseidon(LIMB_COUNT);
    for (var i = 0; i < LIMB_COUNT; i++) {
        pkxPack.inputs[i] <== pk_x_limbs[i];
        pkyPack.inputs[i] <== pk_y_limbs[i];
    }

    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== pkxPack.out;
    leafHasher.inputs[1] <== pkyPack.out;
    signal current_value[DEPTH + 1];
    current_value[0] <== leafHasher.out;

    signal left[DEPTH];
    signal right[DEPTH];
    signal leftFromSibling[DEPTH];
    signal leftFromCurrent[DEPTH];
    signal rightFromSibling[DEPTH];
    signal rightFromCurrent[DEPTH];
    component levelHashers[DEPTH];
    for (var i = 0; i < DEPTH; i++) {
        merkle_pos[i] * (merkle_pos[i] - 1) === 0;

        leftFromSibling[i] <== merkle_pos[i] * merkle_siblings[i];
        leftFromCurrent[i] <== (1 - merkle_pos[i]) * current_value[i];
        left[i] <== leftFromSibling[i] + leftFromCurrent[i];

        rightFromSibling[i] <== (1 - merkle_pos[i]) * merkle_siblings[i];
        rightFromCurrent[i] <== merkle_pos[i] * current_value[i];
        right[i] <== rightFromSibling[i] + rightFromCurrent[i];

        levelHashers[i] = Poseidon(2);
        levelHashers[i].inputs[0] <== left[i];
        levelHashers[i].inputs[1] <== right[i];
        current_value[i + 1] <== levelHashers[i].out;
    }
    current_value[DEPTH] === root_pubkeys;

    component sigRPacker = Poseidon(LIMB_COUNT);
    component sigSPacker = Poseidon(LIMB_COUNT);
    for (var i = 0; i < LIMB_COUNT; i++) {
        sigRPacker.inputs[i] <== sig_r_limbs[i];
        sigSPacker.inputs[i] <== sig_s_limbs[i];
    }

    component identityHasher = Poseidon(2);
    identityHasher.inputs[0] <== sigRPacker.out;
    identityHasher.inputs[1] <== sigSPacker.out;

    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== identityHasher.out;
    nullifierHasher.inputs[1] <== proposalId;
    nullifierHasher.out === nullifier;
}

// Default instantiation for a tree of depth 4 and 4x64-bit limb encoding.
component main = ZKVote(4, 64, 4);
