pragma circom 2.0.0;
include "../../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../../node_modules/circomlib/circuits/comparators.circom";

template getMerkleRoot(depth){
    signal input leaf;
    signal input path2_root[depth];
    signal input path2_root_pos[depth];
    
    signal output out;
    component switchers[depth];
    component hashers[depth];

    for(var i = 0; i < depth; i++){
        switchers[i] = Switcher();
        switchers[i].L <== i == 0 ? leaf : hashers[i-1].out;
        switchers[i].R <== path2_root[i];
        switchers[i].sel <== path2_root_pos[i];
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;
    }

    out <== hashers[depth-1].out;

}

template IsValidMTP(depth){
    signal input leaf;
    signal input root;
    signal input path2_root[depth];
    signal input path2_root_pos[depth];
    
    signal output out;
    component computed_root = getMerkleRoot(depth);
    computed_root.leaf <== leaf;

    for(var i = 0; i < depth; i++){
        computed_root.path2_root[i] <== path2_root[i];
        computed_root.path2_root_pos[i] <== path2_root_pos[i];
    }
    component eq = IsEqual();
    eq.in[0] <== computed_root.out;
    eq.in[1] <== root;
    out <== eq.out; 
}