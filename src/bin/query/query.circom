pragma circom 2.0.0;
include "../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "merkleProof.circom";
include "../utils/claimUtils.circom";


/*
  Operators:
 "0" - noop, skip execution. Ignores all `in` and `value` passed to query, out 1
 "1" - equals
 "2" - less-than
 "3" - greater-than
 "4" - in
 "5" - not in
 "6" - in range
 "7" - not in use
*/
template Query (depth) {
    signal input in;
    signal input leaf0;
    signal input leaf1;
    signal input determinisiticValue;
    signal input elemsPath0[depth];
    signal input pos0;
    signal input elemsPath1[depth];
    signal input pos1;
    signal input operator;
    signal output out;

    component n2b = Num2Bits(3);
    n2b.in <== operator;

    // check if 2 leaves is consecutive
    component isConsecutive = IsEqual();
    isConsecutive.in[0] <== pos0 + 1;
    isConsecutive.in[1] <== pos1;

    component indicesPath0 = Num2Bits(depth);
    indicesPath0.in <== pos0;
    component indicesPath1 = Num2Bits(depth);
    indicesPath1.in <== pos1; 

    // use to avoid the case root value size exceeds 252 bits
    signal valueForSingleOp;
    component selector = Mux3();
    selector.s[0] <== n2b.out[0];
    selector.s[1] <== n2b.out[1];
    selector.s[2] <== n2b.out[2];

    selector.c[0] <== 0;
    selector.c[1] <== determinisiticValue;
    selector.c[2] <== determinisiticValue;
    selector.c[3] <== determinisiticValue;
    selector.c[4] <== 0;
    selector.c[5] <== 0;
    selector.c[6] <== 0;
    selector.c[7] <== 0;

    valueForSingleOp <== selector.out;

    // operation components
    component eq = IsEqual();
    eq.in[0] <== in;
    eq.in[1] <== valueForSingleOp;

    component lt = LessThan(252);
    lt.in[0] <== in;
    lt.in[1] <== valueForSingleOp;

    component gt = GreaterThan(252);
    gt.in[0] <== in;
    gt.in[1] <== valueForSingleOp;

    component isValidMTP0 = IsValidMTP(depth);
    isValidMTP0.leaf <== leaf0;
    isValidMTP0.root <== determinisiticValue;
    for(var i = 0; i < depth; i++){
      isValidMTP0.path2_root[i] <== elemsPath0[i];
      isValidMTP0.path2_root_pos[i] <== indicesPath0.out[i];
    }
    
    component isValidMTP1 = IsValidMTP(depth);
    isValidMTP1.leaf <== leaf1;
    isValidMTP1.root <== determinisiticValue;
    for(var i = 0; i < depth; i++){
      isValidMTP1.path2_root[i] <== elemsPath1[i];
      isValidMTP1.path2_root_pos[i] <== indicesPath1.out[i];
    }

    component isLeaf0LeftMost = IsEqual();
    isLeaf0LeftMost.in[0] <== pos0;
    isLeaf0LeftMost.in[1] <== 0;

    component isLeaf1RightMost = IsEqual();
    isLeaf1RightMost.in[0] <== pos1 + 1;
    isLeaf1RightMost.in[1] <== (1 << depth);

    component isInEqualLeaf0 = IsEqual();
    isInEqualLeaf0.in[0] <== in;
    isInEqualLeaf0.in[1] <== leaf0;

    component isInEqualLeaf1 = IsEqual();
    isInEqualLeaf1.in[0] <== in;
    isInEqualLeaf1.in[1] <== leaf1;

    component isInGreaterThanLeaf0 = GreaterThan(252);
    isInGreaterThanLeaf0.in[0] <== in;
    isInGreaterThanLeaf0.in[1] <== leaf0;

    component isInLessThanLeaf1 = LessThan(252);
    isInLessThanLeaf1.in[0] <== in;
    isInLessThanLeaf1.in[1] <== leaf1;

    signal isInBetween2Leaves <== isInGreaterThanLeaf0.out * isInLessThanLeaf1.out;
    signal isBoth2LeavesValid <== isValidMTP0.out * isValidMTP1.out;
    signal isInBetween2ValidLeaves <== isInBetween2Leaves * isBoth2LeavesValid;
    signal isInBetween2ConsecutiveValidLeaves <== isConsecutive.out * isInBetween2ValidLeaves;

    signal isInLessThanLeaf0 <== (1 - isInGreaterThanLeaf0.out) * (1 - isInEqualLeaf0.out);
    signal isValidLeftMostLeaf <== isValidMTP0.out * isLeaf0LeftMost.out;
    signal isInLessThanLeftMost <== isValidLeftMostLeaf * isInLessThanLeaf0;

    signal isInGreaterThanLeaf1 <== (1 - isInLessThanLeaf1.out) * (1 - isInEqualLeaf1.out);
    signal isValidRightMostLeaf <== isValidMTP1.out * isLeaf1RightMost.out;
    signal isInGreaterThanRightMost <== isInGreaterThanLeaf1 * isValidRightMostLeaf;
    
    signal isNotIn <== isInBetween2ConsecutiveValidLeaves + isInLessThanLeftMost + isInGreaterThanRightMost;

    signal isIn <== isValidMTP0.out * isInEqualLeaf0.out;

    // mux
    component mux = Mux3();


    mux.s[0] <== n2b.out[0];
    mux.s[1] <== n2b.out[1];
    mux.s[2] <== n2b.out[2];

    mux.c[0] <== 1; // noop, skip execution
    mux.c[1] <== eq.out;
    mux.c[2] <== lt.out;
    mux.c[3] <== gt.out;
    mux.c[4] <== isIn;
    mux.c[5] <== isNotIn;
    mux.c[6] <== isInBetween2ValidLeaves;
    mux.c[7] <== 0; // not in use

    // output
    out <== mux.out;
}


