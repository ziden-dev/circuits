/******

SMTVerifierLevel

This circuit has 1 hash

Outputs according to the state.

State        root
=====        =======
top          H'(child, sibling)
i0           0
iold         old1leaf
inew         new1leaf
na           0

H' is the Hash function with the inputs shifted acordingly.

*****/
pragma circom 2.0.0;
include "quinHashers.circom";

template QuinSMTVerifierLevel() {
    signal input st_top;
    signal input st_i0;
    signal input st_iold;
    signal input st_inew;
    signal input st_na;

    signal output root;
    signal input siblings[4];
    signal input index;
    signal input old1leaf;
    signal input new1leaf;
    signal input child;

    signal aux[2];

    component proofHash = QuinSMTHash5();
    for(var i = 0; i< 4; i++){
        proofHash.siblings[i] <== siblings[i];
    }
    proofHash.index <== index;
    proofHash.child <== child;


    aux[0] <== proofHash.out * st_top;
    aux[1] <== old1leaf*st_iold;

    root <== aux[0] + aux[1] + new1leaf*st_inew;
}