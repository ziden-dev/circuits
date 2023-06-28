/*

SMTVerifier is a component to verify inclusion/exclusion of an element in the tree


fnc:  0 -> VERIFY INCLUSION
      1 -> VERIFY NOT INCLUSION

 */
pragma circom 2.0.0;

include "../../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../../node_modules/circomlib/circuits/gates.circom";
include "../../../../node_modules/circomlib/circuits/comparators.circom";
include "quinSmtLevins.circom";
include "quinSmtVerifierLevel.circom";
include "quinSmtVerifierSm.circom";
include "quinHashers.circom";
include "quinify.circom";

template QuinSMTVerifier(nLevels) {
    signal input root;
    signal input siblings[4 * nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;
    signal input key;
    signal input value;
    signal input fnc;

    var i;

    component hash1Old = QuinSMTHash1();
    hash1Old.key <== oldKey;
    hash1Old.value <== oldValue;

    component hash1New = QuinSMTHash1();
    hash1New.key <== key;
    hash1New.value <== value;

    component smtLevIns = QuinSMTLevIns(nLevels);
    for (i=0; i < 4 * nLevels; i++) smtLevIns.siblings[i] <== siblings[i];

    component sm[nLevels];
    for (i=0; i<nLevels; i++) {
        sm[i] = QuinSMTVerifierSM();
        if (i==0) {
            sm[i].prev_top <== 1;
            sm[i].prev_i0 <== 0;
            sm[i].prev_inew <== 0;
            sm[i].prev_iold <== 0;
            sm[i].prev_na <== 0;
        } else {
            sm[i].prev_top <== sm[i-1].st_top;
            sm[i].prev_i0 <== sm[i-1].st_i0;
            sm[i].prev_inew <== sm[i-1].st_inew;
            sm[i].prev_iold <== sm[i-1].st_iold;
            sm[i].prev_na <== sm[i-1].st_na;
        }
        sm[i].is0 <== isOld0;
        sm[i].fnc <== fnc;
        sm[i].levIns <== smtLevIns.levIns[i];
    }
    sm[nLevels-1].st_na + sm[nLevels-1].st_iold + sm[nLevels-1].st_inew + sm[nLevels-1].st_i0 === 1;

    component keyQuins = Dec2Quin(111);
    keyQuins.in <== key;
    component levels[nLevels];
    for (i=nLevels-1; i != -1; i--) {
        levels[i] = QuinSMTVerifierLevel();

        levels[i].st_top <== sm[i].st_top;
        levels[i].st_i0 <== sm[i].st_i0;
        levels[i].st_inew <== sm[i].st_inew;
        levels[i].st_iold <== sm[i].st_iold;
        levels[i].st_na <== sm[i].st_na;

        for(var j = 0; j < 4; j++){
            levels[i].siblings[j] <== siblings[4 * i + j];
        }
        levels[i].index <== keyQuins.out[i];

        levels[i].old1leaf <== hash1Old.out;
        levels[i].new1leaf <== hash1New.out;

        if (i==nLevels-1) {
            levels[i].child <== 0;
        } else {
            levels[i].child <== levels[i+1].root;
        }
    }


    // Check that if checking for non inclussuin and isOld0==0 then key!=old
    component areKeyEquals = IsEqual();
    areKeyEquals.in[0] <== oldKey;
    areKeyEquals.in[1] <== key;

    component keysOk = MultiAND(3);
    keysOk.in[0] <== fnc;
    keysOk.in[1] <== 1-isOld0;
    keysOk.in[2] <== areKeyEquals.out;

    keysOk.out === 0;

    // Check the root
    component checkRoot = IsEqual();
    checkRoot.in[0] <== levels[0].root;
    checkRoot.in[1] <== root;

    checkRoot.out === 1;

}