pragma circom 2.0.0;
include "../../../../node_modules/circomlib/circuits/comparators.circom";

template Dec2Quin(n){
    signal input in;
    signal output out[n];

    var lc1=0;
    var temp = in;
    var e5=1;
    component lt[n];
    for (var i = 0; i<n; i++) {
        out[i] <-- temp % 5;
        temp = temp \ 5;

        lt[i] = LessThan(3);
        lt[i].in[0] <== out[i];
        lt[i].in[1] <== 5;
        lt[i].out === 1;

        lc1 += out[i] * e5;
        e5 *= 5;
    }

    lc1 === in;
}

template Quin2Dec(n){
    signal input in[n];
    signal output out;

    var lc1=0;

    var e5 = 1;
    for (var i = 0; i<n; i++) {
        lc1 += in[i] * e5;
        e5 *= 5;
    }

    lc1 ==> out;
}