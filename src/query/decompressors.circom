pragma circom 2.0.0;
include "../../../../node_modules/circomlib/circuits/bitify.circom";

template maskingValue(){
    signal input mask;
    signal input value;
    signal output out;


    component binValue = Num2Bits(256);
    component binMask = Num2Bits(256);
    component decValue = Bits2Num(256);

    binValue.in <== value;
    binMask.in <== mask;
    for(var i = 0; i < 256; i++){
        decValue.in[i] <== binValue.out[i] * binMask.out[i];
    }
    out <== decValue.out;
}
