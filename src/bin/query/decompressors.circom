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

template deriveInput(){
  signal input in;
  signal output out[4];

  component binInput = Num2Bits(198);
  component derivedTimestamp = Bits2Num(64);
  component derivedSchemaHash = Bits2Num(128);
  component derivedSlotIndex = Bits2Num(3);
  component derivedOperator = Bits2Num(3);

  binInput.in <== in;
  
  // derive timestamp
  for(var i = 0; i < 64; i++){
    derivedTimestamp.in[i] <== binInput.out[134+i];
  }
  out[0] <== derivedTimestamp.out;
  
  // derive schema hash
  for(var i = 0; i < 128; i++){
    derivedSchemaHash.in[i] <== binInput.out[6+i];
  }
  out[1] <== derivedSchemaHash.out;

  // derive slot index and operator
  for(var i = 0; i < 3; i++){
    derivedSlotIndex.in[i] <== binInput.out[3+i];
    derivedOperator.in[i] <== binInput.out[i];
  }
  out[2] <== derivedSlotIndex.out;
  out[3] <== derivedOperator.out;
}