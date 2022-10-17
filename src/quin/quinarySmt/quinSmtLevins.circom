/*

This component finds the level where the oldInsert is done.
The rules are:

levIns[i] == 1 if its level and all the child levels have all siblings been zero and
the parent level has at least one sibling != 0.  Considere that the root level always has
a parent with at least one sibling != 0.


                                  ┌──────────────┐
                                  │              │
                                  │              │───▶ levIns[0] <== (1-done[i])
                                  │              │
                                  └──────────────┘
                                          ▲
                                          │
                                          │
                                       done[0]



                                      done[i-1] <== levIns[i] + done[i]
                                          ▲
                                          │
                                          │
                   ┌───────────┐  ┌──────────────┐
                   │           │  │              │
   sibling[i-1]───▶│IsZero[i-1]│─▶│              │───▶ levIns[i] <== (1-done[i])*(1-isZero[i-1].out)
                   │           │  │              │
                   └───────────┘  └──────────────┘
                                          ▲
                                          │
                                          │
                                       done[i]



                                     done[n-2] <== levIns[n-1]
                                         ▲
                                         │
                                         │
                  ┌───────────┐  ┌──────────────┐
                  │           │  │              │
  sibling[n-2]───▶│IsZero[n-2]│─▶│              │────▶ levIns[n-1] <== (1-isZero[n-2].out)
                  │           │  │              │
                  └───────────┘  └──────────────┘

                  ┌───────────┐
                  │           │
  sibling[n-1]───▶│IsZero[n-1]│────▶ === 0
                  │           │
                  └───────────┘

 */
pragma circom 2.0.0;
include "../../../../node_modules/circomlib/circuits/gates.circom";
include "../../../../node_modules/circomlib/circuits/comparators.circom";

template AreAllSiblingsZero() {
    signal input siblings[4];
    signal output out;
    component isZero[4];
    for (var i=0; i<4; i++) {
        isZero[i] = IsZero();
        isZero[i].in <== siblings[i];
    }
    component areAllZero = MultiAND(4);
    for (var i=0; i<4; i++) {
        areAllZero.in[i] <== isZero[i].out;
    }
    out <== areAllZero.out;
}
template QuinSMTLevIns(nLevels) {
    signal input siblings[nLevels * 4];
    signal output levIns[nLevels];
    signal done[nLevels-1];        // Indicates if the insLevel has aready been detected.

    var i;

    component isZero[nLevels];

    for (i=0; i<nLevels; i++) {
        isZero[i] = AreAllSiblingsZero();
        for(var j = 0; j < 4; j++){
            isZero[i].siblings[j] <== siblings[4 * i + j];
        }
    }

    // The last level must always have all zero siblings. If not, then it cannot be inserted.
    isZero[nLevels-1].out === 1;

    levIns[nLevels-1] <== (1-isZero[nLevels-2].out);
    done[nLevels-2] <== levIns[nLevels-1];
    for (i=nLevels-2; i>0; i--) {
        levIns[i] <== (1-done[i])*(1-isZero[i-1].out);
        done[i-1] <== levIns[i] + done[i];
    }

    levIns[0] <== (1-done[0]);
}