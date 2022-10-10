pragma circom 2.0.0;

include "query/credentialAtomicQuerySig.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimNonRevState,
                        determinisiticValue,
                        compactInput,
                        mask]} = CredentialAtomicQuerySig(8, 32, 10);
