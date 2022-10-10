pragma circom 2.0.0;

include "query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        determinisiticValue,
                        compactInput,
                        mask]} = CredentialAtomicQueryMTP(8, 32, 10);
