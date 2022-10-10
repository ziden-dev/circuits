pragma circom 2.0.0;
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../idOwnershipBySignature.circom";
include "query.circom";
include "decompressors.circom";


/**
credentialAtomicQuerySig.circom - query claim value and verify claim issuer signature:

checks:
- identity ownership
- verify credential subject (verify that identity is an owner of a claim )
- claim schema
- claim ownership and issuance state
- claim non revocation state
- claim expiration
- query data slots

IdOwnershipLevels - Merkle tree depth level for personal claims
IssuerLevels - Merkle tree depth level for claims issued by the issuer
valueArraySize - Number of elements in comparison array for in/notin operation if level = 3 number of values for
comparison ["1", "2", "3"]

*/
template CredentialAtomicQuerySig(IdOwnershipLevels, IssuerLevels, valueTreeDepth) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    /* userID ownership signals */
    signal input userID;
    signal input userState;

    signal input userClaimsTreeRoot;
    signal input userAuthClaimMtp[IdOwnershipLevels];
    signal input userAuthClaim[8];

    signal input userRevTreeRoot;
    signal input userAuthClaimNonRevMtp[IdOwnershipLevels];
    signal input userAuthClaimNonRevMtpNoAux;
    signal input userAuthClaimNonRevMtpAuxHi;
    signal input userAuthClaimNonRevMtpAuxHv;

    signal input userRootsTreeRoot;

    /* signature*/
    signal input challenge;
    signal input challengeSignatureR8x;
    signal input challengeSignatureR8y;
    signal input challengeSignatureS;

    /* issuerClaim signals */

    signal input issuerClaim[8];
    
    // issuerClaim signature
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;

    // issuer state
    signal input issuerID;

    signal input issuerAuthClaim[8];
    signal input issuerAuthClaimMtp[IssuerLevels];
    // issuer auth claim non rev proof
    signal input issuerAuthClaimNonRevMtp[IssuerLevels];
    signal input issuerAuthClaimNonRevMtpNoAux;
    signal input issuerAuthClaimNonRevMtpAuxHi;
    signal input issuerAuthClaimNonRevMtpAuxHv;

    signal input issuerAuthClaimsTreeRoot;
    signal input issuerAuthRevTreeRoot;
    signal input issuerAuthRootsTreeRoot;
    signal output issuerAuthState;

    // issuerClaim non rev inputs
    signal input issuerClaimNonRevMtp[IssuerLevels];
    signal input issuerClaimNonRevMtpNoAux;
    signal input issuerClaimNonRevMtpAuxHi;
    signal input issuerClaimNonRevMtpAuxHv;
    signal input issuerClaimNonRevClaimsTreeRoot;
    signal input issuerClaimNonRevRevTreeRoot;
    signal input issuerClaimNonRevRootsTreeRoot;
    signal input issuerClaimNonRevState;

    /** Query */
    signal input compactInput;
    signal input determinisiticValue;
    signal input mask;
    signal input leaf0;
    signal input leaf1;
    signal input elemsPath0[valueTreeDepth];
    signal input pos0;
    signal input elemsPath1[valueTreeDepth];
    signal input pos1;


    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> End Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */
    // derive compact input
    component inputs = deriveInput();
    inputs.in <== compactInput;

    /* Id ownership check*/
    component userIdOwnership = IdOwnershipBySignature(IdOwnershipLevels);

    userIdOwnership.userClaimsTreeRoot <== userClaimsTreeRoot; // currentHolderStateClaimsTreeRoot
    for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.userAuthClaimMtp[i] <== userAuthClaimMtp[i]; }
    for (var i=0; i<8; i++) { userIdOwnership.userAuthClaim[i] <== userAuthClaim[i]; }

    userIdOwnership.userRevTreeRoot <== userRevTreeRoot;  // currentHolderStateClaimsRevTreeRoot
    for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.userAuthClaimNonRevMtp[i] <== userAuthClaimNonRevMtp[i]; }
    userIdOwnership.userAuthClaimNonRevMtpNoAux <== userAuthClaimNonRevMtpNoAux;
    userIdOwnership.userAuthClaimNonRevMtpAuxHv <== userAuthClaimNonRevMtpAuxHv;
    userIdOwnership.userAuthClaimNonRevMtpAuxHi <== userAuthClaimNonRevMtpAuxHi;

    userIdOwnership.userRootsTreeRoot <== userRootsTreeRoot; // currentHolderStateClaimsRootsTreeRoot

    userIdOwnership.challenge <== challenge;
    userIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    userIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    userIdOwnership.challengeSignatureS <== challengeSignatureS;

    userIdOwnership.userState <== userState;


    // Check issuerClaim is issued to provided identity
    component claimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== issuerClaim[i]; }
    claimIdCheck.id <== userID;

    // Verify issuerClaim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== issuerClaim[i]; }
    claimSchemaCheck.schema <== inputs.out[1];

    // verify issuerClaim expiration time
    component claimExpirationCheck = verifyExpirationTime();
    for (var i=0; i<8; i++) { claimExpirationCheck.claim[i] <== issuerClaim[i]; }
    claimExpirationCheck.timestamp <== inputs.out[0];

    // get value
    component getClaimValue = getValueByIndex();
    for (var i=0; i<8; i++) { getClaimValue.claim[i] <== issuerClaim[i]; }
    getClaimValue.index <== inputs.out[2];


    var AUTH_SCHEMA_HASH  = 304427537360709784173770334266246861770;
    component issuerSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { issuerSchemaCheck.claim[i] <== issuerAuthClaim[i]; }
    issuerSchemaCheck.schema <== AUTH_SCHEMA_HASH;
    // verify authClaim issued and not revoked
    // calculate issuerAuthState
    component issuerAuthStateComponent = getIdenState();
    issuerAuthStateComponent.claimsTreeRoot <== issuerAuthClaimsTreeRoot;
    issuerAuthStateComponent.revTreeRoot <== issuerAuthRevTreeRoot;
    issuerAuthStateComponent.rootsTreeRoot <== issuerAuthRootsTreeRoot;

    issuerAuthState <== issuerAuthStateComponent.idenState;


    // issuerAuthClaim proof of existence (isProofExist)
    //
    component smtIssuerAuthClaimExists = checkClaimExists(IssuerLevels);
    for (var i=0; i<8; i++) { smtIssuerAuthClaimExists.claim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { smtIssuerAuthClaimExists.claimMTP[i] <== issuerAuthClaimMtp[i]; }
    smtIssuerAuthClaimExists.treeRoot <== issuerAuthClaimsTreeRoot;

    // issuerAuthClaim proof of non-revocation
    //
    component verifyIssuerAuthClaimNotRevoked = checkClaimNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyIssuerAuthClaimNotRevoked.claim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) {
        verifyIssuerAuthClaimNotRevoked.claimNonRevMTP[i] <== issuerAuthClaimNonRevMtp[i];
    }
    verifyIssuerAuthClaimNotRevoked.noAux <== issuerAuthClaimNonRevMtpNoAux;
    verifyIssuerAuthClaimNotRevoked.auxHi <== issuerAuthClaimNonRevMtpAuxHi;
    verifyIssuerAuthClaimNotRevoked.auxHv <== issuerAuthClaimNonRevMtpAuxHv;
    verifyIssuerAuthClaimNotRevoked.treeRoot <== issuerClaimNonRevRevTreeRoot;

    component issuerAuthPubKey = getPubKeyFromClaim();
    for (var i=0; i<8; i++){ issuerAuthPubKey.claim[i] <== issuerAuthClaim[i]; }

    // issuerClaim  check signature
    component verifyClaimSig = verifyClaimSignature();
    for (var i=0; i<8; i++) { verifyClaimSig.claim[i] <== issuerClaim[i]; }
    verifyClaimSig.sigR8x <== issuerClaimSignatureR8x;
    verifyClaimSig.sigR8y <== issuerClaimSignatureR8y;
    verifyClaimSig.sigS <== issuerClaimSignatureS;
    verifyClaimSig.pubKeyX <== issuerAuthPubKey.Ax;
    verifyClaimSig.pubKeyY <== issuerAuthPubKey.Ay;

    // verify issuer state includes issuerClaim
    component verifyClaimIssuanceIdenState = checkIdenStateMatchesRoots();
    verifyClaimIssuanceIdenState.claimsTreeRoot <== issuerClaimNonRevClaimsTreeRoot;
    verifyClaimIssuanceIdenState.revTreeRoot <== issuerClaimNonRevRevTreeRoot;
    verifyClaimIssuanceIdenState.rootsTreeRoot <== issuerClaimNonRevRootsTreeRoot;
    verifyClaimIssuanceIdenState.expectedState <== issuerClaimNonRevState;

    // non revocation status
    component verifyClaimNotRevoked = checkClaimNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyClaimNotRevoked.claim[i] <== issuerClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) {
        verifyClaimNotRevoked.claimNonRevMTP[i] <== issuerClaimNonRevMtp[i];
    }
    verifyClaimNotRevoked.noAux <== issuerClaimNonRevMtpNoAux;
    verifyClaimNotRevoked.auxHi <== issuerClaimNonRevMtpAuxHi;
    verifyClaimNotRevoked.auxHv <== issuerClaimNonRevMtpAuxHv;
    verifyClaimNotRevoked.treeRoot <== issuerClaimNonRevRevTreeRoot;

    // masking
    component masking = maskingValue();
    masking.mask <== mask;
    masking.value <== getClaimValue.value;

    // query
    component q = Query(valueTreeDepth);
    q.in <== masking.out;
    q.determinisiticValue <== determinisiticValue;
    q.operator <== inputs.out[3];
    q.leaf0 <== leaf0;
    q.leaf1 <== leaf1;
    q.pos0 <== pos0;
    q.pos1 <== pos1;
    for(var i = 0; i<valueTreeDepth; i++){
        q.elemsPath0[i] <== elemsPath0[i];
        q.elemsPath1[i] <== elemsPath1[i];
    }
    q.out === 1;
}
