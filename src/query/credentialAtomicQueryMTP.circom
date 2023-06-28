pragma circom 2.0.0;
include "../../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../../node_modules/circomlib/circuits/comparators.circom";
include "../idOwnershipBySignature.circom";
include "query.circom";
include "decompressors.circom";

/**
credentialAtomicQueryMTP.circom - query issuerClaim value and verify issuerClaim MTP

checks:
- identity ownership
- verify credential subject (verify that identity is an owner of a claim )
- claim schema
- claim ownership and issuance state
- claim non revocation state
- claim expiration ?
- query data slots

IdOwnershipLevels - Merkle tree depth level for personal claims
IssuerLevels - Merkle tree depth level for claims issued by the issuer
valueLevels - Number of elements in comparison array for in/notin operation if level =3 number of values for
comparison ["1", "2", "3"]

*/
template CredentialAtomicQueryMTP(IdOwnershipLevels, IssuerLevels, valueTreeDepth) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    /* userID ownership signals */
    signal input userID;
    signal input userState;

	signal input userAuthsRoot;
	signal input userAuthMtp[IdOwnershipLevels * 4];
	signal input userAuthHi;
    signal input userAuthPubX;
    signal input userAuthPubY;

	
	signal input userClaimsRoot;
    signal input userClaimRevRoot;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    /* issuerClaim signals */
    signal input issuerClaim[8];
    signal input issuerClaimMtp[IssuerLevels * 4];
    signal input issuerClaimAuthsRoot;
    signal input issuerClaimClaimsRoot;
    //signal input issuerClaimAuthRevRoot;
    signal input issuerClaimClaimRevRoot;
    signal input issuerClaimIdenState;
    signal input issuerID;

    // issuerClaim non rev inputs
    signal input issuerClaimNonRevMtp[IssuerLevels * 4];
    signal input issuerClaimNonRevMtpNoAux;
    signal input issuerClaimNonRevMtpAuxHi;
    signal input issuerClaimNonRevMtpAuxHv;
    
    signal input issuerClaimNonRevAuthsRoot;
    signal input issuerClaimNonRevClaimsRoot;
   // signal input issuerClaimNonRevAuthRevRoot; 
    signal input issuerClaimNonRevClaimRevRoot;
    signal input issuerClaimNonRevState;

    signal input timestamp;
    signal input claimSchema;
    signal input slotIndex;
    signal input operator;
    
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

    userID * 0 === 0;
    issuerID * 0 === 0;

    /* Id ownership check*/
    component userIdOwnership = IdOwnershipBySignature(IdOwnershipLevels);

    userIdOwnership.userAuthsRoot <== userAuthsRoot;
    userIdOwnership.userAuthHi <== userAuthHi;
    userIdOwnership.userAuthPubX <== userAuthPubX;
    userIdOwnership.userAuthPubY <== userAuthPubY;
    for (var i=0; i<IdOwnershipLevels * 4; i++) { userIdOwnership.userAuthMtp[i] <== userAuthMtp[i]; }
    

    // userIdOwnership.userAuthRevRoot <== userAuthRevRoot; 
    // for (var i=0; i<IdOwnershipLevels * 4; i++) { userIdOwnership.userAuthNonRevMtp[i] <== userAuthNonRevMtp[i]; }
    // userIdOwnership.userAuthNonRevMtpNoAux <== userAuthNonRevMtpNoAux;
    // userIdOwnership.userAuthNonRevMtpAuxHv <== userAuthNonRevMtpAuxHv;
    // userIdOwnership.userAuthNonRevMtpAuxHi <== userAuthNonRevMtpAuxHi;

    userIdOwnership.userClaimsRoot <== userClaimsRoot;
    userIdOwnership.userClaimRevRoot <== userClaimRevRoot;

    userIdOwnership.challenge <== challenge;
    userIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    userIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    userIdOwnership.challengeSignatureS <== challengeSignatureS;

    userIdOwnership.userState <== userState;

    // verify issuerClaim issued and not revoked
    component vci = verifyClaimIssuanceNonRev(IssuerLevels);
    for (var i=0; i<8; i++) { vci.claim[i] <== issuerClaim[i]; }
    for (var i=0; i<IssuerLevels * 4; i++) { vci.claimIssuanceMtp[i] <== issuerClaimMtp[i]; }
    vci.claimIssuanceAuthsRoot <== issuerClaimAuthsRoot;
    vci.claimIssuanceClaimsRoot <== issuerClaimClaimsRoot;
    //vci.claimIssuanceAuthRevRoot <== issuerClaimAuthRevRoot;
    vci.claimIssuanceClaimRevRoot <== issuerClaimClaimRevRoot;
    vci.claimIssuanceIdenState <== issuerClaimIdenState;

    // non revocation status
    for (var i=0; i<IssuerLevels * 4; i++) { vci.claimNonRevMtp[i] <== issuerClaimNonRevMtp[i]; }
    vci.claimNonRevMtpNoAux <== issuerClaimNonRevMtpNoAux;
    vci.claimNonRevMtpAuxHi <== issuerClaimNonRevMtpAuxHi;
    vci.claimNonRevMtpAuxHv <== issuerClaimNonRevMtpAuxHv;

    vci.claimNonRevIssuerAuthsRoot <== issuerClaimNonRevAuthsRoot;
    vci.claimNonRevIssuerClaimsRoot <== issuerClaimNonRevClaimsRoot;
   // vci.claimNonRevIssuerAuthRevRoot <== issuerClaimNonRevAuthRevRoot;
    vci.claimNonRevIssuerClaimRevRoot <== issuerClaimNonRevClaimRevRoot;
    vci.claimNonRevIssuerState <== issuerClaimNonRevState;


    // Check issuerClaim is issued to provided identity
    component claimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== issuerClaim[i]; }
    claimIdCheck.id <== userID;

    // Verify issuerClaim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== issuerClaim[i]; }
    claimSchemaCheck.schema <== claimSchema;

    // verify issuerClaim expiration time
    component claimExpirationCheck = verifyExpirationTime();
    for (var i=0; i<8; i++) { claimExpirationCheck.claim[i] <== issuerClaim[i]; }
    claimExpirationCheck.timestamp <== timestamp;

    // get value
    component getClaimValue = getValueByIndex();
    for (var i=0; i<8; i++) { getClaimValue.claim[i] <== issuerClaim[i]; }
    getClaimValue.index <== slotIndex;

    // masking
    component masking = maskingValue();
    masking.mask <== mask;
    masking.value <== getClaimValue.value;

    // query
    component q = Query(valueTreeDepth);
    q.in <== masking.out;
    q.determinisiticValue <== determinisiticValue;
    q.operator <== operator;
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