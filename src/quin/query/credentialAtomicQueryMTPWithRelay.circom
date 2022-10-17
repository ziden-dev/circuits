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
- verify credential subject (verify that identity is an owner of a issuerClaim )
- issuerClaim schema
- issuerClaim ownership and issuance state
- issuerClaim non revocation state
- issuerClaim expiration ?
- query data slots

IdOwnershipLevels - Merkle tree depth level for personal claims
IssuerLevels - Merkle tree depth level for claims issued by the issuer
valueLevels - Number of elements in comparison array for in/notin operation if level =3 number of values for
comparison ["1", "2", "3"]

*/
template CredentialAtomicQueryMTPWithRelay(IdOwnershipLevels, IssuerLevels, RelayLevels, valueTreeDepth) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    /* user id ownership signals */
    signal input userID;

    signal input relayState;
    signal input userStateInRelayClaimMtp[RelayLevels * 4];
    signal input userStateInRelayClaim[8];
	signal input relayProofValidClaimsTreeRoot;
	signal input relayProofValidRevTreeRoot;
	signal input relayProofValidRootsTreeRoot;    

    signal input userClaimsTreeRoot;
    signal input userAuthClaimMtp[IdOwnershipLevels * 4];
    signal input userAuthClaim[8];

    signal input userRevTreeRoot;
    signal input userAuthClaimNonRevMtp[IdOwnershipLevels * 4];
    signal input userAuthClaimNonRevMtpNoAux;
    signal input userAuthClaimNonRevMtpAuxHi;
    signal input userAuthClaimNonRevMtpAuxHv;

    signal input userRootsTreeRoot;

    signal input challenge;
    signal input challengeSignatureR8x;
    signal input challengeSignatureR8y;
    signal input challengeSignatureS;

    /* issuerClaim signals */
    signal input issuerClaim[8];
    signal input issuerClaimMtp[IssuerLevels * 4];
    signal input issuerClaimClaimsTreeRoot;
    signal input issuerClaimRevTreeRoot;
    signal input issuerClaimRootsTreeRoot;
    signal input issuerClaimIdenState;
    signal input issuerID;

    signal input issuerClaimNonRevMtp[IssuerLevels * 4];
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
    component userIdOwnership = IdOwnershipBySignatureWithRelay(IdOwnershipLevels, RelayLevels);

    userIdOwnership.userClaimsTreeRoot <== userClaimsTreeRoot; // currentUserStateClaimsTreeRoot
    for (var i=0; i<IdOwnershipLevels * 4; i++) { userIdOwnership.userAuthClaimMtp[i] <== userAuthClaimMtp[i]; }
    for (var i=0; i<8; i++) { userIdOwnership.userAuthClaim[i] <== userAuthClaim[i]; }

    userIdOwnership.userRevTreeRoot <== userRevTreeRoot;  // currentUserStateClaimsRevTreeRoot
    for (var i=0; i<IdOwnershipLevels * 4; i++) { userIdOwnership.userAuthClaimNonRevMtp[i] <== userAuthClaimNonRevMtp[i]; }
    userIdOwnership.userAuthClaimNonRevMtpNoAux <== userAuthClaimNonRevMtpNoAux;
    userIdOwnership.userAuthClaimNonRevMtpAuxHv <== userAuthClaimNonRevMtpAuxHv;
    userIdOwnership.userAuthClaimNonRevMtpAuxHi <== userAuthClaimNonRevMtpAuxHi;

    userIdOwnership.userRootsTreeRoot <== userRootsTreeRoot; // currentUserStateClaimsRootsTreeRoot

    userIdOwnership.challenge <== challenge;
    userIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    userIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    userIdOwnership.challengeSignatureS <== challengeSignatureS;

    userIdOwnership.userID <== userID;

    userIdOwnership.relayState <== relayState;
    for (var i=0; i<RelayLevels * 4; i++) { userIdOwnership.userStateInRelayClaimMtp[i] <== userStateInRelayClaimMtp[i]; }
    for (var i=0; i<8; i++) { userIdOwnership.userStateInRelayClaim[i] <== userStateInRelayClaim[i]; }
	userIdOwnership.relayProofValidClaimsTreeRoot <== relayProofValidClaimsTreeRoot;
	userIdOwnership.relayProofValidRevTreeRoot <== relayProofValidRevTreeRoot;
	userIdOwnership.relayProofValidRootsTreeRoot <== relayProofValidRootsTreeRoot;

    // verify issuerClaim issued and not revoked
    component vci = verifyClaimIssuanceNonRev(IssuerLevels);
    for (var i=0; i<8; i++) { vci.claim[i] <== issuerClaim[i]; }
    for (var i=0; i<IssuerLevels * 4; i++) { vci.claimIssuanceMtp[i] <== issuerClaimMtp[i]; }
    vci.claimIssuanceClaimsTreeRoot <== issuerClaimClaimsTreeRoot;
    vci.claimIssuanceRevTreeRoot <== issuerClaimRevTreeRoot;
    vci.claimIssuanceRootsTreeRoot <== issuerClaimRootsTreeRoot;
    vci.claimIssuanceIdenState <== issuerClaimIdenState;

    // non revocation status
    for (var i=0; i<IssuerLevels; i++) { vci.claimNonRevMtp[i] <== issuerClaimNonRevMtp[i]; }
    vci.claimNonRevMtpNoAux <== issuerClaimNonRevMtpNoAux;
    vci.claimNonRevMtpAuxHi <== issuerClaimNonRevMtpAuxHi;
    vci.claimNonRevMtpAuxHv <== issuerClaimNonRevMtpAuxHv;
    vci.claimNonRevIssuerClaimsTreeRoot <== issuerClaimNonRevClaimsTreeRoot;
    vci.claimNonRevIssuerRevTreeRoot <== issuerClaimNonRevRevTreeRoot;
    vci.claimNonRevIssuerRootsTreeRoot <== issuerClaimNonRevRootsTreeRoot;
    vci.claimNonRevIssuerState <== issuerClaimNonRevState;

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
