/*
# idOwnershipBySignature.circom

Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside its Identity State (in Claim tree)
*/

pragma circom 2.0.0;

include "utils/claimUtils.circom";
include "utils/treeUtils.circom";

template IdOwnershipBySignature(nLevels) {
    signal input userState;

	signal input userAuthsRoot;
	signal input userAuthMtp[nLevels * 4];
	signal input userAuthHi;
    signal input userAuthPubX;
    signal input userAuthPubY;

	signal input userClaimsRoot;
    signal input userClaimRevRoot;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;


    component verifyAuth = VerifyAuthAndSignature(nLevels);
    
    verifyAuth.authHi <== userAuthHi;
    verifyAuth.authPubX <== userAuthPubX;
    verifyAuth.authPubY <== userAuthPubY;
	for (var i=0; i<nLevels * 4; i++) { verifyAuth.authMtp[i] <== userAuthMtp[i]; }
	verifyAuth.authsRoot <== userAuthsRoot;

    verifyAuth.challengeSignatureS <== challengeSignatureS;
    verifyAuth.challengeSignatureR8x <== challengeSignatureR8x;
    verifyAuth.challengeSignatureR8y <== challengeSignatureR8y;
    verifyAuth.challenge <== challenge;

    component checkUserState = checkIdenStateMatchesRoots();
    checkUserState.authsRoot <== userAuthsRoot;
    checkUserState.claimsRoot <== userClaimsRoot;
    checkUserState.claimRevRoot <== userClaimRevRoot;
    checkUserState.expectedState <== userState;
}

