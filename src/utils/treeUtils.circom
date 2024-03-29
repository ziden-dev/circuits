pragma circom 2.0.0;

include "../../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../../node_modules/circomlib/circuits/mux1.circom";
include "../quinarySmt/quinSmtVerifier.circom";
include "claimUtils.circom";

// getIdenState caclulates the Identity state out of the claims tree root,
// revocations tree root and roots tree root.
template getIdenState() {
	signal input authsRoot;
	signal input claimsRoot;
	//signal input authRevRoot;
	signal input claimRevRoot;

	signal output idenState;

	component calcIdState = Poseidon(3);
	calcIdState.inputs[0] <== authsRoot;
	calcIdState.inputs[1] <== claimsRoot;
	//calcIdState.inputs[2] <== authRevRoot;
	calcIdState.inputs[2] <== claimRevRoot;

	idenState <== calcIdState.out;
}
template checkAuthExists(nLevels) {
	signal input authHi;
	signal input authPubX;
	signal input authPubY;

	signal input authMTP[nLevels * 4];
	signal input authsRoot;

	component hasher = Poseidon(2);
	hasher.inputs[0] <== authPubX;
	hasher.inputs[1] <== authPubY;
	
	component smt = QuinSMTVerifier(nLevels);
	smt.fnc <== 0; // Inclusion
	smt.root <== authsRoot;
	for (var i=0; i<nLevels * 4; i++) { smt.siblings[i] <== authMTP[i]; }
	smt.oldKey <== 0;
	smt.oldValue <== 0;
	smt.isOld0 <== 0;
	smt.key <== authHi;
	smt.value <== hasher.out;
}
// checkClaimExists verifies that claim is included into the claim tree root
template checkClaimExists(IssuerLevels) {
	signal input claim[8];
	signal input claimMTP[IssuerLevels * 4];
	signal input treeRoot;

	component claimHiHv = getClaimHiHv();
	for (var i=0; i<8; i++) { claimHiHv.claim[i] <== claim[i]; }

	component smtClaimExists = QuinSMTVerifier(IssuerLevels);
	smtClaimExists.fnc <== 0; // Inclusion
	smtClaimExists.root <== treeRoot;
	for (var i=0; i<IssuerLevels * 4; i++) { smtClaimExists.siblings[i] <== claimMTP[i]; }
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claimHiHv.hi;
	smtClaimExists.value <== claimHiHv.hv;
}


template checkClaimNotRevoked(treeLevels) {
    signal input claim[8];
    signal input claimNonRevMTP[treeLevels * 4];
    signal input treeRoot;
    signal input noAux;
    signal input auxHi;
    signal input auxHv;

	component claimRevNonce = getClaimRevNonce();
	for (var i=0; i<8; i++) { claimRevNonce.claim[i] <== claim[i]; }

    component smtClaimNotExists = QuinSMTVerifier(treeLevels);
    smtClaimNotExists.fnc <== 1; // Non-inclusion
    smtClaimNotExists.root <== treeRoot;
    for (var i=0; i<treeLevels * 4; i++) { smtClaimNotExists.siblings[i] <== claimNonRevMTP[i]; }
    smtClaimNotExists.oldKey <== auxHi;
    smtClaimNotExists.oldValue <== auxHv;
    smtClaimNotExists.isOld0 <== noAux;
    smtClaimNotExists.key <== claimRevNonce.revNonce;
    smtClaimNotExists.value <== 0;
}

// checkIdenStateMatchesRoots checks that a hash of 3 tree
// roots is equal to expected identity state
template checkIdenStateMatchesRoots() {
	signal input authsRoot;
	signal input claimsRoot;
	//signal input authRevRoot;
	signal input claimRevRoot;
	signal input expectedState;

	component isProofValidIdenState = getIdenState();
	isProofValidIdenState.authsRoot <== authsRoot;
	isProofValidIdenState.claimsRoot <== claimsRoot;
	//isProofValidIdenState.authRevRoot <== authRevRoot;
	isProofValidIdenState.claimRevRoot <== claimRevRoot;

	isProofValidIdenState.idenState === expectedState;
}

// verifyClaimIssuance verifies that claim is issued by the issuer and not revoked
template verifyClaimIssuanceNonRev(IssuerLevels) {
	signal input claim[8];
	signal input claimIssuanceMtp[IssuerLevels * 4];
	signal input claimIssuanceAuthsRoot;
	signal input claimIssuanceClaimsRoot;
	//signal input claimIssuanceAuthRevRoot;
	signal input claimIssuanceClaimRevRoot;
	signal input claimIssuanceIdenState;

	signal input claimNonRevMtp[IssuerLevels * 4];
	signal input claimNonRevMtpNoAux;
	signal input claimNonRevMtpAuxHi;
	signal input claimNonRevMtpAuxHv;
	signal input claimNonRevIssuerAuthsRoot;
	signal input claimNonRevIssuerClaimsRoot;
	//signal input claimNonRevIssuerAuthRevRoot;
	signal input claimNonRevIssuerClaimRevRoot;
	signal input claimNonRevIssuerState;


    // verify country claim is included in claims tree root
    component claimIssuanceCheck = checkClaimExists(IssuerLevels);
    for (var i=0; i<8; i++) { claimIssuanceCheck.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels * 4; i++) { claimIssuanceCheck.claimMTP[i] <== claimIssuanceMtp[i]; }
    claimIssuanceCheck.treeRoot <== claimIssuanceClaimsRoot;

    // verify issuer state includes country claim
    component verifyClaimIssuanceIdenState = checkIdenStateMatchesRoots();
	verifyClaimIssuanceIdenState.authsRoot <== claimIssuanceAuthsRoot;
    verifyClaimIssuanceIdenState.claimsRoot <== claimIssuanceClaimsRoot;
    //verifyClaimIssuanceIdenState.authRevRoot <== claimIssuanceAuthRevRoot;
    verifyClaimIssuanceIdenState.claimRevRoot <== claimIssuanceClaimRevRoot;
    verifyClaimIssuanceIdenState.expectedState <== claimIssuanceIdenState;

    // check non-revocation proof for claim
    component verifyClaimNotRevoked = checkClaimNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyClaimNotRevoked.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels * 4; i++) {
        verifyClaimNotRevoked.claimNonRevMTP[i] <== claimNonRevMtp[i];
    }
    verifyClaimNotRevoked.noAux <== claimNonRevMtpNoAux;
    verifyClaimNotRevoked.auxHi <== claimNonRevMtpAuxHi;
    verifyClaimNotRevoked.auxHv <== claimNonRevMtpAuxHv;
    verifyClaimNotRevoked.treeRoot <== claimNonRevIssuerClaimRevRoot;

    // check issuer state matches for non-revocation proof
    component verifyClaimNonRevIssuerState = checkIdenStateMatchesRoots();
	verifyClaimNonRevIssuerState.authsRoot <== claimNonRevIssuerAuthsRoot;
    verifyClaimNonRevIssuerState.claimsRoot <== claimNonRevIssuerClaimsRoot;
   // verifyClaimNonRevIssuerState.authRevRoot <== claimNonRevIssuerAuthRevRoot;
    verifyClaimNonRevIssuerState.claimRevRoot <== claimNonRevIssuerClaimRevRoot;
    verifyClaimNonRevIssuerState.expectedState <== claimNonRevIssuerState;
}

template VerifyAuthAndSignature(nLevels) {
	signal input authsRoot;
	signal input authMtp[nLevels * 4];
	signal input authHi;
	signal input authPubX;
	signal input authPubY;

	// signal input authRevRoot;
    // signal input authNonRevMtp[nLevels * 4];
    // signal input authNonRevMtpNoAux;
    // signal input authNonRevMtpAuxHi;
    // signal input authNonRevMtpAuxHv;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    component authExists = checkAuthExists(nLevels);
    
	authExists.authHi <== authHi;
	authExists.authPubX <== authPubX;
	authExists.authPubY <== authPubY;
	for (var i=0; i<nLevels * 4; i++) { authExists.authMTP[i] <== authMtp[i]; }
    authExists.authsRoot <== authsRoot;

    // component authNotRevoked = checkAuthNotRevoked(nLevels);
	// authNotRevoked.authHi <== authHi;
    // for (var i=0; i<nLevels * 4; i++) {
    //     authNotRevoked.authNonRevMTP[i] <== authNonRevMtp[i];
    // }
    // authNotRevoked.authRevRoot <== authRevRoot;
    // authNotRevoked.noAux <== authNonRevMtpNoAux;
    // authNotRevoked.auxHi <== authNonRevMtpAuxHi;
    // authNotRevoked.auxHv <== authNonRevMtpAuxHv;

    // signature verification
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;

    sigVerifier.Ax <== authPubX;
    sigVerifier.Ay <== authPubY;

    sigVerifier.S <== challengeSignatureS;
    sigVerifier.R8x <== challengeSignatureR8x;
    sigVerifier.R8y <== challengeSignatureR8y;

    sigVerifier.M <== challenge;
}

template cutId() {
	signal input in;
	signal output out;

	component idBits = Num2Bits(256);
	idBits.in <== in;

	component cutted = Bits2Num(256-16-8);
	for (var i=16; i<256-8; i++) {
		cutted.in[i-16] <== idBits.out[i];
	}
	out <== cutted.out;
}

template cutState() {
	signal input in;
	signal output out;

	component stateBits = Num2Bits(256);
	stateBits.in <== in;

	component cutted = Bits2Num(256-16-8);
	for (var i=0; i<256-16-8; i++) {
		cutted.in[i] <== stateBits.out[i+16+8];
	}
	out <== cutted.out;
}
