# Ziden Circuits

Cryptographic circuits used in Ziden protocol with some main components: **idOwnershipBySignature**, **stateTransition**, **credentialAtomicQueryMTP**

## idOwnershipBySignature.circom

This circuit validate the signature proving the ownership of holder over the identity. It will be used internally by **stateTransition.circom** and **credentialAtomicQueryMTP.circom** for authorization thus there is no public inputs

### Parameters:

- **nLevels**: the depth of identity authorization tree
### Private Inputs:

- **userState**: the accumulated root of user. 

- Authorization MTP </br>
**userAuthsRoot**</br>
**userAuthMTP**</br>
**userAuthHi**</br>
**userAuthPubX**</br>
**userAuthPubY**</br>

- Other User Roots: </br>
**userClaimsRoot**</br>
**userClaimRevRoot**</br>

- **challenge**: the message given by the validator to the holder to sign on

- Signature on the given challenge </br>
**challengeSignatureR8x**</br>
**challengeSignatureR8y**</br>
**challengeSignatureS**</br>



## stateTransition.circom

This circuit validate and commit the change of the identity's state.

### Parameters
- **idOwnershipLevels**: the depth of identity authorization tree

### Public Inputs

- **userId**: ID of user
- **oldUserState**: the old accumulated root of user
- **newUserState**: the new accumulated root of user
- **isOldStateGenesis**: indicate whether it's the first time user transit their state.

### Private Inputs

- Authorization MTP </br>
**userAuthsRoot**</br>
**userAuthMTP**</br>
**userAuthHi**</br>
**userAuthPubX**</br>
**userAuthPubY**</br>

- Other User Roots: </br>
**userClaimsRoot**</br>
**userClaimRevRoot**</br>

- Signature on the hash of the old and new states </br>
**challengeSignatureR8x**</br>
**challengeSignatureR8y**</br>
**challengeSignatureS**</br>


## credentialAtomicQueryMTP.circom

This circuit help the holder operate some queries over their claim, used when the holder wants to demonstrate some statements about their credential data to the verifier

### Parameters

- **idOwnershipLevels**: the depth of identity authorization tree
- **issuerLevels**: the depth of the claim tree and claim revocation tree
- **valueTreeDepth**: the depth of the Merkle tree for membership and non-membership operation

### Public Inputs

- **userId**: ID of user
- **userState**: the accumulated root of user
- **challenge**: the message given by the validator to the holder to sign on
- **issuerID**: id of the issuer who grants the claim for the user
- **issuerClaimIdenState**: the state of the issuer at the moment they granted the claim
- **issuerClaimNonRevState**: the latest state of the issuer ( the holder has to make sure their claim hasn't been revoked in this state )
- **timestamp**: required by the verifier, the holder has to make sure that the expiration time specified in the claim hasn't been passed by this value.
- **claimSchema**: the schemahash of the claim
- **slotIndex**: the index of the value took out to query on.
- **operator**: the operator to make the query on the specified value (value set: EQUAL, GREATER_THAN, LESS_THAN, IN, NOT_IN, IN_RANGE)
- **determinisiticValue**: the value to be compared with the value in the claim.
- **mask**: the queried value might not occupy the whole slot, so we need a mask to extract the queried value out of the slot.


### Private Inputs

- Authorization MTP </br>
**userAuthsRoot**</br>
**userAuthMTP**</br>
**userAuthHi**</br>
**userAuthPubX**</br>
**userAuthPubY**</br>

- Other User Roots: </br>
**userClaimsRoot**</br>
**userClaimRevRoot**</br>

- Signature on the given challenge </br>
**challengeSignatureR8x**</br>
**challengeSignatureR8y**</br>
**challengeSignatureS**</br>

- Existence MTP for the claim in the Claim Tree of issuer </br>
**issuerClaim**</br>
**issuerClaimMTP**</br>
**issuerClaimAuthsRoot**</br>
**issuerClaimClaimsRoot**</br>
**issuerClaimClaimRevRoot**</br>
**issuerClaimIdenState**</br>

- Non Existence MTP for the claim in the Revocation Tree of issuer </br>
**issuerClaimNonRevMtp**</br>
**issuerClaimNonRevMtpNoAux**</br>
**issuerClaimNonRevMtpAuxHi**</br>
**issuerClaimNonRevMtpAuxHv**</br>
**issuerClaimNonRevAuthsRoot**</br>
**issuerClaimNonRevClaimsRoot**</br>
**issuerClaimNonRevClaimRevRoot**</br>
**issuerClaimNonRevState**</br>

- Inputs for membership and non-membership operation (ignored if the operator is neither IN nor NOT IN)
**leaf0**</br>
**leaf1**</br>
**elemsPath0**</br>
**elemsPath1**</br>
**pos0**</br>
**pos1**</br>
**operator**</br>