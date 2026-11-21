---
title: OAuth 2.0 One-Time Refresh Proofs
abbrev: One-Time Refresh Proofs
category: exp
docname: draft-gerber-oauth-refresh-one-time-proofs-latest
submissiontype: IETF
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
author:
 - fullname: Maxwell Gerber
   organization: Twilio
   email: mgerber@twilio.com
normative:
  RFC4648:
  RFC6749:
  RFC7517:
  RFC7518:
  RFC7636:
  RFC8414:
informative:
  RFC6819:
  RFC9449:
  RFC9635:
  RFC9700:
  FAPI2:
    title: FAPI 2.0 Security Profile
    target: https://openid.net/specs/fapi-security-profile-2_0-final.html
    date: 2025-02
    author:
     - name: D. Fett
     - name: D. Tonge
     - name: J. Heenan
    seriesinfo:
      OpenID: Foundation
...

--- abstract

Refresh token rotation was introduced so that an authorization server could
detect the theft of a refresh token held by a public client. It fails when a
token response is lost: the client retries with a superseded refresh token and
the authorization server revokes the grant. Sender-constrained refresh tokens
do not have this failure, but they provide no means of detecting that a key is
in use by more than one party.

This document defines a mechanism in which the client proves possession of a
key each time it uses a refresh token, by signing a counter and a nonce. The
refresh token is not rotated and no secret is conveyed in either direction. A
lost response is recovered by retransmission, and use of the key by a second
party is detected by the authorization server.

--- middle

# Introduction

## Refresh Token Rotation {#rotation}

Refresh token rotation was first described in 2011, under the name "refresh
token replacement", in the threat analysis later published as {{RFC6819}}. It
is described in {{Section 5.2.2.3 of RFC6819}} and in {{Section 10.4 of
RFC6749}}. The authorization server issues a new refresh token in each refresh
response and invalidates the previous one while retaining a record of it.

The purpose of rotation is detection. If a refresh token is obtained by an
attacker and is subsequently used by both the attacker and the legitimate
client, one of them presents an invalidated refresh token. The authorization
server cannot determine which party is legitimate, and revokes the grant.

Rotation was proposed for clients that cannot authenticate to the authorization
server, for which no other means of noticing a second holder of a refresh token
was available. {{Section 4.14.2 of RFC9700}} now requires an authorization
server to either rotate or sender-constrain the refresh tokens it issues to
public clients.

## The Lost Response {#lost-response}

Rotation requires the authorization server to invalidate a credential at the
moment it issues the replacement, while the replacement exists only in a token
response. If that response is not delivered, the client holds only the
invalidated refresh token. A retry with that token is indistinguishable from
the reuse that rotation is intended to detect, and the grant is revoked.

This weakness has been recognized since rotation was introduced. {{RFC6819}}
notes that the measure may cause problems in clustered environments, because
use of the currently valid refresh token must be ensured. {{FAPI2}} prohibits
rotation except in extraordinary circumstances, citing the case in which a
client cannot receive or store the new refresh token, and leaves the recovery
mechanism out of scope. {{Section 11.33 of RFC9635}} describes the same failure
for token rotation in GNAP.

Deployed mitigations include accepting the previous refresh token for a period
of time, accepting it until the new refresh token is first used, and returning
the same new refresh token when the previous one is presented again. Each of
these retains the authorization server as the origin of the next credential,
and each weakens detection for as long as the previous credential remains
acceptable.

## Sender-Constrained Refresh Tokens {#sender-constrained}

DPoP {{RFC9449}} binds a refresh token issued to a public client to a key held
by that client. An authorization server that does so is not required to rotate
the refresh token, and the failure described in {{lost-response}} does not
arise.

DPoP is a preventive measure. When the private key cannot be extracted from the
client, a copy of the client's storage does not permit the refresh token to be
used.

DPoP does not provide detection. A DPoP proof carries no state that relates it
to earlier proofs made with the same key. If the key is copied from a platform
that does not offer non-extractable storage, or is used by an attacker
executing within the client, the requests of the second party are
indistinguishable from those of the client, and the authorization server
receives no indication that two parties hold the key. The property that
motivated rotation is therefore lost when rotation is replaced by
sender-constraining. A deployment that requires both properties combines DPoP
with rotation and reacquires the failure described in {{lost-response}}.

## Design Goals {#goals}

The mechanism defined in this document has the following goals.

Detection:
: Use of a grant by more than one party is detectable by the authorization
  server, as it is with refresh token rotation.

Minimal additional state:
: The authorization server holds, for each grant, a public key, one counter and
  a bounded record of recently accepted requests. The client holds a private
  key, one counter and at most one pending request.

No secrets on the wire:
: No value sufficient to obtain an access token is conveyed in either
  direction. The private key does not leave the client, and nothing required
  for a subsequent request is conveyed in a token response.

A consequence of the third goal is that the loss of a token response cannot
leave the client unable to continue.

The mechanism does not sender-constrain access tokens. It is intended for
clients that do not implement DPoP, including clients that present access
tokens to resource servers over protocols for which DPoP is not defined.

## Conventions and Terminology

{::boilerplate bcp14-tagged}

"Base64url" denotes the URL-safe base64 encoding defined in {{Section 5 of
RFC4648}}, without padding.

Refresh key:
: An asymmetric key pair generated by the client for one grant.

Proof-bound refresh token:
: A refresh token that the authorization server accepts only when accompanied
  by a refresh proof.

Refresh proof:
: A signature made with the private refresh key over a refresh token, a counter
  and a nonce.

Attempt:
: A counter value and a nonce value chosen by the client. Retransmissions of a
  request carry the same attempt.

Accepted attempt:
: An attempt for which the authorization server issued an access token.

# Protocol Overview {#overview}

{{fig-overview}} shows an authorization code exchange followed by three refresh
requests. The response to the second refresh request is lost.

~~~
+--------+                                          +---------------+
|        |--(A) code, code_verifier, refresh_jwk -->|               |
|        |<-(B) access_token, refresh_token --------|               |
|        |                                          |               |
|        |--(C) refresh_token, counter=1, nonce,    |               |
|        |      proof ----------------------------->|               |
|        |<-(D) access_token -----------------------|               |
|        |                                          |               |
|        |--(E) refresh_token, counter=2, nonce2,   |               |
| Client |      proof2 ---------------------------->| Authorization |
|        |        X<-(F) access_token --------------|    Server     |
|        |                                          |               |
|        |--(G) refresh_token, counter=2, nonce2,   |               |
|        |      proof2b --------------------------->|               |
|        |<-(H) error: duplicate_request -----------|               |
|        |                                          |               |
|        |--(I) refresh_token, counter=3, nonce3,   |               |
|        |      proof3 ---------------------------->|               |
|        |<-(J) access_token -----------------------|               |
+--------+                                          +---------------+
~~~
{: #fig-overview title="Refresh with a Lost Response"}

(A)
: The client generates a refresh key and includes the public key in the
  authorization code token request.

(B)
: The authorization server associates the public key with the grant and returns
  a token response. The refresh token is proof-bound.

(C)
: The client sends a refresh request containing counter value 1, a nonce and a
  refresh proof.

(D)
: The authorization server verifies the proof, determines that the counter is
  the next in sequence, and issues an access token. The refresh token is
  unchanged.

(E)
: The client sends a refresh request containing counter value 2 and a new
  nonce.

(F)
: The authorization server accepts the request, but the response is not
  delivered.

(G)
: The client retransmits the request with the same counter and nonce. The proof
  may differ, because the client may compute the signature again.

(H)
: The authorization server determines that the counter and nonce are those of
  an attempt it has already accepted, and returns the `duplicate_request`
  error. No access token is issued and the grant is unchanged.

(I), (J)
: The client, having established that counter value 2 was accepted, sends a
  refresh request containing counter value 3 and a new nonce, which the
  authorization server accepts.

If the request in (E) had been lost instead of the response in (F), the
authorization server would have accepted the request in (G).

# Authorization Code Grant {#code-grant}

## Token Request {#token-request}

A client requesting a proof-bound refresh token generates a refresh key and
adds the following parameter to the token request defined in {{Section 4.1.3 of
RFC6749}}.

refresh_jwk:
: REQUIRED. The public refresh key, as a JSON Web Key {{RFC7517}}. The JWK MUST
  contain an `alg` member whose value is an asymmetric digital signature
  algorithm registered for use with JWS {{RFC7518}}, and which the
  authorization server supports ({{metadata}}). The JWK MUST NOT contain
  private key parameters.

The algorithm used for all refresh proofs under the grant is the one identified
by the `alg` member. No separate algorithm parameter is defined.

A client MUST generate a new refresh key for each grant. A client SHOULD
generate the key such that the private key cannot be exported from the platform
facility that holds it, where such a facility is available.

The mechanism is defined for use with PKCE {{RFC7636}}. The authorization
server MUST NOT issue a proof-bound refresh token in response to a request that
does not contain a valid `code_verifier`.

## Token Response {#token-response}

The authorization server MUST reject a request containing a `refresh_jwk` value
that is not a well-formed JWK, that omits `alg`, that identifies an unsupported
algorithm, that is inconsistent with the identified algorithm, or that contains
private key parameters. The error code is `invalid_request`.

Otherwise the authorization server associates the public key with the grant,
sets the grant's counter to zero, and returns a token response as defined in
{{Section 5.1 of RFC6749}}. The response is unchanged by this document. A
refresh token included in the response is proof-bound.

The response does not indicate that the refresh token is proof-bound. A client
determines whether the authorization server supports the mechanism from
authorization server metadata ({{metadata}}) before sending `refresh_jwk`.

This mechanism does not make the authorization code exchange retryable. A
client that does not receive this response repeats the authorization request.

# Refreshing an Access Token {#refreshing}

## Refresh Request {#refresh-request}

A client presenting a proof-bound refresh token adds the following parameters
to the request defined in {{Section 6 of RFC6749}}.

refresh_counter:
: REQUIRED. A positive integer in decimal notation without leading zeros. Its
  value is one greater than the counter of the client's most recent accepted
  attempt, or 1 if there has been none.

refresh_nonce:
: REQUIRED. A value generated by the client with at least 128 bits of entropy,
  base64url encoded. The client generates a new value for each attempt and
  reuses it for every retransmission of that attempt.

refresh_proof:
: REQUIRED. The refresh proof, computed as described in {{refresh-proof}}.

## Refresh Proof {#refresh-proof}

The signing input is the ASCII string formed by concatenating the refresh
token, a period ("."), the value of `refresh_counter`, a period, and the value
of `refresh_nonce`:

~~~
signing-input = refresh_token "." refresh_counter "." refresh_nonce
~~~

The values are those of the request parameters before form encoding.

The refresh proof is the signature over the signing input, made with the
private refresh key and the algorithm identified in `refresh_jwk`, in the
signature format that {{RFC7518}} or the algorithm's registration specifies for
JWS, base64url encoded. For `ES256` this is the 64-octet concatenation of R and
S.

A client MAY compute a new signature when retransmitting an attempt. Signatures
made with a randomized algorithm will differ between retransmissions; the
counter and nonce MUST NOT.

## Authorization Server Processing {#as-processing}

The authorization server holds, for each grant, the public refresh key, the
counter of the most recent accepted attempt (`last`), and the counter and nonce
of one or more recent accepted attempts.

On receiving a refresh request for a proof-bound refresh token, the
authorization server performs the following steps in order.

1. If `refresh_counter`, `refresh_nonce` or `refresh_proof` is absent or
   malformed, reject the request with `invalid_request`.
2. Verify the refresh proof using the public refresh key. If verification
   fails, reject the request with `invalid_grant`. The grant MUST NOT be
   revoked and its state MUST NOT change.
3. If `refresh_counter` equals `last` + 1, accept the request: set `last` to
   `refresh_counter`, retain the counter and nonce as an accepted attempt, and
   issue an access token ({{success}}).
4. Otherwise, if `refresh_counter` and `refresh_nonce` equal those of a
   retained accepted attempt, reject the request with `duplicate_request`
   ({{duplicate-request}}). The grant's state MUST NOT change.
5. Otherwise, revoke the grant and reject the request with `invalid_grant`.

Step 5 is reached only by a request that carries a valid proof and is out of
sequence. Such a request was made by a holder of the private key that does not
share the state of the party whose attempts were accepted. This is the
condition that refresh token rotation is intended to detect.

Step 2 precedes any change of state so that a party without the private key,
including one that holds the refresh token, cannot cause the grant to be
revoked.

Steps 2 through 5 MUST be performed atomically with respect to other requests
for the same grant. This document assumes an authorization server that provides
this consistency, and does not define a tolerance for counters other than
`last` + 1.

The authorization server MUST retain the most recent accepted attempt and MAY
retain earlier ones. The effect of the number retained is discussed in
{{retention}}.

## Successful Response {#success}

The response is as defined in {{Section 5.1 of RFC6749}}. The authorization
server MUST NOT include a `refresh_token` parameter. The proof-bound refresh
token remains valid until the grant expires or is revoked.

## The duplicate_request Error {#duplicate-request}

This document defines the following error code for use in the error response
defined in {{Section 5.2 of RFC6749}}.

duplicate_request:
: The request is a retransmission of an attempt that the authorization server
  has already accepted. No access token is issued. The client's counter is to
  be advanced past that attempt.

The access token issued for the original request is not returned again. The
authorization server therefore retains no token material in order to answer a
retransmission.

# Client Requirements {#client}

The client holds, for each grant, the refresh token, the private refresh key,
the counter of its most recent accepted attempt, and at most one pending
attempt.

The client MUST store the counter and nonce of an attempt durably before
sending the first request for it. A client that restarts while an attempt is
pending MUST resume that attempt with the stored counter and nonce.

The client retransmits a pending attempt, unchanged in counter and nonce, until
it receives one of the following.

- A successful response. The client records the attempt as accepted and uses
  the access token.
- A `duplicate_request` error. The client records the attempt as accepted and
  begins a new attempt, with the next counter value and a new nonce, to obtain
  an access token.
- An `invalid_grant` or `invalid_client` error. The grant is no longer usable.
  The client discards its state and repeats the authorization request.

The client MUST treat any other outcome as a lost response. This includes
connection failures, timeouts, responses with a 5xx or 429 status code,
responses generated by intermediaries, and responses with a 200 status code
that cannot be parsed as a token response. The client SHOULD apply a delay that
increases between retransmissions.

The client MUST NOT have more than one attempt outstanding for a grant. Where
several execution contexts share a grant, such as multiple browser tabs or
processes, they MUST serialize refresh requests. Two contexts that each send
the next counter value with different nonces are indistinguishable from two
holders of the key, and the grant is revoked.

# Authorization Server Metadata {#metadata}

This document defines the following authorization server metadata {{RFC8414}}
parameter.

refresh_proof_alg_values_supported:
: A JSON array of JWS `alg` values that the authorization server supports for
  refresh proofs. Presence of this parameter indicates support for this
  document.

An authorization server that supports this document MUST support `ES256`.

A client MUST NOT send `refresh_jwk` to an authorization server that does not
publish this parameter. An authorization server that does not implement this
document ignores the unrecognized parameter and issues an ordinary refresh
token, and the token response would give the client no indication of this.

# Security Considerations {#security}

## Detection of a Second Key Holder {#second-holder}

A party that obtains the private refresh key and the refresh token can obtain
access tokens. When both that party and the client subsequently use the grant,
one of them sends a counter value that is not `last` + 1, or sends `last` + 1
after the other has done so with a different nonce, and the grant is revoked
under step 5 of {{as-processing}}. Detection does not depend on the distance
between the two parties' counters or on the number of accepted attempts the
authorization server retains.

As with refresh token rotation, detection requires that both parties use the
grant. If the client never refreshes again, the second party is not detected.
If the second party's copy was made while the client had an attempt pending,
both hold the same counter and nonce, and detection occurs at the following
attempt.

## Key Storage {#key-storage}

Whether a private key is extractable cannot be observed by the authorization
server and is not required by this document. A non-extractable key prevents the
theft of a usable credential from client storage. An extractable key does not,
but its use by a second party is detected as described in {{second-holder}}.
The mechanism is intended to provide detection in both cases and prevention in
the first.

## Attacker Executing in the Client {#in-client}

An attacker able to execute code in the client can use a non-extractable key to
produce refresh proofs. Proofs produced for future counter values and used
elsewhere are subject to the same detection as a copied key: each is valid for
one counter value, and the attacker and the client cannot both have that
counter value accepted. An attacker that prevents the client from refreshing is
not detected. This document does not otherwise address an attacker in this
position.

## Captured Requests {#captured}

A refresh request contains the refresh token and a refresh proof and does not
contain a value from which a later proof can be computed. A party that captures
a request, in transit or from a log, and replays it receives a
`duplicate_request` error if the attempt is retained by the authorization
server, and otherwise causes the grant to be revoked. It does not obtain an
access token in either case.

A party able to prevent a request from reaching the authorization server, and
to submit it instead, obtains one access token. The client's retransmission
then receives `duplicate_request` and the client proceeds; the event is not
detected.

A nonce is required in addition to the counter. If requests were identified by
the counter alone, a retransmission by the client and a request for the same
counter value from a second key holder could not be distinguished, and a second
key holder could avoid detection by sending only counter values that the client
had already used.

## Retention of Accepted Attempts {#retention}

A retransmission that arrives after its attempt is no longer retained is
processed under step 5 of {{as-processing}} and causes the grant to be revoked,
although only one party holds the key. This can occur when a request is delayed
in the network until after the client has completed later attempts. An
authorization server that retains only the most recent accepted attempt is
exposed to this whenever a delayed request arrives after one further refresh.
Retaining more accepted attempts reduces the exposure at a cost of one counter
and nonce each. The appropriate number is an open issue ({{open-issues}}).

## Access Tokens

Access tokens issued under this mechanism are bearer tokens. This document does
not alter their properties.

# IANA Considerations

This section is not yet written. See {{open-issues}}.

--- back

# Example {#example}

The counters, nonces, proofs, keys and tokens below were produced by an
implementation of this document using `ES256`. The client identifier and host
are illustrative. Line breaks and the unencoded JWK are for display only.

Authorization code exchange:

~~~
POST /token HTTP/1.1
Host: as.example
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=s6BhdRkqt3
&code=R1Kvwmneckl-K_N0aSE1nw
&code_verifier=HhICLMoSdtQ2Jpp4Ie1Q6W569MFAfD-50GllSDLMZas
&refresh_jwk={"alg":"ES256","kty":"EC","crv":"P-256",
  "x":"ptCw10qYlRF7bP1I3SFDFpX8bl7EsnXropZ2NeVWJKA",
  "y":"gi8uJaogtP5Xyjtv_PSXA0EET1wkni9pyIJrJbFXOz0"}

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "dC00HpPoxcMTv0Of75fOMrjCpSjj9im6jNtW1qUw9cQ",
  "token_type": "Bearer",
  "expires_in": 300,
  "refresh_token": "U-Oz88d4L4Hygk-uUTR8O2cYAGqH49GNrKsG5dYGq8A"
}
~~~

Second refresh. The signing input is:

~~~
U-Oz88d4L4Hygk-uUTR8O2cYAGqH49GNrKsG5dYGq8A.2.XqZLPBvDCTCwLUi3rFCENQ
~~~

The authorization server accepts the request and the response is lost.

~~~
POST /token HTTP/1.1
Host: as.example
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&client_id=s6BhdRkqt3
&refresh_token=U-Oz88d4L4Hygk-uUTR8O2cYAGqH49GNrKsG5dYGq8A
&refresh_counter=2
&refresh_nonce=XqZLPBvDCTCwLUi3rFCENQ
&refresh_proof=HOBS7NcxRTvLWeDBVvAC7Ww2-txlc8uzgeRlsc3QUYfP
  PYUqz6RgEphQ9NGmR37_PFyRzxEtQX8k1-rajUP64A
~~~

Retransmission, with the same counter and nonce and a new signature:

~~~
POST /token HTTP/1.1
Host: as.example
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&client_id=s6BhdRkqt3
&refresh_token=U-Oz88d4L4Hygk-uUTR8O2cYAGqH49GNrKsG5dYGq8A
&refresh_counter=2
&refresh_nonce=XqZLPBvDCTCwLUi3rFCENQ
&refresh_proof=UH30pDbEnXQwlKFvC1jvXg-833c7WUt0PJNack1XuvhA
  h3Hdq-GosFRVP-sOb4xvyyBrdRvS9oZ0jpAfCF99Hw

HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{ "error": "duplicate_request" }
~~~

Third refresh, with the same refresh token:

~~~
POST /token HTTP/1.1
Host: as.example
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&client_id=s6BhdRkqt3
&refresh_token=U-Oz88d4L4Hygk-uUTR8O2cYAGqH49GNrKsG5dYGq8A
&refresh_counter=3
&refresh_nonce=fVau5zDbypNY0HG2-L9f9Q
&refresh_proof=-mbTVv5kFRmSsHy8b0hLjWweSqXXT0TqrlsseUzHjTCM
  0f9PK0Gfs1lPRHWIp8JtK4cZK26qcwhXjB4q6tLYgA

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "uFEuw4Q3mLAtPStnHxSACEutwwsZ7YZi-YOd5KQcnqI",
  "token_type": "Bearer",
  "expires_in": 300
}
~~~

After the client's fourth refresh is accepted, a second holder of the key sends
counter value 4 with its own nonce. The proof is valid, the counter is not
`last` + 1, and the nonce does not match the retained attempt. The grant is
revoked, and the client's fifth refresh also receives `invalid_grant`.

~~~
POST /token HTTP/1.1
Host: as.example
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&client_id=s6BhdRkqt3
&refresh_token=U-Oz88d4L4Hygk-uUTR8O2cYAGqH49GNrKsG5dYGq8A
&refresh_counter=4
&refresh_nonce=fDhO-9XRuqf5a0N0w4OZBw
&refresh_proof=PCcqw3EvPQBuaMAmYQNF97Z_Cf2z4TcL7-KxW3jsotr-
  l_4n1xa8ZDXpX5eG7fqp0BcoQ4_FHcnW5Q56Fc3FCA

HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{ "error": "invalid_grant" }
~~~

# Open Issues {#open-issues}

This document is an early draft. The following are known to be unresolved, and
comment is invited on each.

Retention:
: How many accepted attempts an authorization server is to retain, and whether
  the number is to be specified or left to deployment ({{retention}}).

Lost code exchange response:
: The authorization code exchange is not retryable. The same key could be used
  to make it so.

Other grants:
: Only the authorization code grant is covered.

Algorithms:
: Only `ES256` is mandatory. Whether a second algorithm is to be required, and
  how a grant moves to a new key or algorithm, are not addressed.

Relationship to DPoP:
: Whether the counter and nonce could be carried as claims in a DPoP proof for
  clients that implement DPoP, giving those clients detection as well.

Confidential clients:
: Whether the mechanism is of use to clients that authenticate.

Keyless alternative:
: A companion proposal, "OAuth 2.0 Rolling Refresh Verifiers"
  (draft-gerber-oauth-rolling-refresh-verifiers), has the same sequence
  structure but replaces the signature with a hash preimage in the manner of
  PKCE. It requires no asymmetric cryptography, cannot use non-extractable
  storage, and allows a party holding only the refresh token to cause
  revocation. Which of the two is preferable is an open question.

Parameter names:
: All names in this document are provisional.

IANA considerations:
: Not yet written.
