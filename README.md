## Paying out robux from a group, handling the Chef challenge and two factor authentication

main.py contains example python code that does the whole process

# How it works:

### 1.
When your group payout request returns error 403, it contains three headers with data to figure out what challenge blocks your request. The headers are:
   - "rblx-challenge-type": it contains the type of the challenge (usually `chef`, `twostepverification`, or `blocksession`)
   - "rblx-challenge-id": it contains the outer challenge id
   - "rblx-challenge-metadata": this header contains base64 encoded metadata
### 2.
If the type is "chef", you need to decode the base64 metadata. Send a post request to `apis.roblox.com/challenge/v1/continue` with body containing this json to unlock the real challenge: 
```json
{
  "challengeId": "%outer challenge id%",
  "challengeMetadata": "%the decoded chef metadata%",
  "challengeType": "chef"
}
```

### 3.
The response to this request will contain a new `challengeType` and `challengeMetadata`. If it is empty, the challenge is done and you can retry the payout immediately. If it returns "twostepverification", it contains a nested challenge id and user id.

### 4.
Now you need to verify the 2fa code. Send a post request to the endpoint `twostepverification.roblox.com/v1/users/%user id from nested metadata%/challenges/authenticator/verify` (the response to this request will contain a verification token, used to validate your session), with body containing following json:
```json
{
  "actionType": "Generic",
  "challengeId": "%nested challenge id%",
  "code": "%your 6 digit 2fa code%"
}
```

### 5.
Now that you have the verification token, its time to validate your session. Send another post request to `apis.roblox.com/challenge/v1/continue` with body containing this json:
(Make sure to turn `challengeMetadata` value into a string. It can't be an object/dictionary.)
```json
{
  "challengeId": "%outer challenge id%",
  "challengeMetadata": { "rememberDevice": false, "actionType": "Generic", "verificationToken": "%the verification token%", "challengeId": "%the nested challenge id%" },
  "challengeType": "twostepverification"
}
```

### 6.
The next payout request using the same session has to include 3 new headers:
    - rblx-challenge-id - containing the outer challenge id
    - rblx-challenge-type - containing the string "twostepverification"
    - rblx-challenge-metadata - containing this base64 encoded json:
```json
{
   "rememberDevice": false,
   "actionType": "Generic",
   "verificationToken": "%the verification token%",
   "challengeId": "%the nested challenge id%"
}
```

### 7.
If the challenge type is "blocksession" at the beginning or after the chef request, your session is temporarily flagged. You need to wait around 90 seconds and try the whole process from scratch.

### 8.
That's it! Everything should be validated and robux sent.
