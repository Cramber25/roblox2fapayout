import requests
import base64
import json
import pyotp  # this import is just for generating the 2fa code

# put your roblosecurity cookie here
roblosecurity = ""

# put your group id here
group_id = 0

# put user id of the player you want to send robux to here
user_id = 0

# put the amount of robux to send here
robux_amount = 0

# two factor secret to generate the 6 digit 2fa code
twofactor_secret = ""

# actual code below

headers = {
    'Cookie': ".ROBLOSECURITY=" + roblosecurity,
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0'
}


# --- FUNCTIONS ---

def get_totp():
    totp = pyotp.TOTP(twofactor_secret)
    return totp.now()


def set_csrf():
    request = requests.post("https://auth.roblox.com/v2/logout", headers=headers)

    if request.status_code == 401:
        print("Incorrect roblosecurity")
        exit(0)

    token = request.headers.get('X-CSRF-TOKEN') or request.headers.get('x-csrf-token')
    headers.update({'X-CSRF-TOKEN': token})


def payout_request(extra_headers=None):
    req_headers = headers.copy()
    if extra_headers:
        req_headers.update(extra_headers)

    request = requests.post("https://groups.roblox.com/v1/groups/" + str(group_id) + "/payouts", headers=req_headers,
        json={
            "PayoutType": 1,
            "Recipients": [
                {
                    "amount": robux_amount,
                    "recipientId": user_id,
                    "recipientType": 0
                }
            ]
        }
    )
    return request


def verify_request(senderId, challengeId):
    request = requests.post(
        "https://twostepverification.roblox.com/v1/users/" + str(senderId) + "/challenges/authenticator/verify",
        headers=headers, json={
            "actionType": "Generic",
            "challengeId": challengeId,
            "code": get_totp()
        }
    )

    if "errors" in request.json():
        print("2fa error")
        print(request.json()["errors"][0]["message"])
        exit(0)
    return request.json()["verificationToken"]


def continue_request(challengeId, challengeType, metadata):
    request = requests.post("https://apis.roblox.com/challenge/v1/continue", headers=headers, json={
        "challengeId": challengeId,
        "challengeType": challengeType,
        "challengeMetadata": json.dumps(metadata)
    })
    return request


# --- Payout the robux ---

set_csrf()

print("Sending initial payout request...")
request = payout_request()

if request.status_code == 200:
    print("Robux successfully sent! (No challenge required)")
    exit(0)

# get necessary data to figure out what challenge we got
challenge_type = request.headers.get("rblx-challenge-type", "").lower()
challenge_id = request.headers.get("rblx-challenge-id", "")
challenge_metadata_b64 = request.headers.get("rblx-challenge-metadata", "")

if not challenge_type or not challenge_id:
    print("Payout error - no challenge headers found")
    print(request.text)
    exit(0)

# handle chef challenge
if challenge_type == "chef":
    print("chef challenge detected. Solving...")
    chef_metadata = json.loads(base64.b64decode(challenge_metadata_b64))

    # send chef continue request
    continue_req = continue_request(challenge_id, "chef", chef_metadata)
    cont_data = continue_req.json()

    next_challenge_type = cont_data.get("challengeType", "")
    next_metadata_raw = cont_data.get("challengeMetadata", "")

    if next_challenge_type == "":
        # chef passed immediately, retry payout
        print("chef passed without 2fa, retrying payout...")
        retry_headers = {
            "rblx-challenge-id": challenge_id,
            "rblx-challenge-type": "twostepverification",
            "rblx-challenge-metadata": challenge_metadata_b64
        }
        final_req = payout_request(retry_headers)

    elif next_challenge_type == "twostepverification":
        # chef unlocked a 2fa challenge
        print("chef requires 2fa challenge...")
        tfa_metadata = json.loads(next_metadata_raw)
        tfa_user = tfa_metadata["userId"]
        tfa_cid = tfa_metadata["challengeId"]

        # send the totp verify request to roblox using the nested id
        vtoken = verify_request(tfa_user, tfa_cid)

        # continue the 2fa challenge
        tfa_metadata["verificationToken"] = vtoken
        tfa_metadata["rememberDevice"] = False
        continue_request(challenge_id, "twostepverification", tfa_metadata)

        # generate proof for final payout
        tfa_proof = base64.b64encode(json.dumps({
            "rememberDevice": False,
            "actionType": "Generic",
            "verificationToken": vtoken,
            "challengeId": tfa_cid
        }).encode()).decode()

        print("Retrying payout with 2fa proof...")
        retry_headers = {
            "rblx-challenge-id": challenge_id,
            "rblx-challenge-type": "twostepverification",
            "rblx-challenge-metadata": tfa_proof
        }
        final_req = payout_request(retry_headers)

        # fallback if standard twostepverification type fails on retry
        if final_req.status_code != 200:
            print("First retry failed, trying alternative chef headers...")
            retry_headers["rblx-challenge-type"] = "chef"
            retry_headers["rblx-challenge-metadata"] = challenge_metadata_b64
            final_req = payout_request(retry_headers)

    elif next_challenge_type == "blocksession":
        print("Session flagged (AutomatedTampering). Wait a minute and try again.")
        exit(0)
    else:
        print("Unknown challenge:", next_challenge_type)
        exit(0)

    # Check final result
    if final_req.status_code == 200:
        print("Robux successfully sent after chef challenge!")
    else:
        print("Payout error after chef challenge:")
        print(final_req.text)


# if chef is not required
elif challenge_type == "twostepverification":
    print("No chef challenge, doing 2fa...")
    metadata = json.loads(base64.b64decode(challenge_metadata_b64))
    metadata_challengeId = metadata["challengeId"]
    senderId = metadata["userId"]

    verification_token = verify_request(senderId, metadata_challengeId)

    tfa_proof = {
        "rememberDevice": False,
        "actionType": "Generic",
        "verificationToken": verification_token,
        "challengeId": metadata_challengeId
    }

    continue_request(challenge_id, "twostepverification", tfa_proof)

    retry_headers = {
        'rblx-challenge-id': challenge_id,
        'rblx-challenge-metadata': base64.b64encode(json.dumps(tfa_proof).encode()).decode(),
        'rblx-challenge-type': "twostepverification"
    }

    final_req = payout_request(retry_headers)
    if final_req.status_code == 200:
        print("Robux successfully sent after 2fa!")
    else:
        print("Payout error after 2fa:")
        print(final_req.text)

# handle session block
elif challenge_type == "blocksession":
    print("Session temporarily flagged on first request. Wait a minute and try again.")
else:
    print("Unknown challenge type:", challenge_type)
