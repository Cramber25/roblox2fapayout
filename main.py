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

headers = {'Cookie': ".ROBLOSECURITY=" + roblosecurity}

# --- FUNCTIONS ---


def get_totp():
    totp = pyotp.TOTP(twofactor_secret)
    return totp.now()

def set_csrf():
    request = requests.post("https://auth.roblox.com/v2/logout", headers=headers)

    if request.status_code == 401:
        print("Incorrect roblosecurity")
        exit(0)

    headers.update({'X-CSRF-TOKEN': request.headers['X-CSRF-TOKEN']})

def payout_request():
    request = requests.post("https://groups.roblox.com/v1/groups/" + str(group_id) + "/payouts", headers=headers, json={
       "PayoutType": 1,
       "Recipients": [
           {
               "amount": robux_amount,
               "recipientId": user_id,
               "recipientType": 0
           }
       ]
    })
    if request.status_code == 403 and request.json()["errors"][0]["message"] == "Challenge is required to authorize the request":
        return request
    elif request.status_code == 200:
        print("Robux successfully sent!")
        return False
    else:
        print("payout error")
        print(request.json()["errors"][0]["message"])
        return False


def verify_request(senderId, metadata_challengeId):
    request = requests.post("https://twostepverification.roblox.com/v1/users/" + senderId + "/challenges/authenticator/verify", headers=headers, json={
        "actionType": "Generic",
        "challengeId": metadata_challengeId,
        "code": get_totp()
    })

    if "errors" in request.json():
        print("2fa error")
        print(request.json()["errors"][0]["message"])
        exit(0)
    return request.json()["verificationToken"]


def continue_request(challengeId, verification_token, metadata_challengeId):
    requests.post("https://apis.roblox.com/challenge/v1/continue", headers=headers, json={
        "challengeId": challengeId,
        "challengeMetadata": json.dumps({
            "rememberDevice": False,
            "actionType": "Generic",
            "verificationToken": verification_token,
            "challengeId": metadata_challengeId
        }),
        "challengeType": "twostepverification"
    })


# --- Payout the robux ---

set_csrf()

data = payout_request()
if data == False:
    exit(0)

# get necessary data for the 2fa validation
challengeId = data.headers["rblx-challenge-id"]
metadata = json.loads(base64.b64decode(data.headers["rblx-challenge-metadata"]))
metadata_challengeId = metadata["challengeId"]
senderId = metadata["userId"]

# send the totp verify request to roblox
verification_token = verify_request(senderId, metadata_challengeId)

# send the continue request, its really important
continue_request(challengeId, verification_token, metadata_challengeId)

# before sending the final payout request, add verification information to headers
headers.update({
    'rblx-challenge-id': challengeId,
    'rblx-challenge-metadata': base64.b64encode(json.dumps({
        "rememberDevice": False,
        "actionType": "Generic",
        "verificationToken": verification_token,
        "challengeId": metadata_challengeId
    }).encode()).decode(),
    'rblx-challenge-type': "twostepverification"
})

# send the final payout request
payout_request()
