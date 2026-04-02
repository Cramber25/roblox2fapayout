import requests
import base64
import json
import pyotp


class RobloxPayout:
    def __init__(self, roblosecurity, group_id, twofactor_secret):
        self.roblosecurity = roblosecurity
        self.group_id = group_id
        self.twofactor_secret = twofactor_secret

        self.headers = {
            'Cookie': ".ROBLOSECURITY=" + self.roblosecurity,
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0'
        }

    def _get_totp(self):
        totp = pyotp.TOTP(self.twofactor_secret)
        return totp.now()

    def _set_csrf(self):
        request = requests.post("https://auth.roblox.com/v2/logout", headers=self.headers)

        if request.status_code == 401:
            print("Incorrect roblosecurity")
            return False

        token = request.headers.get('X-CSRF-TOKEN') or request.headers.get('x-csrf-token')
        if token:
            self.headers.update({'X-CSRF-TOKEN': token})
        return True

    def _payout_request(self, user_id, robux_amount, extra_headers=None):
        req_headers = self.headers.copy()
        if extra_headers:
            req_headers.update(extra_headers)

        request = requests.post("https://groups.roblox.com/v1/groups/" + str(self.group_id) + "/payouts",
            headers=req_headers,
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

    def _verify_request(self, sender_id, challenge_id):
        request = requests.post(
            "https://twostepverification.roblox.com/v1/users/" + str(sender_id) + "/challenges/authenticator/verify",
            headers=self.headers, json={
                "actionType": "Generic",
                "challengeId": challenge_id,
                "code": self._get_totp()
            }
        )

        req_json = request.json()
        if "errors" in req_json:
            print("2fa error")
            print(req_json["errors"][0]["message"])
            return None

        return req_json["verificationToken"]

    def _continue_request(self, challenge_id, challenge_type, metadata):
        request = requests.post("https://apis.roblox.com/challenge/v1/continue", headers=self.headers, json={
            "challengeId": challenge_id,
            "challengeType": challenge_type,
            "challengeMetadata": json.dumps(metadata)
        })
        return request

    def payout(self, user_id, robux_amount):
        if not self._set_csrf():
            return False

        print("Sending initial payout request...")
        request = self._payout_request(user_id, robux_amount)

        if request.status_code == 200:
            print("Robux successfully sent! (No challenge required)")
            return True

        challenge_type = request.headers.get("rblx-challenge-type", "").lower()
        challenge_id = request.headers.get("rblx-challenge-id", "")
        challenge_metadata_b64 = request.headers.get("rblx-challenge-metadata", "")

        if not challenge_type or not challenge_id:
            print("Payout error - no challenge headers found")
            print(request.text)
            return False

        # handle chef challenge
        if challenge_type == "chef":
            print("chef challenge detected. Solving...")
            chef_metadata = json.loads(base64.b64decode(challenge_metadata_b64))

            # send chef continue request
            continue_req = self._continue_request(challenge_id, "chef", chef_metadata)
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
                final_req = self._payout_request(user_id, robux_amount, retry_headers)

            elif next_challenge_type == "twostepverification":
                # chef unlocked a 2fa challenge
                print("chef requires 2fa challenge...")
                tfa_metadata = json.loads(next_metadata_raw)
                tfa_user = tfa_metadata["userId"]
                tfa_cid = tfa_metadata["challengeId"]

                # send the totp verify request to roblox using the nested id
                vtoken = self._verify_request(tfa_user, tfa_cid)
                if not vtoken:
                    return False

                # continue the 2fa challenge
                tfa_metadata["verificationToken"] = vtoken
                tfa_metadata["rememberDevice"] = False
                self._continue_request(challenge_id, "twostepverification", tfa_metadata)

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
                final_req = self._payout_request(user_id, robux_amount, retry_headers)

                # fallback if standard twostepverification type fails on retry
                if final_req.status_code != 200:
                    print("First retry failed, trying alternative chef headers...")
                    retry_headers["rblx-challenge-type"] = "chef"
                    retry_headers["rblx-challenge-metadata"] = challenge_metadata_b64
                    final_req = self._payout_request(user_id, robux_amount, retry_headers)

            elif next_challenge_type == "blocksession":
                print("Session flagged (AutomatedTampering). Wait a minute and try again.")
                return False
            else:
                print("Unknown challenge:", next_challenge_type)
                return False

            # check final result
            if final_req.status_code == 200:
                print("Robux successfully sent after chef challenge!")
                return True
            else:
                print("Payout error after chef challenge:")
                print(final_req.text)
                return False

        # if chef is not required
        elif challenge_type == "twostepverification":
            print("No chef challenge, doing 2fa...")
            metadata = json.loads(base64.b64decode(challenge_metadata_b64))
            metadata_challenge_id = metadata["challengeId"]
            sender_id = metadata["userId"]

            verification_token = self._verify_request(sender_id, metadata_challenge_id)
            if not verification_token:
                return False

            tfa_proof = {
                "rememberDevice": False,
                "actionType": "Generic",
                "verificationToken": verification_token,
                "challengeId": metadata_challenge_id
            }

            self._continue_request(challenge_id, "twostepverification", tfa_proof)

            retry_headers = {
                'rblx-challenge-id': challenge_id,
                'rblx-challenge-metadata': base64.b64encode(json.dumps(tfa_proof).encode()).decode(),
                'rblx-challenge-type': "twostepverification"
            }

            final_req = self._payout_request(user_id, robux_amount, retry_headers)
            if final_req.status_code == 200:
                print("Robux successfully sent after 2fa!")
                return True
            else:
                print("Payout error after 2fa:")
                print(final_req.text)
                return False

        # handle session block
        elif challenge_type == "blocksession":
            print("Session temporarily flagged on first request. Wait a minute and try again.")
            return False
        else:
            print("Unknown challenge type:", challenge_type)
            return False