const axios = require('axios');
const otplib = require('otplib');

class RobloxPayout {
    constructor(roblosecurity, groupId, twofactorSecret) {
        this.roblosecurity = roblosecurity;
        this.groupId = groupId;
        this.twofactorSecret = twofactorSecret;

        this.headers = {
            'Cookie': `.ROBLOSECURITY=${this.roblosecurity}`,
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0',
            'Content-Type': 'application/json'
        };
    }

    _getTotp() {
        return otplib.authenticator.generate(this.twofactorSecret);
    }

    async _setCsrf() {
        try {
            await axios.post("https://auth.roblox.com/v2/logout", {}, { headers: this.headers });
        } catch (error) {
            const token = error.response?.headers['x-csrf-token'];
            if (token) {
                this.headers['X-CSRF-TOKEN'] = token;
                return true;
            }
            if (error.response?.status === 401) {
                console.log("Incorrect roblosecurity");
                return false;
            }
        }
        return false;
    }

    async _payoutRequest(userId, robuxAmount, extraHeaders = {}) {
        const reqHeaders = { ...this.headers, ...extraHeaders };
        try {
            return await axios.post(`https://groups.roblox.com/v1/groups/${this.groupId}/payouts`, {
                PayoutType: 1,
                Recipients: [
                    {
                        amount: robux_amount,
                        recipientId: userId,
                        recipientType: 0
                    }
                ]
            }, { headers: reqHeaders, validateStatus: () => true });
        } catch (error) {
            return error.response;
        }
    }

    async _verifyRequest(senderId, challengeId) {
        const response = await axios.post(
            `https://twostepverification.roblox.com/v1/users/${senderId}/challenges/authenticator/verify`,
            {
                actionType: "Generic",
                challengeId: challengeId,
                code: this._getTotp()
            },
            { headers: this.headers, validateStatus: () => true }
        );

        if (response.data.errors) {
            console.log("2fa error");
            console.log(response.data.errors[0].message);
            return null;
        }
        return response.data.verificationToken;
    }

    async _continueRequest(challengeId, challengeType, metadata) {
        return await axios.post("https://apis.roblox.com/challenge/v1/continue", {
            challengeId: challengeId,
            challengeType: challengeType,
            challengeMetadata: JSON.stringify(metadata)
        }, { headers: this.headers, validateStatus: () => true });
    }

    async payout(userId, robuxAmount) {
        if (!await this._setCsrf()) return false;

        console.log("Sending initial payout request...");
        let request = await this._payoutRequest(userId, robuxAmount);

        if (request.status === 200) {
            console.log("Robux successfully sent! (No challenge required)");
            return true;
        }

        const challengeType = (request.headers['rblx-challenge-type'] || "").toLowerCase();
        const challengeId = request.headers['rblx-challenge-id'] || "";
        const challengeMetadataB64 = request.headers['rblx-challenge-metadata'] || "";

        if (!challengeType || !challengeId) {
            console.log("Payout error - no challenge headers found");
            console.log(request.data);
            return false;
        }

        let finalReq;

        if (challengeType === "chef") {
            console.log("chef challenge detected. Solving...");
            const chefMetadata = JSON.parse(Buffer.from(challengeMetadataB64, 'base64').toString());

            const continueReq = await this._continueRequest(challengeId, "chef", chefMetadata);
            const contData = continueReq.data;

            const nextChallengeType = contData.challengeType || "";
            const nextMetadataRaw = contData.challengeMetadata || "";

            if (nextChallengeType === "") {
                console.log("chef passed without 2fa, retrying payout...");
                finalReq = await this._payoutRequest(userId, robuxAmount, {
                    "rblx-challenge-id": challengeId,
                    "rblx-challenge-type": "twostepverification",
                    "rblx-challenge-metadata": challengeMetadataB64
                });
            } else if (nextChallengeType === "twostepverification") {
                console.log("chef requires 2fa challenge...");
                const tfaMetadata = JSON.parse(nextMetadataRaw);
                const vtoken = await this._verifyRequest(tfaMetadata.userId, tfaMetadata.challengeId);
                if (!vtoken) return false;

                tfaMetadata.verificationToken = vtoken;
                tfaMetadata.rememberDevice = false;
                await this._continueRequest(challengeId, "twostepverification", tfaMetadata);

                const tfaProof = Buffer.from(JSON.stringify({
                    rememberDevice: false,
                    actionType: "Generic",
                    verificationToken: vtoken,
                    challengeId: tfaMetadata.challengeId
                })).toString('base64');

                console.log("Retrying payout with 2fa proof...");
                const retryHeaders = {
                    "rblx-challenge-id": challenge_id,
                    "rblx-challenge-type": "twostepverification",
                    "rblx-challenge-metadata": tfaProof
                };
                finalReq = await this._payoutRequest(userId, robuxAmount, retryHeaders);

                if (finalReq.status !== 200) {
                    console.log("First retry failed, trying alternative chef headers...");
                    retryHeaders["rblx-challenge-type"] = "chef";
                    retryHeaders["rblx-challenge-metadata"] = challengeMetadataB64;
                    finalReq = await this._payoutRequest(userId, robuxAmount, retryHeaders);
                }
            }
        } else if (challengeType === "twostepverification") {
            console.log("No chef challenge, doing 2fa...");
            const metadata = JSON.parse(Buffer.from(challengeMetadataB64, 'base64').toString());
            const vtoken = await this._verifyRequest(metadata.userId, metadata.challengeId);
            if (!vtoken) return false;

            const tfaProof = {
                rememberDevice: false,
                actionType: "Generic",
                verificationToken: vtoken,
                challengeId: metadata.challengeId
            };

            await this._continueRequest(challengeId, "twostepverification", tfaProof);

            finalReq = await this._payoutRequest(userId, robuxAmount, {
                'rblx-challenge-id': challengeId,
                'rblx-challenge-metadata': Buffer.from(JSON.stringify(tfaProof)).toString('base64'),
                'rblx-challenge-type': "twostepverification"
            });
        }

        if (finalReq && finalReq.status === 200) {
            console.log("Robux successfully sent!");
            return true;
        } else {
            console.log("Payout failed.");
            return false;
        }
    }
}

module.exports = RobloxPayout;