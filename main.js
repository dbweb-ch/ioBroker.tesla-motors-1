"use strict";

/*
 * Created with @iobroker/create-adapter v1.34.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios");
const qs = require("qs");

const crypto = require("crypto");
const Json2iob = require("./lib/json2iob");
const axiosCookieJarSupport = require("axios-cookiejar-support").default;
const tough = require("tough-cookie");

class Teslamotors extends utils.Adapter {
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "tesla-motors",
        });
        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Initialize your adapter here

        // Reset the connection indicator during startup
        this.setState("info.connection", false, true);
        if (this.config.interval < 0.5) {
            this.log.info("Set interval to minimum 0.5");
            this.config.interval = 0.5;
        }
        this.adapterConfig = "system.adapter." + this.name + "." + this.instance;
        const obj = await this.getForeignObjectAsync(this.adapterConfig);
        if (this.config.reset) {
            if (obj) {
                obj.native.session = {};
                obj.native.cookies = "";
                obj.native.captchaSvg = "";
                obj.native.reset = false;
                obj.native.captcha = "";
                await this.setForeignObjectAsync(this.adapterConfig, obj);
                this.log.info("Login Token resetted");
                this.terminate();
            }
        }

        if (this.config.captchaSvg && !this.config.captcha) {
            this.log.info("Waiting for captcha");
            return;
        }

        axiosCookieJarSupport(axios);
        this.cookieJar = new tough.CookieJar();

        if (obj && obj.native.cookies) {
            this.cookieJar = tough.CookieJar.fromJSON(obj.native.cookies);
        }

        this.requestClient = axios.create();

        this.session = {};
        this.ownSession = {};
        if (obj && obj.native.session && obj.native.session.refresh_token) {
            this.session = obj.native.session;
            await this.refreshToken();
        }
        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
        this.idArray = [];

        this.json2iob = new Json2iob(this);
        this.headers = {
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "x-tesla-user-agent": "TeslaApp/3.10.14-474/540f6f430/ios/12.5.1",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            "accept-language": "de-de",
        };
        if (!this.session.access_token) {
            await this.login();
        }
        if (this.session.access_token && this.ownSession.access_token) {
            await this.getDeviceList();
            this.updateInterval = setInterval(async () => {
                await this.updateDevices();
            }, this.config.interval * 60 * 1000);
            this.refreshTokenInterval = setInterval(() => {
                this.refreshToken();
            }, this.session.expires_in * 1000);
        }
    }
    async login() {
        const [code_verifier, codeChallenge] = this.getCodeChallenge();
        this.state = this.randomString(43);
        this.url =
            "https://auth.tesla.com/oauth2/v3/authorize?audience=&client_id=ownerapi&code_challenge=" +
            codeChallenge +
            "&code_challenge_method=S256&locale=de&prompt=login&redirect_uri=https%3A%2F%2Fauth.tesla.com%2Fvoid%2Fcallback&response_type=code&scope=openid%20email%20offline_access&state=" +
            this.state;

        const htmlLoginForm = await this.requestClient({
            method: "get",
            url: this.url,
            headers: this.headers,
            jar: this.cookieJar,
            withCredentials: true,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.setState("info.connection", true, true);
                return res.data;
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!htmlLoginForm) {
            return;
        }
        let form = {};
        form = this.extractHidden(htmlLoginForm);
        form["identity"] = this.config.username;
        form["credential"] = this.config.password;
        if (!this.config.captcha) {
            await this.receiveCaptcha();
            this.log.warn("Please enter captcha in instance setting");
            return;
        }
        form["captcha"] = this.config.captcha;

        const code = await this.requestClient({
            method: "post",
            url: this.url,
            headers: this.headers,
            data: qs.stringify(form),
            jar: this.cookieJar,
            withCredentials: true,
            maxRedirects: 0,
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                if (res.data.split("messages = ")[1]) {
                    this.log.error(res.data.split("messages = ")[1].split(";")[0]);
                    const obj = await this.getForeignObjectAsync(this.adapterConfig);
                    this.log.info("reset captcha");
                    if (obj) {
                        obj.native.captchaSvg = "";
                        obj.native.captcha = "";
                        obj.native.mfa = "";
                        this.setForeignObject(this.adapterConfig, obj);
                    }
                    return;
                }

                if (this.config.mfa) {
                    const transactionid = res.data.split(' transaction_id: "')[1].split('",')[0];
                    await this.handleMfa(transactionid);
                    return await this.requestClient({
                        method: "post",
                        url: this.url,
                        headers: this.headers,
                        data: "transaction_id=" + transactionid,
                        jar: this.cookieJar,
                        withCredentials: true,
                        maxRedirects: 0,
                    })
                        .then(async (res) => {
                            this.log.debug(JSON.stringify(res.data));
                        })
                        .catch((error) => {
                            if (error.response && error.response.status === 302) {
                                return error.response.data.split("https://auth.tesla.com/void/callback?code=")[1].split("&amp;")[0];
                            } else {
                                error.response && this.log.error(JSON.stringify(error.response.data));
                                this.log.error(error);
                            }
                        });
                }
                this.log.error("Missing mfa or check username passwor");
                return;
            })
            .catch((error) => {
                if (error.response && error.response.status === 302) {
                    return error.response.data.split("https://auth.tesla.com/void/callback?code=")[1].split("&amp;")[0];
                } else {
                    error.response && this.log.error(JSON.stringify(error.response.data));
                    this.log.error(error);
                }
            });

        let data = {
            grant_type: "authorization_code",
            code: code,
            client_id: "ownerapi",
            redirect_uri: "https://auth.tesla.com/void/callback",
            scope: "openid offline_access",
            code_verifier: code_verifier,
        };
        this.log.debug(JSON.stringify(data));
        await this.requestClient({
            method: "post",
            url: "https://auth.tesla.com/oauth2/v3/token",
            headers: this.headers,
            data: qs.stringify(data),
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;

                await this.getOwnerToken();
                this.setState("info.connection", true, true);
                return res.data;
            })
            .catch((error) => {
                this.setState("info.connection", false, true);
                this.log.error(error);

                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });
    }
    async receiveCaptcha() {
        await this.requestClient({
            method: "get",
            url: "https://auth.tesla.com/captcha",
            headers: {
                accept: "image/png,image/svg+xml,image/*;q=0.8,video/*;q=0.8,*/*;q=0.5",
                "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                "accept-language": "de-de",
            },
            jar: this.cookieJar,
            withCredentials: true,
        })
            .then(async (res) => {
                this.log.silly(JSON.stringify(res.data));

                const obj = await this.getForeignObjectAsync(this.adapterConfig);
                if (obj) {
                    obj.native.captchaSvg = res.data;
                    obj.native.cookies = this.cookieJar.toJSON();
                    this.setForeignObject(this.adapterConfig, obj);
                }

                return res.data;
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }
    async handleMfa(transaction_id) {
        this.log.debug("start mfa");
        const id = await this.requestClient({
            method: "get",
            url: "https://auth.tesla.com/oauth2/v3/authorize/mfa/factors?transaction_id=" + transaction_id,
            headers: {
                accept: "application/json",
                "content-type": "application/json;charset=UTF-8",
                "accept-language": "de-de",
                "x-requested-with": "XMLHttpRequest",
                "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                referer:
                    "https://auth.tesla.com/oauth2/v1/authorize?redirect_uri=https://www.tesla.com/teslaaccount/owner-xp/auth/callback&response_type=code&client_id=ownership&scope=offline_access%20openid%20ou_code%20email&audience=https%3A%2F%2Fownership.tesla.com%2",
            },
            jar: this.cookieJar,
            withCredentials: true,
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                if (res.data.data && res.data.data[0] && res.data.data[0].id) {
                    return res.data.data[0].id;
                }
                this.log.error("MFA Init Failed");
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        await this.requestClient({
            method: "post",
            url: "https://auth.tesla.com/oauth2/v3/authorize/mfa/verify",
            headers: {
                "content-type": "application/json;charset=UTF-8",
                accept: "application/json",
                "x-requested-with": "XMLHttpRequest",
                "accept-language": "de-de",
                "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            },
            jar: this.cookieJar,
            withCredentials: true,
            data: { transaction_id: transaction_id, factor_id: id, passcode: this.config.mfa },
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                if (res.data.data && res.data.data.valid) {
                    return;
                }
                this.log.error("MFA Submit Failed");
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async getDeviceList() {
        const headers = {
            "Content-Type": "application/json",
            Accept: "*/*",
            "User-Agent": "ioBroker 1.0.0",
            Authorization: "Bearer " + this.session.access_token,
        };
        await this.requestClient({
            method: "get",
            url: "https://owner-api.teslamotors.com/api/1/products",
            headers: headers,
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                for (const device of res.data.response) {
                    this.idArray.push(device.id);
                    await this.setObjectNotExistsAsync(device.vin, {
                        type: "device",
                        common: {
                            name: device.display_name,
                        },
                        native: {},
                    });

                    await this.setObjectNotExistsAsync(device.vin + ".general", {
                        type: "channel",
                        common: {
                            name: "General Device Information",
                        },
                        native: {},
                    });

                    this.json2iob.parse(device.vin + ".general", device);
                }
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }
    async updateDevices() {}
    async refreshToken() {
        await this.requestClient({
            method: "post",
            url: "https://auth.tesla.com/oauth2/v3/token",
            headers: this.headers,
            data: "grant_type=refresh_token&client_id=ownerapi&scope=openid email offline_access&refresh_token=" + this.session.refresh_token,
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session.access_token = res.data.access_token;
                this.session.expires_in = res.data.expires_in;

                await this.getOwnerToken();
                this.setState("info.connection", true, true);
                return res.data;
            })
            .catch(async (error) => {
                this.setState("info.connection", false, true);
                this.log.error("refresh token failed");
                this.log.error(error);
                this.session = {};

                error.response && this.log.error(JSON.stringify(error.response.data));
                this.log.error("Start relogin in 1min");
                this.reLoginTimeout = setTimeout(() => {
                    this.login();
                }, 1000 * 60 * 1);
            });
    }
    async getOwnerToken() {
        await this.requestClient({
            method: "post",
            url: "https://owner-api.teslamotors.com/oauth/token",
            headers: {
                "content-type": "application/json; charset=utf-8",
                accept: "*/*",
                authorization: "bearer " + this.session.access_token,
                "accept-language": "de-de",
                "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                "x-tesla-user-agent": "TeslaApp/3.10.14-474/540f6f430/ios/12.5.1",
            },
            data: { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", client_id: "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384" },
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                this.ownSession = res.data;

                return res.data;
            })
            .catch(async (error) => {
                this.setState("info.connection", false, true);
                this.log.error("own token failed");
                this.log.error(error);
                this.session = {};
                error.response && this.log.error(JSON.stringify(error.response.data));
                this.log.error("Start relogin in 1min");
                this.reLoginTimeout = setTimeout(() => {
                    this.login();
                }, 1000 * 60 * 1);
            });
    }
    getCodeChallenge() {
        let hash = "";
        let result = "";
        const chars = "0123456789abcdef";
        result = "";
        for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
        hash = crypto.createHash("sha256").update(result).digest("base64");
        hash = hash.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

        return [result, hash];
    }
    randomString(length) {
        let result = "";
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }
    extractHidden(body) {
        const returnObject = {};
        let matches;
        if (body.matchAll) {
            matches = body.matchAll(/<input (?=[^>]* name=["']([^'"]*)|)(?=[^>]* value=["']([^'"]*)|)/g);
        } else {
            this.log.warn("The adapter needs in the future NodeJS v12. https://forum.iobroker.net/topic/22867/how-to-node-js-f%C3%BCr-iobroker-richtig-updaten");
            matches = this.matchAll(/<input (?=[^>]* name=["']([^'"]*)|)(?=[^>]* value=["']([^'"]*)|)/g, body);
        }
        for (const match of matches) {
            returnObject[match[1]] = match[2];
        }
        return returnObject;
    }
    matchAll(re, str) {
        let match;
        const matches = [];

        while ((match = re.exec(str))) {
            // add all matched groups
            matches.push(match);
        }

        return matches;
    }
    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    async onUnload(callback) {
        try {
            callback();

            const obj = await this.getForeignObjectAsync(this.adapterConfig);
            if (obj) {
                obj.native.session = this.session;
                // obj.native.captchaSvg = "";
                // obj.native.captcha = "";
                // obj.native.mfa = "";
                this.log.debug("Session saved");
                this.setForeignObject(this.adapterConfig, obj);
            }
        } catch (e) {
            callback();
        }
    }

    /**
     * Is called if a subscribed state changes
     * @param {string} id
     * @param {ioBroker.State | null | undefined} state
     */
    onStateChange(id, state) {
        if (state) {
            // The state was changed
            this.log.info(`state ${id} changed: ${state.val} (ack = ${state.ack})`);
        } else {
            // The state was deleted
            this.log.info(`state ${id} deleted`);
        }
    }
}

if (require.main !== module) {
    // Export the constructor in compact mode
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    module.exports = (options) => new Teslamotors(options);
} else {
    // otherwise start the instance directly
    new Teslamotors();
}
