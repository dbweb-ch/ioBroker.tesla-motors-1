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
        axiosCookieJarSupport(axios);
        this.cookieJar = new tough.CookieJar();
        const adapterConfig = "system.adapter." + this.name + "." + this.instance;
        const obj = await this.getForeignObjectAsync(adapterConfig);
        if (obj && obj.native.cookies) {
            this.cookieJar = tough.CookieJar.fromJSON(obj.native.cookies);
        }
        this.requestClient = axios.create();
        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
        this.idArray = [];

        this.session = {};
        this.json2iob = new Json2iob(this);
        this.headers = {
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "x-tesla-user-agent": "TeslaApp/3.10.14-474/540f6f430/ios/12.5.1",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            "accept-language": "de-de",
        };
        await this.login();
        if (this.session.access_token) {
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
        const adapterConfig = "system.adapter." + this.name + "." + this.instance;
        const obj = await this.getForeignObjectAsync(adapterConfig);
        if (obj) {
            obj.native.captchaSvg = "";
            obj.native.captcha = "";
            this.setForeignObject(adapterConfig, obj);
        }

        const code = await this.requestClient({
            method: "post",
            url: this.url,
            headers: this.headers,
            data: qs.stringify(form),
            jar: this.cookieJar,
            withCredentials: true,
            maxRedirects: 0,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                return "";
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
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
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
                this.log.debug(JSON.stringify(res.data));
                const adapterConfig = "system.adapter." + this.name + "." + this.instance;
                const obj = await this.getForeignObjectAsync(adapterConfig);
                if (obj) {
                    obj.native.captchaSvg = res.data;
                    obj.native.cookies = this.cookieJar.toJSON();
                    this.setForeignObject(adapterConfig, obj);
                }

                return res.data;
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
                            name: device.modelId,
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
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "ioBroker 1.0",
            },
            data: "grant_type=refresh_token&client_id=ownerapi&refresh_token=" + this.session.refresh_token,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.setState("info.connection", true, true);
                return res.data;
            })
            .catch((error) => {
                this.setState("info.connection", false, true);
                this.log.error("refresh token failed");
                this.log.error(error);
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
    onUnload(callback) {
        try {
            callback();
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
