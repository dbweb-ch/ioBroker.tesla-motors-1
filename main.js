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
        this.sleepTimes = {};
        if (obj && obj.native.session && obj.native.session.refresh_token) {
            this.session = obj.native.session;
            await this.refreshToken();
        }
        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
        this.idArray = [];

        this.json2iob = new Json2iob(this);

        this.subscribeStates("*");
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
            this.updateDevices();
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
                this.log.info("Login successful");
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

                this.idArray = [];
                for (let device of res.data.response) {
                    const id = device.id_s || device.id;
                    this.log.debug(id);
                    if (device.vehicle_id) {
                        this.idArray.push(id);
                    } else {
                        this.nonVehicles = true;
                    }
                    await this.setObjectNotExistsAsync(id, {
                        type: "device",
                        common: {
                            name: device.display_name || device.site_name || device.resource_type,
                        },
                        native: {},
                    });

                    this.json2iob.parse(id, device);
                    if (!device.vehicle_id) {
                        continue;
                    }

                    await this.setObjectNotExistsAsync(id + ".remote", {
                        type: "channel",
                        common: {
                            name: "Remote Controls",
                        },
                        native: {},
                    });

                    const remoteArray = [
                        { command: "wake_up" },
                        { command: "honk_horn" },
                        { command: "flash_lights" },
                        { command: "remote_start_drive" },
                        { command: "trigger_homelink" },
                        { command: "set_sentry_mode" },
                        { command: "door_unlock" },
                        { command: "door_lock" },
                        { command: "actuate_trunk-rear" },
                        { command: "actuate_trunk-front" },
                        { command: "window_control-vent" },
                        { command: "window_control-close" },
                        { command: "sun_roof_control-vent" },
                        { command: "sun_roof_control-close" },
                        { command: "charge_port_door_open" },
                        { command: "charge_port_door_close" },
                        { command: "charge_start" },
                        { command: "charge_stop" },
                        { command: "charge_standard" },
                        { command: "charge_max_range" },
                        { command: "set_charge_limit", type: "number", role: "level" },
                        { command: "set_temps", type: "number", role: "level" },
                        { command: "set_temps-driver_temp", type: "number", role: "level" },
                        { command: "set_temps-passenger_temp", type: "number", role: "level" },
                        { command: "remote_seat_heater_request-0", type: "number", role: "level" },
                        { command: "remote_seat_heater_request-1", type: "number", role: "level" },
                        { command: "remote_seat_heater_request-2", type: "number", role: "level" },
                        { command: "remote_seat_heater_request-4", type: "number", role: "level" },
                        { command: "remote_seat_heater_request-5", type: "number", role: "level" },
                        { command: "auto_conditioning_start" },
                        { command: "auto_conditioning_stop" },
                        { command: "media_toggle_playback" },
                        { command: "media_next_track" },
                        { command: "media_prev_track" },
                        { command: "media_volume_up" },
                        { command: "media_volume_down" },
                        { command: "set_preconditioning_max" },
                        { command: "remote_steering_wheel_heater_request" },
                    ];
                    remoteArray.forEach((remote) => {
                        this.setObjectNotExists(id + ".remote." + remote.command, {
                            type: "state",
                            common: {
                                name: remote.name || "",
                                type: remote.type || "boolean",
                                role: remote.role || "button",
                                write: true,
                                read: true,
                            },
                            native: {},
                        });
                    });
                }
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }
    async updateDevices() {
        const statusArray = [{ path: "", url: "https://owner-api.teslamotors.com/api/1/vehicles/{id}/vehicle_data" }];

        const headers = {
            "Content-Type": "application/json; charset=utf-8",
            Accept: "*/*",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            "x-tesla-user-agent": "TeslaApp/3.10.14-474/540f6f430/ios/12.5.1",
            Authorization: "Bearer " + this.ownSession.access_token,
        };

        this.idArray.forEach(async (id) => {
            //check state
            const state = await this.requestClient({
                method: "get",
                url: "https://owner-api.teslamotors.com/api/1//vehicles/" + id,
                headers: headers,
            })
                .then((res) => {
                    this.log.debug(JSON.stringify(res.data));

                    return res.data.response.state;
                })
                .catch((error) => {
                    this.log.error(error);
                    error.response && this.log.error(JSON.stringify(error.response.data));
                });

            if (state === "asleep" && !this.config.wakeup) {
                this.log.debug(id + " asleep skip update");
                return;
            }

            const waitForSleep = await this.checkWaitForSleepState(id);
            if (waitForSleep && !this.config.wakeup) {
                if (!this.sleepTimes[id]) {
                    this.sleepTimes[id] = Date.now();
                }
                //wait 15min
                if (Date.now() - this.sleepTimes[id] >= 900000) {
                    this.log.debug(id + " wait for sleep was not successful");
                    this.sleepTimes[id] = null;
                } else {
                    this.log.debug(id + " skip update waiting for sleep");
                    return;
                }
            }

            if (this.config.wakeup) {
                await this.sendCommand(id, "wake_up");
                await this.sleep(15000);
            }
            statusArray.forEach(async (element) => {
                let url = element.url.replace("{id}", id);
                this.log.debug(url);
                await this.requestClient({
                    method: "get",
                    url: url,
                    headers: headers,
                })
                    .then((res) => {
                        this.log.debug(JSON.stringify(res.data));

                        if (!res.data) {
                            return;
                        }
                        let data = res.data.response;

                        this.json2iob.parse(id + element.path, data);
                    })
                    .catch((error) => {
                        if (error.response && error.response.status === 401) {
                            error.response && this.log.debug(JSON.stringify(error.response.data));
                            this.log.info(element.path + " receive 401 error. Refresh Token in 30 seconds");
                            clearTimeout(this.refreshTokenTimeout);
                            this.refreshTokenTimeout = setTimeout(() => {
                                this.refreshToken();
                            }, 1000 * 30);

                            return;
                        }
                        if (error.response && error.response.status === 404) {
                            if (element.path === "statusv1") {
                                this.statusBlock[id] = true;
                            }
                        }

                        this.log.error(url);
                        this.log.error(error);
                        error.response && this.log.error(JSON.stringify(error.response.data));
                    });
            });
        });

        if (this.nonVehicles) {
            this.getDeviceList();
        }
    }
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
                if (error.code === "ENOTFOUND") {
                    this.log.error("No connection to Tesla server please check your connection");
                    return;
                }
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
    async checkWaitForSleepState(id) {
        const checkStates = [".drive_state.shift_state", ".drive_state.speed", ".climate_state.is_climate_on", ".charge_state.battery_range", ".vehicle_state.odometer", ".vehicle_state.locked"];
        for (let stateId of checkStates) {
            const curState = await this.getStateAsync(id + stateId);
            //laste update not older than 30min and last change not older then 30min
            if (curState && (curState.ts <= Date.now() - 1800000 || curState.ts - curState.lc <= 1800000)) {
                return false;
            }
        }
        this.log.debug("30 min not change. Start waiting for sleep");
        return true;
    }
    async sendCommand(id, command, action, value) {
        const headers = {
            "Content-Type": "application/json; charset=utf-8",
            Accept: "*/*",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            "x-tesla-user-agent": "TeslaApp/3.10.14-474/540f6f430/ios/12.5.1",
            Authorization: "Bearer " + this.ownSession.access_token,
        };
        let url = "https://owner-api.teslamotors.com/api/1/vehicles/" + id + "/command/" + command;

        if (command === "wake_up") {
            url = "https://owner-api.teslamotors.com/api/1/vehicles/" + id + "/wake_up";
        }
        const passwordArray = ["remote_start_drive"];
        const latlonArray = ["trigger_homelink", "window_control"];
        const onArray = ["remote_steering_wheel_heater_request", "set_preconditioning_max", "set_sentry_mode"];
        const valueArray = ["set_temps"];
        const stateArray = ["sun_roof_control"];
        const commandArray = ["window_control"];
        const percentArray = ["set_charge_limit"];
        let data = {};
        if (command in passwordArray) {
            data["password"] = this.config.password;
        }
        if (command in latlonArray) {
            const latState = await this.getStateAsync(id + ".drive_state.latitude");
            const lonState = await this.getStateAsync(id + ".drive_state.longitude");
            data["lat"] = latState ? latState.val : 0;
            data["lon"] = lonState ? lonState.val : 0;
        }
        if (onArray.includes(command)) {
            data["on"] = value;
        }
        if (valueArray.includes(command)) {
            if (command === "set_temps") {
                const driverState = await this.getStateAsync(id + ".climate_state.driver_temp_setting");
                const passengerState = await this.getStateAsync(id + ".climate_state.passenger_temp_setting");
                data["driver_temp"] = driverState ? driverState.val : 23;
                data["passenger_temp"] = passengerState ? passengerState.val : driverState.val;
            }
            data[action] = value;
        }
        if (stateArray.includes(command)) {
            data["state"] = action;
        }
        if (commandArray.includes(command)) {
            data["command"] = action;
        }
        if (percentArray.includes(command)) {
            data["percent"] = value;
        }

        this.log.debug(url);
        this.log.debug(JSON.stringify(data));
        await this.requestClient({
            method: "post",
            url: url,
            headers: headers,
        })
            .then((res) => {
                this.log.info(JSON.stringify(res.data));
            })
            .catch((error) => {
                if (error.response && error.response.status === 401) {
                    error.response && this.log.debug(JSON.stringify(error.response.data));
                    this.log.info(command + " receive 401 error. Refresh Token in 30 seconds");
                    clearTimeout(this.refreshTokenTimeout);
                    this.refreshTokenTimeout = setTimeout(() => {
                        this.refreshToken();
                    }, 1000 * 30);

                    return;
                }

                this.log.error(url);
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
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
    sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
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

    async onStateChange(id, state) {
        if (state) {
            if (!state.ack) {
                const vehicleid = id.split(".")[2];

                let command = id.split(".")[4];
                const action = command.split("-")[1];
                command = command.split("-")[0];
                this.sendCommand(vehicleid, command, action, state.val);
                this.refreshTimeout = setTimeout(async () => {
                    await this.updateDevices();
                }, 10 * 1000);
            } else {
                const resultDict = { driver_temp_setting: "set_temps-driver_temp", passenger_temp_setting: "set_temps-passenger_temp" };
                const idArray = id.split(".");
                const stateName = idArray[idArray.length - 1];
                const vin = id.split(".")[2];
                let value = true;
                if (resultDict[stateName] && isNaN(state.val)) {
                    if (!state.val || state.val === "INVALID" || state.val === "NOT_CHARGING" || state.val === "ERROR" || state.val === "UNLOCKED") {
                        value = false;
                    }
                } else {
                    value = state.val;
                }
                if (resultDict[stateName]) {
                    await this.setStateAsync(vin + ".remote." + resultDict[stateName], value, true);
                }
            }
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
