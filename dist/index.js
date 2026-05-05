"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleUpdateKeycloakUser = exports.handleCreateKeycloakUser = exports.getKeycloakUsers = exports.getKeycloakToken = exports.isValidEmail = void 0;
exports.ssoAuthenticateMiddleware = ssoAuthenticateMiddleware;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
const axios_1 = __importDefault(require("axios"));
function ssoAuthenticateMiddleware(config) {
    const client = (0, jwks_rsa_1.default)({
        jwksUri: config.jwksUri,
        cache: true,
        rateLimit: true,
    });
    const getKey = (header, callback) => {
        if (!header.kid) {
            return callback(new Error("No KID in token header"));
        }
        client.getSigningKey(header.kid, (err, key) => {
            if (err)
                return callback(err);
            const signingKey = key === null || key === void 0 ? void 0 : key.getPublicKey();
            callback(null, signingKey);
        });
    };
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: "TOKEN WASN'T PROVIDED" });
        }
        const [scheme, token] = authHeader.split(" ");
        if (scheme !== "Bearer" || !token) {
            return res.status(401).json({ error: "INVALID AUTH HEADER" });
        }
        jsonwebtoken_1.default.verify(token, getKey, {
            issuer: config.issuer,
            audience: config.clientId,
            algorithms: ["RS256"],
        }, (err, decoded) => {
            var _a, _b, _c;
            if (err) {
                return res.status(401).json({ error: "INVALID TOKEN" });
            }
            if ((decoded === null || decoded === void 0 ? void 0 : decoded.azp) !== config.frontendClientId) {
                return res.status(403).json({ error: "FORBIDDEN" });
            }
            const hasPermission = (_c = (_b = (_a = decoded.resource_access) === null || _a === void 0 ? void 0 : _a[config.frontendClientId]) === null || _b === void 0 ? void 0 : _b.roles) === null || _c === void 0 ? void 0 : _c.includes(config.frontendAccessName);
            if (!hasPermission) {
                return res.status(403).json({ error: "FORBIDDEN." });
            }
            req.ssouser = decoded;
            next();
        });
    };
}
const isValidEmail = (val) => {
    if (typeof val !== "string")
        return false;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(val);
};
exports.isValidEmail = isValidEmail;
const getKeycloakToken = async (adminUrl, realm, grantType, clientId, clientSecret) => {
    const params = new URLSearchParams();
    params.append("grant_type", grantType);
    params.append("client_id", clientId);
    params.append("client_secret", clientSecret);
    const { data: resToken } = await axios_1.default.post(`${adminUrl}/realms/${realm}/protocol/openid-connect/token`, params, {
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
    });
    return {
        headers: {
            Authorization: `Bearer ${resToken.access_token}`,
        },
    };
};
exports.getKeycloakToken = getKeycloakToken;
const getKeycloakUsers = async (adminUrl, realm, config, params) => {
    const res = await axios_1.default.get(`${adminUrl}/admin/realms/${realm}/users`, {
        ...config,
        params,
    });
    // first: 0, max: 10000
    return res.data;
};
exports.getKeycloakUsers = getKeycloakUsers;
const validateUserPayload = (record, isCreate) => {
    const arr = [record.name, record.lastName, (0, exports.isValidEmail)(record.email)];
    if (isCreate)
        arr.push(record.username);
    else
        arr.push(record.id);
    const isValid = arr.every(Boolean);
    if (!isValid)
        throw new Error("SOME FIELD IS WRONG");
};
const handleCreateKeycloakUser = async (adminUrl, realm, body, config) => {
    validateUserPayload(body, true);
    const obj = {
        requiredActions: ["UPDATE_PASSWORD"],
        emailVerified: true,
        username: body.username,
        firstName: body.name || "-",
        lastName: body.lastName || "-",
        email: (0, exports.isValidEmail)(body.email)
            ? body.email.trim()
            : `${body.email || "temp"}_mail@mail.com`,
        groups: [],
        attributes: {},
        enabled: false,
        credentials: [
            {
                temporary: true,
                type: "password",
                value: body.username,
            },
        ],
    };
    console.log("create:", obj);
    await axios_1.default.post(`${adminUrl}/admin/realms/${realm}/users/`, obj, config);
};
exports.handleCreateKeycloakUser = handleCreateKeycloakUser;
const handleUpdateKeycloakUser = async (adminUrl, realm, body, config) => {
    validateUserPayload(body, false);
    const obj = {
        id: body.id,
        firstName: body.name,
        lastName: body.lastName,
        email: body.email,
        enabled: body.isActive,
    };
    console.log("update:", obj);
    await axios_1.default.put(`${adminUrl}/admin/realms/${realm}/users/${body.id}`, obj, config);
};
exports.handleUpdateKeycloakUser = handleUpdateKeycloakUser;
