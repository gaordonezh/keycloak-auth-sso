"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ssoAuthenticateMiddleware = ssoAuthenticateMiddleware;
exports.isValidEmail = isValidEmail;
exports.getKeycloakToken = getKeycloakToken;
exports.handleCreateKeycloakUser = handleCreateKeycloakUser;
exports.handleUpdateKeycloakUser = handleUpdateKeycloakUser;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
const axios_1 = __importDefault(require("axios"));
function ssoAuthenticateMiddleware(config) {
    const client = (0, jwks_rsa_1.default)({ jwksUri: config.jwksUri, cache: true, rateLimit: true });
    const getKey = (header, callback) => {
        if (!header.kid) {
            return callback(new Error("No KID in token header"));
        }
        client.getSigningKey(header.kid, (err, key) => {
            if (err) {
                return callback(err);
            }
            const signingKey = key === null || key === void 0 ? void 0 : key.getPublicKey();
            callback(null, signingKey);
        });
    };
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: "TOKEN_WAS_NOT_PROVIDED" });
        }
        const [scheme, token] = authHeader.split(" ");
        if (scheme !== "Bearer" || !token) {
            return res.status(401).json({ error: "INVALID_AUTH_HEADER" });
        }
        jsonwebtoken_1.default.verify(token, getKey, {
            issuer: config.issuer,
            audience: config.clientId,
            algorithms: ["RS256"],
        }, (err, decoded) => {
            if (err) {
                return res.status(401).json({ error: "INVALID_TOKEN" });
            }
            const currentClientAccess = config.accessConfig.map((item) => item.clientId).includes(decoded === null || decoded === void 0 ? void 0 : decoded.azp);
            if (!currentClientAccess) {
                return res.status(403).json({ error: "FORBIDDEN" });
            }
            const resourcePermission = config.accessConfig.some((record) => {
                var _a, _b;
                return (_b = (_a = decoded.resource_access[record.clientId]) === null || _a === void 0 ? void 0 : _a.roles) === null || _b === void 0 ? void 0 : _b.includes(record.access);
            });
            if (!resourcePermission) {
                return res.status(403).json({ error: "FORBIDDEN_" });
            }
            req.ssouser = decoded;
            next();
        });
    };
}
function isValidEmail(val) {
    if (typeof val !== "string") {
        return false;
    }
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(val);
}
async function getKeycloakToken(parameters) {
    const params = new URLSearchParams();
    params.append("grant_type", parameters.grantType);
    params.append("client_id", parameters.clientId);
    params.append("client_secret", parameters.clientSecret);
    const { data: resToken } = await axios_1.default.post(`${parameters.adminUrl}/realms/${parameters.realm}/protocol/openid-connect/token`, params, { headers: { "Content-Type": "application/x-www-form-urlencoded" } });
    return { headers: { Authorization: `Bearer ${resToken.access_token}` } };
}
const getKeycloakUsers = async (adminUrl, realm, headersConfig, params) => {
    const res = await axios_1.default.get(`${adminUrl}/admin/realms/${realm}/users`, {
        ...headersConfig,
        params,
    });
    // first: 0, max: 10000
    return res.data;
};
const validateUserPayload = (record) => {
    const arr = [record.username, record.name, record.lastName, isValidEmail(record.email)];
    const isValid = arr.every(Boolean);
    if (!isValid) {
        throw new Error("Some field is incorrect");
    }
};
async function handleCreateKeycloakUser(body, tokenConfig) {
    var _a;
    validateUserPayload(body);
    const keycloakConfig = await getKeycloakToken(tokenConfig);
    const finUsername = await getKeycloakUsers(tokenConfig.adminUrl, tokenConfig.realm, keycloakConfig, {
        username: body.username,
    });
    if (finUsername.length) {
        throw new Error(`username:${body.username} ya se encuentra registrado`);
    }
    const userByEmail = await getKeycloakUsers(tokenConfig.adminUrl, tokenConfig.realm, keycloakConfig, {
        email: body.email,
    });
    if (userByEmail.length) {
        throw new Error(`email:${body.email} ya se encuentra registrado`);
    }
    const obj = {
        requiredActions: ["UPDATE_PASSWORD"],
        emailVerified: true,
        username: body.username,
        firstName: body.name || "-",
        lastName: body.lastName || "-",
        email: isValidEmail(body.email) ? body.email.trim() : `${body.email || "temp"}_mail@mail.com`,
        groups: [],
        attributes: {},
        enabled: false,
        credentials: [
            {
                temporary: true,
                type: "password",
                value: (_a = body.password) !== null && _a !== void 0 ? _a : body.username,
            },
        ],
    };
    console.log("kc create:", obj);
    await axios_1.default.post(`${tokenConfig.adminUrl}/admin/realms/${tokenConfig.realm}/users/`, obj, keycloakConfig);
    const userByUsername = await getKeycloakUsers(tokenConfig.adminUrl, tokenConfig.realm, keycloakConfig, {
        username: body.username,
    });
    if (!userByUsername.length) {
        throw new Error(`No se encontró el username:${body.username} creado en keycloak.`);
    }
    const ssoid = userByUsername[0].id;
    if (!ssoid) {
        throw new Error("No se encontró el id creado");
    }
    return ssoid;
}
async function handleUpdateKeycloakUser(body, tokenConfig) {
    var _a;
    validateUserPayload(body);
    const keycloakConfig = await getKeycloakToken(tokenConfig);
    const userByUsername = await getKeycloakUsers(tokenConfig.adminUrl, tokenConfig.realm, keycloakConfig, {
        username: body.username,
    });
    if (!userByUsername.length) {
        throw new Error(`No se encontró el username:${body.username} en keycloak.`);
    }
    const ssoid = (_a = userByUsername[0]) === null || _a === void 0 ? void 0 : _a.id;
    if (!ssoid) {
        throw new Error(`No se encontró el id del usuario`);
    }
    const obj = {
        id: ssoid,
        firstName: body.name,
        lastName: body.lastName,
        email: body.email,
        enabled: body.isActive,
    };
    console.log("kc update:", obj);
    await axios_1.default.put(`${tokenConfig.adminUrl}/admin/realms/${tokenConfig.realm}/users/${obj.id}`, obj, keycloakConfig);
}
