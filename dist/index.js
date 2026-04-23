"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ssoAuthenticate = ssoAuthenticate;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
function ssoAuthenticate(config) {
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
        const authHeader = String(req.headers.authorization);
        const [scheme, token] = authHeader.split(" ");
        if (scheme !== "Bearer" || !token) {
            return res.status(401).json({ error: "INVALID_AUTH_HEADER" });
        }
        if (!authHeader) {
            return res.status(401).json({ error: "INVALID_TOKEN." });
        }
        jsonwebtoken_1.default.verify(token, getKey, {
            issuer: config.issuer,
            audience: config.clientId,
            algorithms: ["RS256"],
        }, (err, decoded) => {
            var _a, _b, _c;
            if (err) {
                return res.status(401).json({ error: "INVALID_TOKEN" });
            }
            if ((decoded === null || decoded === void 0 ? void 0 : decoded.azp) !== config.frontendClientId) {
                return res.status(403).json({ error: "FORBIDDEN" });
            }
            const hasPermission = (_c = (_b = (_a = decoded.resource_access) === null || _a === void 0 ? void 0 : _a[config.frontendClientId]) === null || _b === void 0 ? void 0 : _b.roles) === null || _c === void 0 ? void 0 : _c.includes(config.frontendAccessName);
            if (!hasPermission) {
                return res.status(403).json({ error: "FORBIDDEN." });
            }
            req.user = decoded;
            next();
        });
    };
}
