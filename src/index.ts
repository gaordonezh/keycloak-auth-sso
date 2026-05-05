import { Request, Response, NextFunction, RequestHandler } from "express";
import jwt, { JwtHeader } from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import axios from "axios";

declare global {
  namespace Express {
    interface Request {
      ssouser?: {
        iss: string;
        aud: Array<string>;
        /**
         * Keycloak user id
         */
        sub: string;
        "allowed-origins": Array<string>;
        realm_access: {
          roles: Array<string>;
        };
        resource_access: Record<string, { roles: Array<string> }>;
        email_verified: boolean;
        name: string;
        /**
         * Keycloak username
         */
        preferred_username: string;
        given_name: string;
        family_name: string;
        email: string;
      };
    }
  }
}

export interface KeycloakConfigProps {
  jwksUri: string;
  issuer: string;
  clientId: string;
  frontendClientId: string;
  frontendAccessName: string;
}

export interface KeycloakUserPayloadCreateProps {
  username: string;
  name: string;
  lastName: string;
  email: string;
  isActive?: boolean;
}

export interface KeycloakUserPayloadUpdateProps extends Omit<
  KeycloakUserPayloadCreateProps,
  "username"
> {
  id: string;
}

export function ssoAuthenticateMiddleware(
  config: KeycloakConfigProps,
): RequestHandler {
  const client = jwksClient({
    jwksUri: config.jwksUri,
    cache: true,
    rateLimit: true,
  });

  const getKey = (header: JwtHeader, callback: any) => {
    if (!header.kid) {
      return callback(new Error("No KID in token header"));
    }

    client.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      const signingKey = key?.getPublicKey();
      callback(null, signingKey);
    });
  };

  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: "TOKEN WASN'T PROVIDED" });
    }

    const [scheme, token] = authHeader.split(" ");
    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "INVALID AUTH HEADER" });
    }

    jwt.verify(
      token,
      getKey,
      {
        issuer: config.issuer,
        audience: config.clientId,
        algorithms: ["RS256"],
      },
      (err, decoded: any) => {
        if (err) {
          return res.status(401).json({ error: "INVALID TOKEN" });
        }

        if (decoded?.azp !== config.frontendClientId) {
          return res.status(403).json({ error: "FORBIDDEN" });
        }

        const hasPermission = decoded.resource_access?.[
          config.frontendClientId
        ]?.roles?.includes(config.frontendAccessName);

        if (!hasPermission) {
          return res.status(403).json({ error: "FORBIDDEN." });
        }

        req.ssouser = decoded;
        next();
      },
    );
  };
}

export const isValidEmail = (val: any) => {
  if (typeof val !== "string") return false;
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(val);
};

export const getKeycloakToken = async (
  adminUrl: string,
  realm: string,
  grantType: string,
  clientId: string,
  clientSecret: string,
) => {
  const params = new URLSearchParams();
  params.append("grant_type", grantType);
  params.append("client_id", clientId);
  params.append("client_secret", clientSecret);

  const { data: resToken } = await axios.post(
    `${adminUrl}/realms/${realm}/protocol/openid-connect/token`,
    params,
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    },
  );

  return {
    headers: {
      Authorization: `Bearer ${resToken.access_token}`,
    },
  };
};

export const getKeycloakUsers = async (
  adminUrl: string,
  realm: string,
  config: Record<string, any>,
  params?: Record<string, string>,
): Promise<Array<Record<string, any>>> => {
  const res = await axios.get(`${adminUrl}/admin/realms/${realm}/users`, {
    ...config,
    params,
  });
  // first: 0, max: 10000
  return res.data;
};

const validateUserPayload = (
  record: Record<string, any>,
  isCreate: boolean,
) => {
  const arr = [record.name, record.lastName, isValidEmail(record.email)];
  if (isCreate) arr.push(record.username);
  else arr.push(record.id);

  const isValid = arr.every(Boolean);
  if (!isValid) throw new Error("SOME FIELD IS WRONG");
};

export const handleCreateKeycloakUser = async (
  adminUrl: string,
  realm: string,
  body: KeycloakUserPayloadCreateProps,
  config: Record<string, any>,
) => {
  validateUserPayload(body, true);

  const obj = {
    requiredActions: ["UPDATE_PASSWORD"],
    emailVerified: true,
    username: body.username,
    firstName: body.name || "-",
    lastName: body.lastName || "-",
    email: isValidEmail(body.email)
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

  await axios.post(`${adminUrl}/admin/realms/${realm}/users/`, obj, config);
};

export const handleUpdateKeycloakUser = async (
  adminUrl: string,
  realm: string,
  body: KeycloakUserPayloadUpdateProps,
  config: Record<string, any>,
) => {
  validateUserPayload(body, false);

  const obj = {
    id: body.id,
    firstName: body.name,
    lastName: body.lastName,
    email: body.email,
    enabled: body.isActive,
  };

  console.log("update:", obj);

  await axios.put(
    `${adminUrl}/admin/realms/${realm}/users/${body.id}`,
    obj,
    config,
  );
};
