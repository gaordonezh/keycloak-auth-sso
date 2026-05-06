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

export interface KeycloakTokenParamsProps {
  adminUrl: string;
  realm: string;
  grantType: string;
  clientId: string;
  clientSecret: string;
}

export interface KeycloakFrontendAccessConfigProps {
  clientId: string;
  access: string;
}

export interface KeycloakConfigProps {
  jwksUri: string;
  issuer: string;
  clientId: string;
  accessConfig: Array<KeycloakFrontendAccessConfigProps>;
}

export interface KeycloakUserPayloadCreateProps {
  username: string;
  name: string;
  lastName: string;
  email: string;
  password?: string;
  isActive?: boolean;
}

export interface KeycloakUserPayloadUpdateProps extends Omit<KeycloakUserPayloadCreateProps, "password"> {}

export function ssoAuthenticateMiddleware(config: KeycloakConfigProps): RequestHandler {
  const client = jwksClient({ jwksUri: config.jwksUri, cache: true, rateLimit: true });

  const getKey = (header: JwtHeader, callback: any) => {
    if (!header.kid) {
      return callback(new Error("No KID in token header"));
    }

    client.getSigningKey(header.kid, (err, key) => {
      if (err) {
        return callback(err);
      }
      const signingKey = key?.getPublicKey();
      callback(null, signingKey);
    });
  };

  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: "TOKEN_WAS_NOT_PROVIDED" });
    }

    const [scheme, token] = authHeader.split(" ");
    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "INVALID_AUTH_HEADER" });
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
          return res.status(401).json({ error: "INVALID_TOKEN" });
        }

        const frontOriginClientId = decoded.azp;

        const record = config.accessConfig.find((r) => r.clientId === frontOriginClientId);
        if (!record) {
          return res.status(403).json({ error: "FORBIDDEN" });
        }

        const roles = decoded.resource_access[frontOriginClientId]?.roles ?? [];
        if (!roles.includes(record.access)) {
          return res.status(403).json({ error: "FORBIDDEN_" });
        }

        req.ssouser = decoded;
        next();
      },
    );
  };
}

export function isValidEmail(val: any) {
  if (typeof val !== "string") return false;

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(val);
}

export async function getKeycloakToken(parameters: KeycloakTokenParamsProps) {
  const params = new URLSearchParams();
  params.append("grant_type", parameters.grantType);
  params.append("client_id", parameters.clientId);
  params.append("client_secret", parameters.clientSecret);

  const { data: resToken } = await axios.post(
    `${parameters.adminUrl}/realms/${parameters.realm}/protocol/openid-connect/token`,
    params,
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } },
  );

  return { headers: { Authorization: `Bearer ${resToken.access_token}` } };
}

const getKeycloakUsers = async (
  adminUrl: string,
  realm: string,
  headersConfig: Record<string, any>,
  params?: Record<string, string>,
): Promise<Array<Record<string, any>>> => {
  const res = await axios.get(`${adminUrl}/admin/realms/${realm}/users`, {
    ...headersConfig,
    params,
  });
  // first: 0, max: 10000
  return res.data;
};

const validateUserPayload = (record: Record<string, any>) => {
  const arr = [record.username, record.name, record.lastName, isValidEmail(record.email)];

  const isValid = arr.every(Boolean);
  if (!isValid) {
    throw new Error("Some field is incorrect");
  }
};

export async function handleCreateKeycloakUser(
  body: KeycloakUserPayloadCreateProps,
  tokenConfig: KeycloakTokenParamsProps,
): Promise<string> {
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
        value: body.password ?? body.username,
      },
    ],
  };

  console.log("kc create:", obj);

  await axios.post(`${tokenConfig.adminUrl}/admin/realms/${tokenConfig.realm}/users/`, obj, keycloakConfig);

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

export async function handleUpdateKeycloakUser(
  body: KeycloakUserPayloadUpdateProps,
  tokenConfig: KeycloakTokenParamsProps,
) {
  validateUserPayload(body);

  const keycloakConfig = await getKeycloakToken(tokenConfig);
  const userByUsername = await getKeycloakUsers(tokenConfig.adminUrl, tokenConfig.realm, keycloakConfig, {
    username: body.username,
  });
  if (!userByUsername.length) {
    throw new Error(`No se encontró el username:${body.username} en keycloak.`);
  }

  const ssoid = userByUsername[0]?.id;
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

  await axios.put(`${tokenConfig.adminUrl}/admin/realms/${tokenConfig.realm}/users/${obj.id}`, obj, keycloakConfig);
}
