import { Request, Response, NextFunction, RequestHandler } from "express";
import jwt, { JwtHeader } from "jsonwebtoken";
import jwksClient from "jwks-rsa";

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

export interface KeycloakConfig {
  jwksUri: string;
  issuer: string;
  clientId: string;
  frontendClientId: string;
  frontendAccessName: string;
}

export function ssoAuthenticate(config: KeycloakConfig): RequestHandler {
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
