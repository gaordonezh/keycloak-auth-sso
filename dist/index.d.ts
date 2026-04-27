import { RequestHandler } from "express";
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
                resource_access: Record<string, {
                    roles: Array<string>;
                }>;
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
export declare function ssoAuthenticate(config: KeycloakConfig): RequestHandler;
