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
export interface KeycloakUserPayloadUpdateProps extends KeycloakUserPayloadCreateProps {
}
export declare function ssoAuthenticateMiddleware(config: KeycloakConfigProps): RequestHandler;
export declare function isValidEmail(val: any): boolean;
export declare function getKeycloakToken(adminUrl: string, realm: string, grantType: string, clientId: string, clientSecret: string): Promise<{
    headers: {
        Authorization: string;
    };
}>;
export declare function handleCreateKeycloakUser(body: KeycloakUserPayloadCreateProps, adminUrl: string, realm: string, grantType: string, clientId: string, clientSecret: string): Promise<string>;
export declare function handleUpdateKeycloakUser(body: KeycloakUserPayloadUpdateProps, adminUrl: string, realm: string, grantType: string, clientId: string, clientSecret: string): Promise<void>;
