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
export interface KeycloakUserPayloadUpdateProps extends Omit<KeycloakUserPayloadCreateProps, "username"> {
    id: string;
}
export declare function ssoAuthenticateMiddleware(config: KeycloakConfigProps): RequestHandler;
export declare const isValidEmail: (val: any) => boolean;
export declare const getKeycloakToken: (adminUrl: string, realm: string, grantType: string, clientId: string, clientSecret: string) => Promise<{
    headers: {
        Authorization: string;
    };
}>;
export declare const getKeycloakUsers: (adminUrl: string, realm: string, config: Record<string, any>, params?: Record<string, string>) => Promise<Array<Record<string, any>>>;
export declare const handleCreateKeycloakUser: (adminUrl: string, realm: string, body: KeycloakUserPayloadCreateProps, config: Record<string, any>) => Promise<void>;
export declare const handleUpdateKeycloakUser: (adminUrl: string, realm: string, body: KeycloakUserPayloadUpdateProps, config: Record<string, any>) => Promise<void>;
