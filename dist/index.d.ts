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
export interface KeycloakUserPayloadUpdateProps extends Omit<KeycloakUserPayloadCreateProps, "password"> {
}
export declare function ssoAuthenticateMiddleware(config: KeycloakConfigProps): RequestHandler;
export declare function isValidEmail(val: any): boolean;
export declare function getKeycloakToken(parameters: KeycloakTokenParamsProps): Promise<{
    headers: {
        Authorization: string;
    };
}>;
export declare function handleCreateKeycloakUser(body: KeycloakUserPayloadCreateProps, tokenConfig: KeycloakTokenParamsProps): Promise<string>;
export declare function handleUpdateKeycloakUser(body: KeycloakUserPayloadUpdateProps, tokenConfig: KeycloakTokenParamsProps): Promise<void>;
