import { RequestHandler } from "express";
export interface KeycloakConfig {
    jwksUri: string;
    issuer: string;
    clientId: string;
    frontendClientId: string;
    frontendAccessName: string;
}
export declare function ssoAuthenticate(config: KeycloakConfig): RequestHandler;
