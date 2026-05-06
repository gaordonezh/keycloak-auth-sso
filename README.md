# TypeScript + Express

Este proyecto se usa como _Libreria de verificación de Keycloak tokens express_

## Forma de uso

Colocar el nombre y la libreria apuntando al repositorio y al tag que se quiere consumir

```js
"dependencies": {
  "keycloak-auth-sso": "github:gaordonezh/keycloak-auth-sso#v1.1.0"
},
```

Expone:

- ssoAuthenticateMiddleware: Middleware con los parámetros de validación.
- isValidEmail: Función para validar emails.
- getKeycloakToken: Obtener el token de keycloak.
- handleCreateKeycloakUser: Crear un usuario en keycloak.
- handleUpdateKeycloakUser: Actualizar un usuario en keycloak.
- types:
  - KeycloakUserPayloadCreateProps
  - KeycloakUserPayloadUpdateProps
  - KeycloakTokenParamsProps
  - KeycloakConfigProps
  - KeycloakFrontendAccessConfigProps
  - Express > Request > ssouser
