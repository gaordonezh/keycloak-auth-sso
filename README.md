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

- Middleware ssoAuthenticate con los parámetros de validación
