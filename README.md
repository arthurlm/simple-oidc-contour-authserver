# OIDC auth server for project contour

A really simple OIDC auth server to use with [Project Contour](https://projectcontour.io/).

## Few more details

This project is made to add JSON Web Token (JWT) validation in K8S.

It provide:

- only the **bare minimum** features !

Is is focus on:

- speed
- stability

It **does not** provide:

- full OIDC implem

See more details on auth server at: <https://projectcontour.io/guides/external-authorization/>

## K8S example

See [wiki](https://github.com/arthurlm/simple-oidc-contour-authserver/wiki/K8S-resources-example) for details example.

## HTTP headers informations

App will add following headers on success:

- `Auth-Jwt-Sub`: JWT specific: user subject (may be empty)
- `Auth-Jwt-Aud`: JWT specific: user audience (may be empty)
- `Auth-Jwt-Iss`: JWT specific: user issuer (may be empty)
- `Auth-Email`: User email (may be empty)
- `Auth-Name`: User name (may be empty)
- `Auth-Unique-Name`: User unique name (may be empty)

Otherwise it will return 401 error status code and do not forward requests to protected backend.

## Contribute guidelines

Feel free to create PR.
Any help, improvment ideas are welcome :smile: !

To run:

    source .envrc
    cargo r bearer

To test:

    cargo t
