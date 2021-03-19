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
