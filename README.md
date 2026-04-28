# Caddy Crowdsec Docker Swarm - Security/Observability

- Exec Crowdsec Setup

```sh
chmod +x config/crowdsec-setup.sh
```

- Pull Images

```sh
docker compose -f docker-swarm.yml pull
```

```sh
docker compose -f docker-compose.yml pull
```

- Docker Compose Up Firewall Crowdsec

```sh
docker compose -f docker-compose.yml up -d
```

- Basic Auth Hash - Caddyfile

```sh
docker run --rm -it caddy caddy hash-password minhaSenhaSecreta
```

- Init Swarm

```sh
docker swarm init
```

- Stack Deploy Swarm

```sh
docker stack deploy -c docker-swarm.yml app
```

- Crowdsec Keys - Caddy Bouncer & Firewall Bouncer

```sh
docker exec -it crowdsec_container sh
```

```sh
cscli bouncers add caddy-bouncer
```

```sh
cscli bouncers add firewall-bouncer
```

- Service Remove Swarm

```sh
docker service rm app_service
```

- Service Update Swarm

```sh
docker service update app_service --force
```

- Service List

```sh
docker service ls
```

- Stack Remove Swarm

```sh
docker stack rm app
```

- Stats

```sh
docker stats
```

- Ports

1. Caddy (Host) `80:443`
2. Heimdall `80`
3. Crowdsec (Host) `8080`
4. CAdvisor `8080`
5. Quarkus `8081`
6. Grafana `3000`
7. Uptime Kuma `3001`
8. Loki `3100`
9. MySQL `3306`
10. Portainer `9000`
11. Prometheus `9090`

##

This project uses Quarkus, the Supersonic Subatomic Java Framework.

If you want to learn more about Quarkus, please visit its website: https://quarkus.io/ .

## Running the application in dev mode

You can run your application in dev mode that enables live coding using:
```shell script
./mvnw compile quarkus:dev
```

> **_NOTE:_**  Quarkus now ships with a Dev UI, which is available in dev mode only at http://localhost:8080/q/dev/.

## Packaging and running the application

The application can be packaged using:
```shell script
./mvnw package
```
It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory.
Be aware that it’s not an _über-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

The application is now runnable using `java -jar target/quarkus-app/quarkus-run.jar`.

If you want to build an _über-jar_, execute the following command:
```shell script
./mvnw package -Dquarkus.package.type=uber-jar
```

The application, packaged as an _über-jar_, is now runnable using `java -jar target/*-runner.jar`.

## Creating a native executable

You can create a native executable using:
```shell script
./mvnw package -Pnative
```

Or, if you don't have GraalVM installed, you can run the native executable build in a container using:
```shell script
./mvnw package -Pnative -Dquarkus.native.container-build=true
```

You can then execute your native executable with: `./target/bitcoin-1.0.0-SNAPSHOT-runner`

If you want to learn more about building native executables, please consult https://quarkus.io/guides/maven-tooling.

## Related Guides

- REST Client Classic ([guide](https://quarkus.io/guides/rest-client)): Call REST services
- RESTEasy Classic JSON-B ([guide](https://quarkus.io/guides/rest-json)): JSON-B serialization support for RESTEasy Classic
- RESTEasy Classic ([guide](https://quarkus.io/guides/resteasy)): REST endpoint framework implementing Jakarta REST and more

## Provided Code

### REST Client

Invoke different services through REST with JSON

[Related guide section...](https://quarkus.io/guides/rest-client)

### RESTEasy JAX-RS

Easily start your RESTful Web Services

[Related guide section...](https://quarkus.io/guides/getting-started#the-jax-rs-resources)
