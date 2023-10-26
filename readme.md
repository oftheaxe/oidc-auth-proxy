# OIDC Authenticated Proxy with OpenResty and LUA
This repository has an example setup of OpenResty, Keycloak and Kibana/Elasticsearch to demonstrate OIDC sign-on to Kibana through the OpenResty authenticated proxy. 

It contains three folders with docker-compose files to start the services. Keycloak has a Dockerfile to customize it to run behind a proxy. OpenResty has a Dockerfile which adds the LUA Rock (library) for OIDC authentication.

This code is for demonstration purposes only, it's a bit opinionated and although functional, it is open to improvements like using proper secrets injection and further automation.

The following files might need adjustments in URI's/naming if running this somewhere else than locally:
- openresty-lua/conf.d/kibana.conf (URI/secrets)
- openresty-lua/conf.d/keycloak.conf (URI)
- elastic/kibana/kibana.yml (secrets)
- docker-compose.yml files (secrets)

With default config OpenResty is dependent on kibana and keycloak being resolvable, best to run the docker-compose files for these two first and OpenResty last.

## Host prep
- Ensure Docker and docker-compose are installed
- Currently we assume that keycloak.example.com and kibana.example.com will resolve to your host where Docker is running. Add these to the hosts file on the machine through which you will connect. Or change the URI's to something resolvable to your Docker host.

## Run Elasticsearch and Kibana
```
cd elastic
docker run -it --rm -v ./config:/usr/share/elasticsearch/config docker.elastic.co/elasticsearch/elasticsearch:8.10.2 sh -c 'bin/elasticsearch-keystore create'
docker run -it --rm -v ./config:/usr/share/elasticsearch/config docker.elastic.co/elasticsearch/elasticsearch:8.10.2 sh -c 'echo "changeme" | bin/elasticsearch-keystore add bootstrap.password -f'
KIBANA_TOKEN=$(docker run -it --rm -v ./config:/usr/share/elasticsearch/config docker.elastic.co/elasticsearch/elasticsearch:8.10.2 sh -c 'bin/elasticsearch-service-tokens create elastic/kibana kibana-token | cut -d " " -f4')
sed -i s/\<elasticsearch_serviceaccounttoken\>/${KIBANA_TOKEN}/g docker-compose.yml

docker-compose up -d
```

## Run Keycloak
```
cd keycloak
docker build . -t keycloak-22.0.0
docker-compose up -d
```

## Run OpenResty
```
cd openresty-lua
docker build . -t openresty-lua
docker-compose up -d
```

## Configure Keycloak
When all containers are up and running you should be able to access Keycloak (http://keycloak.example.com if default) and Kibana (http://kibana.example.com) (which redirects to Keycloak). Logging in to Kibana then will throw an error as we first need to configure Keycloak to have this fully working as intended.

Log in to Keycloak (http://keycloak.example.com/auth) using the admin user and admin password.

For Kibana OIDC login to work you need to create a Client in Keycloak:
- Go to Clients
- Add new Client
  - Name/Client ID: kibana
  - Client authentication: enabled
  - Root URL: http://kibana.example.com (if default)
- Go to the Credentials section of the client and copy the Client Secret, set it in the kibana.conf file
- Go to Client scopes
- Add a Token mapper of Type User Realm Role with the name "groups". Ensure Add to ID token is enabled.

The script is configured to look at the "groups" value in the ID Token, but you could change it to look at something else in the ID token as well (e.g. Roles). Using "groups" it requires a bit more complex configuration in Keycloak, but should set you up for better understanding and versatility.

Configure a user with the Realm Role to log in as admin:
- Create a Realm role named "kibana-admin"
- Create a Group with any name, assign the kibana-admin Realm Role to this group
- Create user and add the user to the group

You should now be able to log in to http://kibana.example.com with the user you created.

## Troubleshooting
Looking in the container logs will get you a long way. Of course the cause will be DNS... 

```
docker logs -f openresty-lua
```

Debugging LUA is quite difficult unfortunately. I got a long way by using statements like this:
```
ngx.log(ngx.INFO, "Print contents of string_variable", variable_name)
```