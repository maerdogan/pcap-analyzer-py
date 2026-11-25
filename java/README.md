# pcap-analyzer (Java WAR)

Java port of pcap-analyzer, packaged as a WAR for Tomcat 10.1+ (Jakarta Servlet 6). It reads captures with tshark and shows the same pages as the Python version, in Turkish, English, German and Spanish.

Requires Java 17+, Maven 3.9+ to build, tshark 4.0+ (and `mergecap` for captures in parts) on the server.

```bash
mvn package                      # builds target/pcap-analyzer.war and target/pcap-analyzer-cli.jar
cp target/pcap-analyzer.war $CATALINA_HOME/webapps/
```

Put the settings in `$CATALINA_HOME/bin/setenv.sh`:

```bash
export JAVA_HOME=/path/to/java17
export CATALINA_OPTS="-Xms256m -Xmx1g"
export PCAP_ANALYZER_WORKDIR=/var/lib/pcap-analyzer
export PCAP_ANALYZER_ADMIN_PASSWORD='choose-one'   # required until the password is changed in the app
```

Sign in with HTTP Basic as `admin`. Open `/pcap-analyzer/`.

## Settings

| Variable | Meaning |
|---|---|
| `PCAP_ANALYZER_WORKDIR` | Where analyses are kept. Default: the Java temp folder. |
| `PCAP_ANALYZER_ADMIN_USER`, `PCAP_ANALYZER_ADMIN_PASSWORD` | The shared login. A password set under Preferences replaces the variable. |
| `PCAP_ANALYZER_TSHARK` | Path of tshark. |
| `PCAP_ANALYZER_TTL_DAYS` | Days an analysis is kept. Default 7. |
| `PCAP_ANALYZER_KEEP_CAPTURE` | `0` deletes the capture after the analysis. Packets, graphs, followed streams, services and objects then are not available. |
| `PCAP_ANALYZER_TIMEOUT_S` | Time limit of one tshark run. Default 900. |
| `PCAP_ANALYZER_GEOIP_DIR` | Folder with MaxMind GeoLite2 Country and ASN files. |
| `PCAP_ANALYZER_REQUEST_ID_HEADER` | Header that follows a request through proxies. Default `x-request-id`. |

## REST API

Create a token under Preferences, then send `Authorization: Bearer TOKEN`.

| Call | Result |
|---|---|
| `POST /api/v1/captures` | Upload with the form field `capture`; optional `keylog`, `rsa_key`, `more`, `host_a`, `host_b`, `port`, `start`, `end`, `display_filter`, `decode_as`. Returns `202` and a `job`. |
| `GET /api/v1/jobs/{job}` | `state`: `waiting`, `running`, `done`, `failed`. |
| `GET /api/v1/analyses`, `GET /api/v1/analyses/{id}` | Saved analyses. |
| `GET /api/v1/analyses/{id}/{section}` | `overview`, `urls`, `connections`, `hosts`, `issues`, `slowest`, `statistics`, `services`, `voip`, `check`. |
| `DELETE /api/v1/analyses/{id}` | Deletes an analysis. |

`/check?p95=0.5&error_rate=1&slowest=5` returns `"ok": false` with the limits that were broken, for CI.

## Command line

`mvn package` also builds `target/pcap-analyzer-cli.jar`, the same engine without Tomcat. It reads the same `PCAP_ANALYZER_*` variables and writes into the same work folder, so an analysis made here also shows up in the web pages.

```bash
export PCAP_ANALYZER_WORKDIR=/var/lib/pcap-analyzer
java -jar target/pcap-analyzer-cli.jar analyze capture.pcap --keylog keys.log   # prints the analysis ID
java -jar target/pcap-analyzer-cli.jar list
java -jar target/pcap-analyzer-cli.jar inspect ID --dst 10.0.0.5 --port 443
java -jar target/pcap-analyzer-cli.jar check ID --p95 0.5 --error-rate 1 --slowest 5   # exit code 2 when a limit is broken
java -jar target/pcap-analyzer-cli.jar set-password
```

`analyze` also takes `--rsa-key F`, `--host IP` and `--host2 IP` for a pair, `--port N`, `--display-filter EXPR` and `--decode-as RULE` (more than once). Keys are copied into the analysis folder and only those copies are removed afterwards.

## Not ported

Parts-based reading of captures near 1 GB (the Java version holds one analysis in memory, so give Tomcat enough heap), expert-information views other than the issue list, and the Python command line commands `delete`, `purge`, `report`, `connection`, `compare`, `serve` and `hash-password`, and the `--start`, `--end`, `--no-cache` and `--json` options of `analyze`.
