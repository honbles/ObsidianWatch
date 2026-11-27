# Instrumented sample applications

Five real applications instrumented to Tier 2 for ObsidianWatch, one per language, each following its page in
`docs/application/`. `run-all.sh` unpacks them, installs what is missing and starts each one on its own free
random port on 0.0.0.0 (never 80, 443 or any port already in use).

    cd samples/app/bundles
    sudo ./run-all.sh            # first run: installs tools, builds, starts all five, prints the URLs (10-20 min)
    ./run-all.sh traffic         # sample traffic for every app (logins, denials, bad input, errors, queries)
    ./run-all.sh status          # URLs and state
    ./run-all.sh logs eshop      # follow one app's log
    ./run-all.sh stop            # stop the apps and the databases they started

    APPS="juice-shop go-orders" ./run-all.sh    # only some of them

| App | Zip | Language | Database | Sign-in |
|---|---|---|---|---|
| `juice-shop` | OWASP Juice Shop 20.4 | Node.js 22 | SQLite (built in) | admin@juice-sh.op / admin123 |
| `fastapi` | Full Stack FastAPI Template | Python 3.14 | PostgreSQL | admin@example.com / changethis |
| `petclinic` | Spring PetClinic (Spring Boot 4.2) | Java 17+ | H2 (built in) | none |
| `eshop` | eShopOnWeb (ASP.NET Core 8) | .NET 8 | in memory (`OW_DB=sqlserver` for SQL Server in Docker) | demouser@microsoft.com / Pass@word1 |
| `go-orders` | order service on PostgreSQL | Go 1.25, otelsql | PostgreSQL | alice@example.com / orders-demo-1 (API only) |

The machine needs the ObsidianWatch agent with the app-server profile (OTLP on `127.0.0.1:4318`, or set
`OTEL_EXPORTER_OTLP_ENDPOINT`) and internet access for the first build (npm, PyPI, Maven Central, NuGet, cdnjs,
nodejs.org, go.dev, GitHub). On Debian or Ubuntu the script installs, when missing: curl, unzip, git, python3,
build-essential, Node.js 22, uv, OpenJDK 21, the .NET 8 SDK, Go and (only when Docker is not running) the
PostgreSQL server, whose default cluster it stops and disables. Apps go to `/opt/ow-sample-apps` as root,
`~/ow-sample-apps` otherwise (`DEST=` to change). PostgreSQL for `fastapi` and `go-orders` runs in Docker
(`postgres:17`) when Docker runs, otherwise as a local cluster on a random loopback port.

Each zip also works alone: unzip it, then `./run.sh` and `./run.sh traffic`. Its `OBSIDIANWATCH.md` lists every
change made for ObsidianWatch and what to look at in the console. Open the printed ports in your firewall to reach
the apps from another machine. These are test applications and Juice Shop is deliberately vulnerable: do not expose
them to the internet.
