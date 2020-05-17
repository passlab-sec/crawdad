# Crawdad
Password security auditing tool for login over HTTP GET or HTTP Basic Authentication. Use responsibly please.

![Logo](docs/logo.svg)

## Overview
This is a very basic utility for brute-forcing web applications that authenticate via username/password parameters passed as HTTP GET parameters or via HTTP basic authentication. This utility was originally written to audit networked devices for cross-protocol vulnerability to the password guessing attack used by the Mirai botnet worm to propagate.

## Building
It's a Python script, so nothing special is needed. Just one of these:

```bash
python3 crawdad.py
```

## Usage
Because this tool is designed to work with any web application that uses HTTP GET parameters/HTTP basic authentication then each attack under `/attacks` must be designed with a specific device/application in mind. The two devices I was working with (and have included auditing CSVs for) were:

* The SMC Barricade &reg; wireless broadband router: `/attacks/smc_barricade/mirai.csv`
* The ACTi &reg; D32 IP Security Camera: `/attacks/acti_d32/mirai.csv`

Briefly, use the program like this to audit an ACTi D32 security camera at IP address `192.168.2.100` for vulnerability to the Mirai attack dictionary:

```
python3 crawdad.py -u http://192.168.2.100/cgi-bin/system -p attacks/acti_d32/mirai.csv -s LOGIN
```

Here's a quick animation showing Crawdad executing under the above configuration:

![Demo](demo.svg)

There really aren't that many options to get to grips with.

| Option       | Required? | Description                                                                                                                                                                              |
|--------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-u`         | Yes       | The URL to audit.                                                                                                                                                                        |
| `-p <file>`  | Yes       | The CSV file to use during the audit.                                                                                                                                                    |
| `-s`         | No        | The regex to use to match a successful response. Default to 200 OK at any response body.                                                                                                 |
| `-q`         | No        | Silences the banner.                                                                                                                                                                     |
| `-h <u>,<p>` | No        | The column names to use for HTTP basic authentication username (`<u>`) and password (`<p>`) respectively, delimited by a comma. These columns will not be passed as HTTP GET parameters. |

GET parameters are supplied in a CSV file with column headers corresponding to keys, like so:

| USER  | PWD       |
|-------|-----------|
| root  | xc3511    |
| root  | vizxv     |
| root  | admin     |
| ...   | ...       |

The above will then post HTTP GET requests to a base URL (in this example, `http://example.com` with query strings as follows:

```
http://example.com?USR=root&PWD=xc3511
http://example.com?USR=root&PWD=vizxv
http://example.com?USR=root&PWD=admin
...
```

This CSV file has some special syntax for more nuanced functionality:

| Symbol  | Meaning                                                                |
|---------|------------------------------------------------------------------------|
| `#`     | Do not pass this parameter, omitting it from the query string.         |
| `%`     | Pass this parameter as a Boolean flag (i.e. a key without a value).    |

## Disclaimer
The standard disclaimer in the MIT license, under which this project is licensed, applies. Also, please use this utility
for its intended purpose: *auditing networks for insecure devices*. Ensure you have permission, in writing, to run this
tool on any network you do not personally own and adhere to applicable laws in your jurisdiction.

## Acknowlegements
* The Mirai attack dictionary bundled with this work was extracted from the [Mirai source code repository](https://github.com/jgamblin/Mirai-Source-Code).
* This tool is named arbitrarily after a line from the _Futurama_ episode _The Deep South_ (S2E12).
