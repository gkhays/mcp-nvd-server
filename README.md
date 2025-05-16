# MCP NVD Server

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-1.6-CC5500.svg)](https://www.anthropic.com/news/model-context-protocol)

MCP server that retrieves CVE information from the national vulnerability database (NVD).

## Installation

### Prerequisites

Install the following.

- [uv](https://github.com/astral-sh/uv)
- [Node.js](https://nodejs.org/en)

## Building

> [!NOTE]
> This project employs `uv`.

1. Synchronize dependencies and update the lockfile.
```
uv sync
```

## Debugging

### MCP Inspector

Use [MCP Inspector](https://github.com/modelcontextprotocol/inspector).

Launch the MCP Inspector as follows:

```
npx @modelcontextprotocol/inspector uv --directory /path/to/mcp-nvd run mcp-nvd
```

![MCP Inspector](docs/mcp-inspector.png)

## Testing

This project employs [pytest](https://docs.pytest.org/en/stable/) for testing.

<details>
    <summary>pytest results</summary>

```python
============================================================= test session starts =============================================================
platform win32 -- Python 3.12.9, pytest-8.3.5, pluggy-1.5.0
rootdir: D:\Users\ghays\src\mcp-nvd-server
configfile: pyproject.toml
plugins: anyio-4.9.0
collected 4 items

src/mcp_nvd/test_nvd.py::test_fetch_cve
---------------------------------------------------------------- live log call ---------------------------------------------------------------- 
2025-05-16 15:50:32 [    INFO] Fetching CVE: CVE-2025-30065... (nvd.py:42)
2025-05-16 15:50:33 [    INFO] Response: 200 (nvd.py:48)
2025-05-16 15:50:33 [    INFO] Description: Schema parsing in the parquet-avro module of Apache Parquet 1.15.0 and previous versions allows bad 
actors to execute arbitrary code


Users are recommended to upgrade to version 1.15.1, which fixes the issue. (nvd.py:55)
2025-05-16 15:50:33 [    INFO] Using constructor method to fetch CVE data for CVE-2025-30065 (test_nvd.py:14)
2025-05-16 15:50:33 [    INFO] Description (en) value: Schema parsing in the parquet-avro module of Apache Parquet 1.15.0 and previous versions 
allows bad actors to execute arbitrary code


Users are recommended to upgrade to version 1.15.1, which fixes the issue. (test_nvd.py:31)
2025-05-16 15:50:33 [    INFO] Description (es) value: El análisis del esquema en el módulo parquet-avro de Apache Parquet 1.15.0 y versiones anteriores permite que actores maliciosos ejecuten código arbitrario. Se recomienda a los usuarios actualizar a la versión 1.15.1, que soluciona el problema. (test_nvd.py:31)
2025-05-16 15:50:33 [    INFO] Reference check: https://lists.apache.org/thread/okzqb3kn479gqzxm21gg5vqr35om9gw5 (test_nvd.py:36)
PASSED                                                                                                                                   [ 25%] 
src/mcp_nvd/test_nvd.py::test_fetch_cve_no_constructor
---------------------------------------------------------------- live log call ---------------------------------------------------------------- 
2025-05-16 15:50:33 [    INFO] Fetching CVE: CVE-2025-30065... (nvd.py:42)
2025-05-16 15:50:34 [    INFO] Response: 200 (nvd.py:48)
2025-05-16 15:50:34 [    INFO] Description: Schema parsing in the parquet-avro module of Apache Parquet 1.15.0 and previous versions allows bad 
actors to execute arbitrary code


Users are recommended to upgrade to version 1.15.1, which fixes the issue. (nvd.py:55)
2025-05-16 15:50:34 [    INFO] Using non-constructor method to fetch CVE data for CVE-2025-30065 (test_nvd.py:43)
PASSED                                                                                                                                   [ 50%] 
src/mcp_nvd/test_nvd.py::test_fetch_description
---------------------------------------------------------------- live log call ---------------------------------------------------------------- 
2025-05-16 15:50:34 [    INFO] Fetching CVE: CVE-2025-30065... (nvd.py:42)
2025-05-16 15:50:34 [    INFO] Response: 200 (nvd.py:48)
2025-05-16 15:50:34 [    INFO] Description: Schema parsing in the parquet-avro module of Apache Parquet 1.15.0 and previous versions allows bad 
actors to execute arbitrary code


Users are recommended to upgrade to version 1.15.1, which fixes the issue. (nvd.py:55)
2025-05-16 15:50:34 [    INFO] Description for language 'en': Schema parsing in the parquet-avro module of Apache Parquet 1.15.0 and previous versions allows bad actors to execute arbitrary code


Users are recommended to upgrade to version 1.15.1, which fixes the issue. (test_nvd.py:69)
PASSED                                                                                                                                   [ 75%] 
src/mcp_nvd/test_nvd.py::test_fetch_references
---------------------------------------------------------------- live log call ---------------------------------------------------------------- 
2025-05-16 15:50:34 [    INFO] Fetching CVE: CVE-2025-30065... (nvd.py:42)
2025-05-16 15:50:34 [    INFO] Response: 200 (nvd.py:48)
2025-05-16 15:50:34 [    INFO] Description: Schema parsing in the parquet-avro module of Apache Parquet 1.15.0 and previous versions allows bad 
actors to execute arbitrary code







Users are recommended to upgrade to version 1.15.1, which fixes the issue. (nvd.py:55)
2025-05-16 15:50:34 [    INFO] Reference URL: https://lists.apache.org/thread/okzqb3kn479gqzxm21gg5vqr35om9gw5 (test_nvd.py:82)


Users are recommended to upgrade to version 1.15.1, which fixes the issue. (nvd.py:55)
2025-05-16 15:50:34 [    INFO] Reference URL: https://lists.apache.org/thread/okzqb3kn479gqzxm21gg5vqr35om9gw5 (test_nvd.py:82)


Users are recommended to upgrade to version 1.15.1, which fixes the issue. (nvd.py:55)
2025-05-16 15:50:34 [    INFO] Reference URL: https://lists.apache.org/thread/okzqb3kn479gqzxm21gg5vqr35om9gw5 (test_nvd.py:82)


Users are recommended to upgrade to version 1.15.1, which fixes the issue. (nvd.py:55)
2025-05-16 15:50:34 [    INFO] Reference URL: https://lists.apache.org/thread/okzqb3kn479gqzxm21gg5vqr35om9gw5 (test_nvd.py:82)


Users are recommended to upgrade to version 1.15.1, which fixes the issue. (nvd.py:55)




Users are recommended to upgrade to version 1.15.1, which fixes the issue. (nvd.py:55)
2025-05-16 15:50:34 [    INFO] Reference URL: https://lists.apache.org/thread/okzqb3kn479gqzxm21gg5vqr35om9gw5 (test_nvd.py:82)
2025-05-16 15:50:34 [    INFO] Reference URL: http://www.openwall.com/lists/oss-security/2025/04/01/1 (test_nvd.py:82)
2025-05-16 15:50:34 [    INFO] Reference URL: https://access.redhat.com/security/cve/CVE-2025-30065 (test_nvd.py:82)
2025-05-16 15:50:34 [    INFO] Reference URL: https://github.com/apache/parquet-java/pull/3169 (test_nvd.py:82)
2025-05-16 15:50:34 [    INFO] Reference URL: https://news.ycombinator.com/item?id=43603091 (test_nvd.py:82)
2025-05-16 15:50:34 [    INFO] Reference URL: https://www.bleepingcomputer.com/news/security/max-severity-rce-flaw-discovered-in-widely-used-apache-parquet/ (test_nvd.py:82)
2025-05-16 15:50:34 [    INFO] Reference URL: https://github.com/h3st4k3r/CVE-2025-30065/blob/main/POC-CVE-2025-30065-ParquetExploitGenerator.java (test_nvd.py:82)
2025-05-16 15:50:34 [    INFO] Reference URL: https://github.com/mouadk/parquet-rce-poc-CVE-2025-30065/blob/main/src/main/java/com/evil/GenerateMaliciousParquetSSRF.java (test_nvd.py:82)
PASSED                                                                                                                                   [100%] 

============================================================== 4 passed in 2.74s ============================================================== 
```

</details>

## NVD Rate Limiting

### How to Add an API Key
- [Getting Started](https://nvd.nist.gov/developers/start-here)
- [Request an API Key](https://nvd.nist.gov/developers/request-an-api-key)
