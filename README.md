# ipvuln

*Inspired by [Lazy-Hunter](https://github.com/iamunixtz/Lazy-Hunter)*

<img width="1373" height="701" alt="image-redacted_dot_app" src="https://github.com/user-attachments/assets/d31ae67c-341b-4b49-9272-88379bf6c24e" />


`ipvuln` is a command-line tool written in Go that leverages Shodan's Internetdb API to perform reconnaissance on IP addresses. It can identify open ports, associated hostnames, and known vulnerabilities (CVEs) for target IPs.

## Features

*   **IP Scanning:** Scan single IP addresses, a list of IPs from a file, or IPs piped via standard input. Automatically parses CIDR ranges.
*   **Port Discovery:** Lists open ports found on the target IP(s).
*   **Hostname Resolution:** Displays hostnames associated with the target IP(s).
*   **CVE Identification:** Fetches and displays Common Vulnerabilities and Exposures (CVEs) linked to the IP, including severity levels and summaries.
*   **Concurrency:** Process multiple IP addresses concurrently to speed up scanning.

## Installation

To install `ipvuln`, you need to have Go installed on your system.

1.  **Clone the repository (if applicable) or navigate to the `ipvuln` directory:**
    ```bash
    cd /path/to/ipvuln
    ```
2.  **Build the executable:**
    ```bash
    go build -o ipvuln
    ```
    This will create an executable named `ipvuln` in the current directory.

## Usage

### Basic Usage (Default Behavior)

By default, if no specific display flags are provided, `ipvuln` will show open ports, hostnames, and CVEs.

```bash
# Example using stdin (replace with your IP source)
echo "8.8.8.8" | ./ipvuln
```

### Flags

*   `-ip <IP_ADDRESS>`: Specify a single IP address to scan.
*   `-file <FILE_PATH>`: Provide a file containing a list of IP addresses (one per line).
*   `-cves`: Show only CVEs.
*   `-ports`: Show only open ports.
*   `-host`: Show only hostnames.
*   `-cve+ports`: Show CVEs with severity level and associated open ports.
*   `-c <NUMBER>`: Set the number of concurrent IP scans (default is 10).

### Examples

**Scan a single IP and show all default information:**

```bash
./ipvuln -ip 54.198.147.148
```

**Scan IPs from a file, showing only CVEs:**

```bash
./ipvuln -file ips.txt -cves
```

**Scan IPs piped from another tool, showing hostnames and ports, with 20 concurrent scans:**

```bash
cat ips.txt | ./ipvuln -host -ports -c 20
```

**Scan IPs from stdin, showing CVEs with ports:**

```bash
echo "54.198.147.148" | ./ipvuln -cve+ports
```

**Scan a CIDR range from stdin:**

```bash
echo "192.168.1.0/30" | ./ipvuln
```
