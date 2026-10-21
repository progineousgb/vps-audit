# vps-audit

```sh
curl -fsSL https://raw.githubusercontent.com/progineousgb/vps-audit/main/vps-audit.sh | sudo bash
```

One command for a fresh Linux VPS. It checks the basics that usually get forgotten after the first login, gives a score out of 100, and prints the exact command to fix each problem. It only reads. It does not change any setting.

If you prefer to read a script before running it as root (you should):

```sh
curl -fsSLO https://raw.githubusercontent.com/progineousgb/vps-audit/main/vps-audit.sh
less vps-audit.sh
sudo bash vps-audit.sh
```

## Platform

Linux only. The script targets Linux servers (Debian, Ubuntu, and similar) and needs bash and root. It does not run on macOS or Windows; from those systems, run it on the server over SSH.

## Example output

Example run on a fresh VPS before any hardening.

```
$ sudo ./vps-audit.sh

vps-audit 1.0.0  web-01 | Debian GNU/Linux 13 (trixie) | 6.12.94+

[ PASS ] SSH password login   PasswordAuthentication no
[ WARN ] SSH root login       PermitRootLogin prohibit-password (default) (key only)
         fix: echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-no-root.conf && sudo systemctl reload ssh  # use a sudo user first
[ WARN ] Open ports           listening: tcp/22(sshd) tcp/3000(node) tcp/443(nginx) tcp/80(nginx)
         fix: sudo ss -tulnp  # review each service, stop or bind to 127.0.0.1 what you do not need
[ FAIL ] Firewall             no active firewall found (checked ufw, nftables, iptables)
         fix: sudo apt install ufw && sudo ufw allow OpenSSH && sudo ufw enable
[ PASS ] Security updates     no pending security updates (based on last apt update)
[ FAIL ] Automatic updates    unattended-upgrades not installed or not enabled
         fix: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
[ FAIL ] fail2ban             not installed
         fix: sudo apt install fail2ban && sudo systemctl enable --now fail2ban
[ PASS ] Swap                 no swap, but 16002 MB RAM
[ PASS ] Disk space           / is 47% used, 69563 MB free
[ PASS ] Disk write speed     1.4 GB/s (64MB direct write)
[ PASS ] Time sync            clock synchronised (NTP)
[ PASS ] Reboot required      no reboot pending

Score: 65/100
Scored on checks that could run. Read-only: nothing was changed.

$ sudo ./vps-audit.sh --json | jq .
{
  "tool": "vps-audit",
  "version": "1.0.0",
  "host": "web-01",
  "root": true,
  "score": 65,
  "checks": [
    {
      "name": "SSH password login",
      "status": "pass",
      "weight": 15,
      "detail": "PasswordAuthentication no",
      "fix": ""
    },
    {
      "name": "SSH root login",
      "status": "warn",
      "weight": 10,
      "detail": "PermitRootLogin prohibit-password (default) (key only)",
      "fix": "echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-no-root.conf && sudo systemctl reload ssh  # use a sudo user first"
    },
    {
      "name": "Open ports",
      "status": "warn",
      "weight": 10,
      "detail": "listening: tcp/22(sshd) tcp/3000(node) tcp/443(nginx) tcp/80(nginx)",
      "fix": "sudo ss -tulnp  # review each service, stop or bind to 127.0.0.1 what you do not need"
    },
    {
      "name": "Firewall",
      "status": "fail",
      "weight": 15,
      "detail": "no active firewall found (checked ufw, nftables, iptables)",
      "fix": "sudo apt install ufw && sudo ufw allow OpenSSH && sudo ufw enable"
    },
    {
      "name": "Security updates",
      "status": "pass",
      "weight": 10,
      "detail": "no pending security updates (based on last apt update)",
      "fix": ""
    },
    {
      "name": "Automatic updates",
      "status": "fail",
      "weight": 5,
      "detail": "unattended-upgrades not installed or not enabled",
      "fix": "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
    },
    {
      "name": "fail2ban",
      "status": "fail",
      "weight": 5,
      "detail": "not installed",
      "fix": "sudo apt install fail2ban && sudo systemctl enable --now fail2ban"
    },
    {
      "name": "Swap",
...
```

## What it checks

| Check | Weight | Passes when |
|---|---|---|
| SSH password login | 15 | `PasswordAuthentication no` (uses `sshd -T` when root, else reads sshd_config and sshd_config.d) |
| SSH root login | 10 | `PermitRootLogin no`. Key-only root login is a warning |
| Open ports | 10 | Lists every port listening on a non-loopback address and the process behind it (`ss -tulnp`). More than 3 is a warning |
| Firewall | 15 | ufw active, or nftables / iptables rules that drop or reject input |
| Security updates | 10 | No pending security upgrades (`apt-get -s upgrade`, or `dnf updateinfo` on RHEL family). Based on your last `apt update` |
| Automatic updates | 5 | unattended-upgrades installed and enabled, or dnf-automatic timer enabled |
| fail2ban | 5 | Installed and running |
| Swap | 5 | Swap exists, or RAM is 4 GB or more |
| Disk space | 10 | Root filesystem under 80% used (warning to 90%) |
| Disk write speed | 5 | 100 MB/s or faster on a 64 MB direct write |
| Time sync | 5 | `timedatectl` reports NTP synchronised, or chrony is running |
| Reboot required | 5 | No `/var/run/reboot-required` (or `needs-restarting -r` on RHEL family) |

The score is points earned divided by points possible, counting only checks that could run. A warning gets half the points. Skipped checks (not root, tool missing, no systemd) do not count either way, so a run without sudo can look better or worse than the real state. Use sudo.

## Options

```
--json        JSON output, for scripts or monitoring
--no-color    plain text (NO_COLOR is honoured too, and colour is off when piped)
--disk-test   run the write test with 512 MB instead of 64 MB
-h, --help
-V, --version
```

## About the disk test

It writes 64 MB of zeros to a temp file in `$TMPDIR` or `/var/tmp` with `dd oflag=direct conv=fdatasync`, then deletes it. It is skipped if there is not enough free space. The 512 MB test only runs with `--disk-test`. It is a rough sequential write number, not a benchmark.

## Limits

- Tested on Debian 13. Written for Debian, Ubuntu and RHEL family systems. Alpine and others will see more skipped checks.
- The firewall check looks for drop or reject rules, it does not judge whether the rules are good.
- Cloud provider firewalls (security groups) are outside the server and are not seen.
- Security update detection on apt relies on the package lists being recent.

## Maintained by

Maintained by Pro Gineous, a domains, hosting and VPS provider: https://progineous.com

Issues and pull requests are welcome.

## License

MIT, see [LICENSE](LICENSE).
