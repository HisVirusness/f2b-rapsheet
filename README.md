# Fail2Ban Rapsheet

A small Bash utility that shows which IPs are currently banned by Fail2Ban and their recent web hits from your access log.
Fail2Ban does the banning; this just gives you a readable roster of your active jails.


## Features

* Lists banned IPs across selected jails.
* Shows recent requests (timestamp, method, path, status, user agent).
* Target a single IP for full detail (`-g IP`).
* Configurable jail list, log path, and line count.
* IPv4 + IPv6 aware.
* Gracefully notes SSH-only offenders (recidive with no web hits).


## Configuration

Create `~/.f2b-rapsheet.conf` (values here override script defaults):

```bash
JAILS="apache-badbots recidive" # include custom jails, if any
MAX_LINES=5
ACCESS_LOG="/var/log/apache2/access.log" # adjust as needed, e.g. /var/log/nginx/access.log
IP_REGEX='^([0-9]{1,3}[.]){3}[0-9]{1,3}$|^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+$'  # IPv4/IPv6
```

---

## Usage

```bash
# Show all banned IPs with their recent web hits
./f2b-rapsheet.sh

# Full history for one IP
./f2b-rapsheet.sh -g 192.0.2.42

# Use jails auto-discovered by Fail2Ban
./f2b-rapsheet.sh --auto-jails

# Override jail list ad hoc
./f2b-rapsheet.sh -j "apache-badbots recidive"
```

## Example Output

```
==============================
IP: 104.248.16.131
==============================
apache-badbots hits:
      [29/Aug/2025:05:13:55 -0500] GET    /.env           -> 403 | UA: Mozilla/5.0; Keydrop.io/1.0(onlyscans.com/about);
      [29/Aug/2025:05:13:55 -0500] GET    /.git/config    -> 403 | UA: Mozilla/5.0; Keydrop.io/1.0(onlyscans.com/about);

==============================
IP: 103.24.63.85
==============================
recidive hits:
      (no web hits; likely SSH-only offender)
```

## Notes / Troubleshooting

* **No web hits for `recidive`** is normal if the offender only tripped SSH.
* If you get empty output, verify:
  - `ACCESS_LOG` points to your active access log.
  - Your log format is the standard/combined style with user agents.
  - The jails in `JAILS` actually exist (`fail2ban-client status --list`).
* `MAX_LINES` controls how many recent entries per IP are shown (default is 5).
