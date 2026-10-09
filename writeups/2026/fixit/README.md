# Splunk Log Parsing & Field Extraction

## Overview

This write-up documents my work on the **TryHackMe Fixit** room from the SOC Level 2 path.

The main objective of the room was to troubleshoot improperly parsed network logs in Splunk, configure event boundaries, extract useful fields with regular expressions, and then use the structured data for analysis.

Rather than focusing on individual room questions, this write-up documents the troubleshooting process from raw incorrectly parsed logs to usable structured events.

### Skills Practiced

- Splunk log ingestion troubleshooting
- Splunk configuration files
- Event boundary configuration
- Regular expressions
- Field extraction
- Regex validation with `rex`
- SPL searches and basic log analysis

---

## Investigation Summary

The network logs were being ingested into Splunk, but the events were not parsed correctly.

The investigation followed this workflow:

```text
Raw network logs
        ↓
Identify incorrect event boundaries
        ↓
Review inputs.conf
        ↓
Configure event boundaries in props.conf
        ↓
Verify correctly separated events
        ↓
Create regex-based field extraction
        ↓
Configure transforms.conf and fields.conf
        ↓
Validate extraction with rex
        ↓
Analyze structured fields with SPL
```

---

## 1. Identifying the Parsing Problem

I started by reviewing the events available in the `main` index.

```spl
index=main
```

The logs were present, but Splunk was not correctly identifying the boundaries between individual events.

Some lines containing information such as the country and timestamp were being treated as separate events instead of being associated with the corresponding `[Network-log]` entry.

![Broken event parsing](images/01-broken-event-parsing.png)

This indicated that the problem was not the absence of data, but the way Splunk was parsing the incoming log stream.

---

## 2. Reviewing the Data Input

I inspected the Fixit application's `inputs.conf` file to understand where the logs were coming from and how they were being indexed.

The monitored script was:

```text
/opt/splunk/etc/apps/fixit/bin/network-logs
```

The input configuration defined the destination index, source, and sourcetype:

```ini
[script:///opt/splunk/etc/apps/fixit/bin/network-logs]

index = main
source = networks
sourcetype = network_logs
interval = 1
```

![Splunk inputs.conf](images/02-inputs-conf.png)

The important value for the next stage was:

```text
sourcetype = network_logs
```

This allowed the parsing configuration to be applied specifically to these network events.

---

## 3. Fixing Event Boundaries

The next step was configuring `props.conf`.

Each valid event begins with:

```text
[Network-log]:
```

Therefore, this pattern could be used to tell Splunk where a new event begins.

The relevant configuration was:

```ini
[network_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\[Network-log\]:
```

![Splunk props.conf](images/03-props-conf.png)

### Why this works

`SHOULD_LINEMERGE` allows multiple physical lines to be combined into one logical event.

`BREAK_ONLY_BEFORE` then tells Splunk that a new event should begin whenever a line starts with:

```regex
^\[Network-log\]:
```

Breaking the regex down:

```text
^               start of the line
\[              literal [
Network-log     expected text
\]              literal ]
:               literal colon
```

This prevents the second line of a network log from being interpreted as an independent event.

---

## 4. Verifying Event Parsing

After configuring the event boundaries, I returned to Splunk Search and inspected the events again.

The network information and the second line containing the country and timestamp were now part of the same event.

![Fixed event parsing](images/04-fixed-event-parsing.png)

A correctly parsed event had a structure similar to:

```text
[Network-log]: User named Bob Johnson from Development department accessed
the resource Cybertees.THM/products/product2.html from the source IP
172.16.0.7 and country Germany at: Fri Oct 9 18:23:25 2026
```

At this point, Splunk could distinguish individual events correctly, but the useful information was still contained inside the raw event text.

The next objective was to convert that text into structured fields.

---

## 5. Extracting Structured Fields

The logs contained several values useful for analysis:

```text
Username
Department
Domain
URI
SourceIP
Country
```

I configured `transforms.conf` to extract these values using capture groups in a regular expression.

The extraction followed the structure of the network logs:

```text
User named <Username>
from <Department> department
accessed the resource <Domain>/<URI>
from the source IP <SourceIP>
and country <Country>
```

The transformation mapped the regex capture groups to Splunk fields:

```ini
[network_log_fields]

REGEX = User named\s(.+?)\sfrom\s(.+?)\sdepartment accessed the resource\s([^/\s]+)/(\S+)\sfrom the source IP\s(\d{1,3}(?:\.\d{1,3}){3})\sand country\s+(.+?)\sat:

FORMAT = Username::$1 Department::$2 Domain::$3 URI::$4 SourceIP::$5 Country::$6

WRITE_META = true
```

![Splunk transforms.conf](images/05-transforms-conf.png)

The important part of the configuration is the relationship between the regex capture groups and the extracted fields:

```text
$1 → Username
$2 → Department
$3 → Domain
$4 → URI
$5 → SourceIP
$6 → Country
```

This transforms information embedded inside `_raw` into fields that can be searched, filtered, counted, and correlated directly in Splunk.

---

## 6. Configuring Indexed Fields

The extracted fields were then defined in `fields.conf`.

```ini
[Username]
INDEXED = true

[Department]
INDEXED = true

[Domain]
INDEXED = true

[URI]
INDEXED = true

[SourceIP]
INDEXED = true

[Country]
INDEXED = true
```

![Splunk fields.conf](images/06-fields-conf.png)

The fields available for analysis were therefore:

```text
Username
Department
Domain
URI
SourceIP
Country
```

This converted the original unstructured network logs into much more useful data for Splunk searches.

---

## 7. Validating the Regex

One of the more difficult parts of the room was getting the regular expression and field extraction working correctly.

Instead of repeatedly changing the configuration without knowing whether the regex itself was correct, I tested the extraction directly against the events with Splunk's `rex` command.

The validation followed this approach:

```spl
index=main
| rex "User named\s(?<Username>.+?)\sfrom\s(?<Department>.+?)\sdepartment accessed the resource\s(?<Domain>[^/\s]+)/(?<URI>\S+)\sfrom the source IP\s(?<SourceIP>\d{1,3}(?:\.\d{1,3}){3})\sand country\s+(?<Country>.+?)\sat:"
| table Username Department Domain URI SourceIP Country
```

The use of named capture groups made it possible to immediately inspect the extracted values.

For example:

```regex
(?<Username>.+?)
```

creates the `Username` field, while:

```regex
(?<SourceIP>\d{1,3}(?:\.\d{1,3}){3})
```

captures the IPv4 address into `SourceIP`.

The resulting table showed that all six values could be extracted from the raw network events:

```text
Username
Department
Domain
URI
SourceIP
Country
```

![Field extraction validation](images/07-field-extraction-validation.png)

This was useful for troubleshooting because it separated two potential problems:

1. whether the **regex itself worked**
2. whether the **Splunk configuration was applying it correctly**

Testing the regex independently made it easier to identify where the extraction problem was occurring.

---

## 8. Analyzing the Structured Logs

Once the fields were available, the remaining investigation could be performed with relatively simple SPL queries.

For example, to determine which user generated the most activity:

```spl
index=main
| stats count by Username
| sort -count
```

![User activity analysis](images/08-user-activity-analysis.png)

The results showed:

```text
Robert Wilson    625
Emily Davis      128
Alice Smith      124
Karen Harris     124
Matthew Young    110
...
```

`Robert Wilson` was therefore the most active user in the dataset, with **625 events**.

This demonstrates why proper parsing and field extraction are important.

Instead of manually reading thousands of raw events, structured fields allow the analyst to aggregate the dataset immediately:

```spl
| stats count by Username
```

The same approach can be applied to other extracted fields:

```spl
| stats count by SourceIP
```

```spl
| stats count by Country
```

```spl
| stats count by URI
```

```spl
| stats count by Department
```

---

## Key Findings

During the exercise, I successfully:

- Identified incorrectly parsed multi-line events.
- Located the monitored log source in `inputs.conf`.
- Used `props.conf` to define correct event boundaries.
- Used `[Network-log]:` as the start of each network event.
- Worked with regex capture groups to extract structured information.
- Configured fields for `Username`, `Department`, `Domain`, `URI`, `SourceIP`, and `Country`.
- Validated field extraction independently using `rex`.
- Used SPL aggregation to analyze user activity.
- Identified **Robert Wilson** as the most active user with **625 events**.

---

## What I Learned

The most valuable part of this room was not the final log searches, but understanding what happens **before the data becomes useful in Splunk**.

Previously, I mostly worked with logs that had already been parsed and were ready for investigation. In this room, I had to troubleshoot how the data itself was being ingested and structured.

The exercise helped me better understand the relationship between:

```text
inputs.conf
     ↓
incoming data
     ↓
props.conf
     ↓
event parsing
     ↓
transforms.conf
     ↓
field extraction
     ↓
fields.conf
     ↓
structured searchable data
     ↓
SPL analysis
```

The regex extraction was the most challenging part. Testing the expression directly with `rex` was particularly useful because I could verify the extraction logic before relying on the configuration files.

The room also reinforced an important SIEM concept: **good analysis depends on good data parsing**. Even simple searches such as `stats count by Username` become useful only after the underlying events and fields are structured correctly.

---

## Tools & Technologies

- Splunk Enterprise
- SPL
- Regular Expressions
- Linux
- `inputs.conf`
- `props.conf`
- `transforms.conf`
- `fields.conf`

---

## Conclusion

The Fixit room provided practical experience with a part of Splunk that I had previously used much less: **log onboarding, parsing, and field extraction**.

The investigation started with incorrectly separated raw network events and ended with structured fields that could be queried and aggregated using SPL.

The main workflow was:

```text
Identify parsing issue
        ↓
Inspect input configuration
        ↓
Fix event boundaries
        ↓
Extract fields with regex
        ↓
Validate extraction
        ↓
Analyze structured logs
```

This exercise improved my understanding of how raw data becomes searchable SIEM data and gave me more practical experience troubleshooting Splunk rather than only searching already prepared logs.
