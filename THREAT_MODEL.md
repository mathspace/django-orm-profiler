# django-orm-profiler threat model

## Overview

A development profiler monkey-patches Django SQL compilers at import to capture SQL text, model/database names and stack/source context, then emits JSON UDP datagrams. A separate Node CLI receives them and displays an interactive terminal GUI or console output; GUI users can save snapshots (django_orm_profiler/profiler.py:16; profiler-client.js:9; profiler_client/common/utils.js:54). This is telemetry beside the ORM, not an ORM permission layer.

Importing the profiler changes compiler methods inside the Django process. Running the Node CLI starts a separate telemetry receiver; its GUI is a terminal interface, not a web dashboard. SQL capture takes as_sql()[0], so the separate parameter tuple is not directly captured, although generated SQL may still contain literals. Neither component gains new database credentials: the principal already running Django retains that authority.

| Component | Source |
| --- | --- |
| Python compiler instrumentation | django_orm_profiler/profiler.py:16 |
| Home configuration, stack capture and UDP emitter | django_orm_profiler/core/config.py:37; django_orm_profiler/core/logger.py:48; django_orm_profiler/core/emitter.py:26 |
| Node listener, terminal and file export | profiler_client/common/receiver.js:18; profiler_client/common/utils.js:54 |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| Library embedded in Django | Python YAML loader | expanduser(~) + fixed CONFIG_FILE_NAME → open → yaml.load | Current user home + /.django-orm-profiler | Python process | Host file ownership; installed YAML loader semantics | django_orm_profiler/core/config.py:38 |
| Library embedded in Django | UDP emitter | Home YAML telemetry_host/telemetry_port → logger .get fallback arguments → UDP sendto | Configured telemetry_host/telemetry_port; absent keys incorrectly fall back to (7734,"127.0.0.1") | Configured UDP listener | Host network controls; no emitter authentication envelope | django_orm_profiler/core/logger.py:24; Documented claim: Constants identify loopback host and numeric port; Discrepancy: Fallback arguments are transposed. |
| Node CLI GUI or console | Node receiver | Home YAML safeLoad → values if loaded; load error → loopback/numeric defaults → bind | ~/.django-orm-profiler values; load failure defaults 127.0.0.1:7734 | Node terminal/store | Bind address and host networking | profiler_client/common/utils.js:308; profiler_client/common/receiver.js:67 |
| Node GUI manual snapshot | Snapshot writer | GUI p key → captured query store → Date.getTime() filename → fs.writeFile | /tmp/django-orm-profile-snapshot-&lt;epoch milliseconds&gt;.log | Filesystem users permitted by host mode/umask | OS permissions; export requires GUI p key | profiler_client/common/utils.js:69 |

## Threat Model, Trust Boundaries, and Assumptions

**Protected assets.** SQL text, source snippets, file paths, model/database identifiers and exception details, potentially sensitive depending on caller SQL (django_orm_profiler/core/logger.py:76). Host query availability, telemetry authenticity, terminal output and saved snapshot confidentiality (django_orm_profiler/profiler.py:25; profiler_client/common/receiver.js:34).

**Actors and starting authority.** A sender able to reach the configured UDP socket can supply datagrams but does not thereby possess database execution authority. A local user able to write the profiler configuration or trusted package occupies a separate configuration/code boundary; ordinary host HTTP callers only influence whatever SQL/context their application produces.

**Trust boundaries and owned controls.**

- Trusted import patches SQLCompiler, SQLInsertCompiler and SQLUpdateCompiler process-wide. Logging runs before original execute_sql; it does not change caller DB credentials or authorize queries (django_orm_profiler/profiler.py:25; django_orm_profiler/profiler.py:34).
- Python loads ~/.django-orm-profiler via yaml.load; Node loads the same filename with yaml.safeLoad. Home-directory writers therefore control trusted instrumentation configuration; loader behavior belongs partly to installed YAML versions (django_orm_profiler/core/config.py:37; profiler_client/common/utils.js:308).
- Emitter sends JSON over UDP without an application authentication envelope. Receiver parses incoming JSON and feeds store/terminal widgets; bind address and host network controls determine who can submit telemetry (django_orm_profiler/core/emitter.py:26; profiler_client/common/receiver.js:34).
- Snapshot export writes captured values to a timestamp filename in /tmp; filesystem permissions and retention are host-owned (profiler_client/common/utils.js:54).

**Security objectives.** Restrict telemetry recipients and reachable senders; preserve confidentiality of SQL and source context. Ensure instrumentation failure behavior does not violate host query availability requirements. Control configuration, terminal/log access and snapshot retention at the host boundary.

**Assumptions and unresolved controls.**

- Python constants declare host 127.0.0.1/port 7734, but logger passes them as swapped fallbacks: absent config yields host=7734 and port="127.0.0.1". Node defaults correctly to 127.0.0.1:7734. Do not describe the absent-config emitter as functioning loopback telemetry (django_orm_profiler/core/logger.py:16; django_orm_profiler/core/logger.py:24; profiler_client/common/utils.js:314).
- Logger docstring claims all exceptions are swallowed, but exception handlers themselves call emit, whose sendto is not wrapped. Transport failures can escape; actual reachability/behavior depends on configuration (django_orm_profiler/core/logger.py:43; django_orm_profiler/core/logger.py:103; django_orm_profiler/core/emitter.py:26).
- Python setuptools and Node CLI packaging exist; no CI release workflow appears in inventory, and publisher account controls are unknown (setup.py:5; profiler-client.js:1).
- Actual Python/Node configuration contents, YAML dependency versions, receiver exposure, terminal rendering behavior and snapshot permissions are unknown. No performance or runtime exploit was measured.

## Attack Surface, Mitigations, and Attacker Stories

These are prioritized hypotheses, not validated vulnerabilities. Each requires its stated caller, data and exposure prerequisites; ordinary use of authority already granted is not a new capability.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | SQL/source telemetry reaches a network listener, console reader or snapshot reader outside the intended audience. | Configured remote destination, shared terminal/log collector or permissive filesystem exposure. | Query and source-context confidentiality loss, depending on captured contents. | Loopback Node fallback, selected capture/ignore frames and host filesystem/network controls. | Restrict recipients; avoid collecting sensitive queries and govern saved snapshots. | django_orm_profiler/core/logger.py:76; profiler_client/common/utils.js:69 |
| 2 | A network sender injects false or malformed telemetry into a reachable receiver. | Attacker can reach the configured UDP bind; no application-level authentication is supplied. | Misleading measurements or interrupted diagnostic process; database execution is not gained. | Configured bind address; JSON parsing precedes storage/rendering. | Keep receiver on a trusted network and bound/validate incoming telemetry where required. | profiler_client/common/receiver.js:34; profiler_client/common/receiver.js:67 |
| 2 | A telemetry failure escapes instrumentation and interrupts a host query before its original execution. | Active profiler import and a failing transport/configuration path; actual impact depends on use in a shared service. | Host operation failure rather than merely lost telemetry. | Some logger exceptions are caught, but handlers emit again and sendto is unwrapped. | Resolve defaults and isolate telemetry failures according to the host availability contract. | django_orm_profiler/profiler.py:25; django_orm_profiler/core/logger.py:103; django_orm_profiler/core/emitter.py:26 |
| 3 | A lower-trust configuration writer changes telemetry recipients or reaches YAML loader capabilities in the Python process. | An actual permission boundary permits writing the user-home configuration while denying intended process authority; installed YAML behavior must be established. | Telemetry redirection; any greater execution impact is dependency-conditional. | Fixed user-home filename; file access controls; Node uses safeLoad. | Protect configuration and resolve Python loader semantics against the installed dependency. | django_orm_profiler/core/config.py:38; profiler_client/common/utils.js:308 |

## Severity Calibration (Critical, High, Medium, Low)

| Level | Repository-specific example | Counterexample or limiting prerequisite |
| --- | --- | --- |
| Critical | A separately demonstrated configuration/parser or release boundary grants broad privileged host execution. | No such execution path is validated here; trusted home-file editing or package maintenance is not automatically a privilege gain. |
| High | A lower-privilege recipient obtains substantial confidential telemetry, or instrumentation causes a material shared-service outage. | Requires sensitive captured data or production availability dependence, neither inferred from developer-tool purpose. |
| Medium | Reachable datagrams reliably disrupt a shared diagnostic receiver or expose limited internal query metadata. | A receiver bound to an inaccessible interface removes that network prerequisite. |
| Low | Local profiling interruption or misleading counts without sensitive disclosure or production effect. | Malformed telemetry does not confer database query authority; intentional exports to authorized users are expected. |

This model uses an independent source-backed architecture pass. Repository citations were checked against the supplied inventory and source lines; application code and external services were not executed. Source-established behavior is distinct from unverified deployment exposure. Revisit the model when the described input, storage, authorization or publication boundaries change.

Repository: github.com/mathspace/django-orm-profiler
Version: 47c40fbb2f334ddd48d53151c6d9db75e4e313b7
