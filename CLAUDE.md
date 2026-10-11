# CLAUDE.md

This file guides Claude (and any other AI assistant) when working in this repository.
Read it in full before doing anything in this project.

## Project goal

WebScrape is a **free and open-source** security research tool. The aim is to stay
useful to security researchers without features ever being moved behind a paywall.

The tool has two functions, and only these two:

1. **Passive service discovery (similar to Shodan).**
   Find services that are openly reachable on the internet and report:
   - the device that is present,
   - the software and/or hardware it is running,
   - the firmware or software version,
   - the open ports.
2. **CVE check.**
   Take the software/hardware and the specific firmware/software version found in
   step 1 and look up the known CVEs that apply to it.

### Hard boundary: no penetration testing

The tool must **never** perform a penetration test or exploit anything. It only
searches for open ports and reads what an exposed service openly announces
(for example a banner or a version string in a normal response).

This means the code must not:
- attempt logins, brute force, or credential checks,
- send exploit payloads or "safe check" probes for a vulnerability,
- try to confirm a CVE by triggering it,
- change, write to, or disrupt the target device in any way.

A CVE result is a **lookup** based on the identified version, not a verified
finding on the device. Reports must say so.

If any requested change would cross this boundary, stop and tell the project owner
instead of building it.

## Rules for Claude: what you must do

- **Ask before creating code.** Before writing or changing any code, describe what
  you plan to create and where it will go, and get the owner's approval first.
  Documentation the owner explicitly asks for (like this file) counts as approved.
- **Store code on `main`.** Commit code to the `main` branch on GitHub unless the
  owner explicitly asks for something different.
- **Use the right model and effort for the task.** Use a smaller, faster model or
  lower effort for simple, mechanical work (renames, small edits, lookups), and a
  larger model or higher effort for design, security-sensitive code, and review.
  Do not spend heavy effort on trivial tasks.
- **Follow professional standards for structure.** Use a conventional project
  layout for the chosen language, with code separated by responsibility (for
  example discovery, fingerprinting, CVE lookup, storage, reporting, interface)
  and placed in the folder where a maintainer would expect to find it.
- **Write human-readable code.** Clear names, small focused functions, consistent
  formatting, no clever tricks where plain code works.
- **Write secure code.** Validate all input, treat every network response as
  untrusted, never hard-code secrets or API keys, use safe defaults, keep
  dependencies minimal and maintained.
- **Ensure there are no vulnerabilities in the code.** Review every change for
  security issues (injection, unsafe parsing, unsafe deserialisation, path
  traversal, secrets in logs, etc.) before it is committed.
- **Comment every code section** so that any person, including a non-developer,
  can follow what each part does and why.
- **Scope tests tightly.** When testing, test only what was just built and anything
  it directly affects. Do not run or write unrelated tests.

## Rules for Claude: what you must not do

- **Do not invent features.** Build only what the owner has described. If you
  think something extra is needed, suggest it and wait for an answer.
- **Do not use poor coding standards**, such as putting everything in a single
  HTML file or a single script.
- **Do not stay silent about doubts.** If an instruction is unclear, or you do not
  think something will work, tell the owner and ask what to do before going on.
- **Do not create any code without asking first.**

## Open decisions

These are not decided yet. Do not assume an answer; ask the owner.

- Programming language and stack.
- Source of CVE data (for example the NVD API).
- Scope, rate limits, and legal/ethical limits for internet-wide port scanning
  (opt-out list, scan rate, identification of the scanner).
- Open-source license.

When one is decided, record the decision in this file.
