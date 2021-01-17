---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

**Please delete the following content when submitting.**

I don't really like to write things in a set format, so you don't need to follow the format for this report. But please read the following, as it will help fix the bugs.

## Key Info

It is strongly recommended that you provide the following information.

* How to trigger this bug?
* The version or branch of `ngx_waf`.
* Output of `nginx -V`.
* Debug log ([How to get the debug log?](how-to-get-the-debug-log)).
* Output of `shell` (if any).

## Optional Info

In most cases you should not provide this information, but the program maintainer will ask you for it if necessary.

* The name and version of the OS.
* Whether `nginx` is running in a virtual environment such as `Docker`. If it is running in `Docker`, please provide the image name.

## How to get the debug log

This module will output debug logs under certain conditions to facilitate bug location.You can get the debug log by following the steps below.

1. Set the error log level to `debug` in the configuration file for `nginx`, e.g. `error_log logs/error.log debug;`
2. Shut down `nginx`, then clear `error.log` (back it up if necessary), and finally start `nginx`.
3. Triggers the bug you want to report.
4. Upload `error.log` and remember to clear the privacy information from the file.
