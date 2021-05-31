---
title: Version Description
lang: en
---

# Version Description

## Semantic Versioning

This project follows the [Semantic Versioning 2.0.0](https://semver.org/).

## Stable

The stable version is guaranteed to be ready to use and contains features that are more stable.
You can get the source code of the stable version of the module with the following command.

```sh
git clone -b master https://github.com/ADD-SP/ngx_waf.git
```

## Development

The development version is guaranteed to work in most cases, 
with some additional changes included relative to the stable version, 
such as new features, bug fixes and functional changes.
You can get the module source code for the development version with the following command.

```sh
git clone -b dev https://github.com/ADD-SP/ngx_waf.git
```

## Branch Description

* master: The branch where the stable version is located, and which is guaranteed to be available at all times.
* dev: The branch where the development version is located, and which is guaranteed to be available in most cases.
* feature-xxxx: The new feature development branch, which is not guaranteed to be available, 
will be merged into the `dev` when development is complete.
* bugfix-xxxx: bug-fixing branch, which is not guaranteed to be available and will generally be merged into the `dev` when the fix is complete.
* hotfix-xxxx: hotfix branch, not guaranteed availability, will be merged to `master` and `dev` when the fix is complete. 
* change-xxxx: Feature change branches, which are not guaranteed to be available, will be merged into the `dev` when development is complete.