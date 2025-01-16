<p align="center">
  <a title="Project Logo">
    <img height="150" style="margin-top:15px" src="https://raw.githubusercontent.com/Advanced-Systems/assets/master/logos/svg/min/adv-logo.svg">
  </a>
</p>

<h1 align="center">Advanced Systems Security</h1>

[![Unit Tests](https://github.com/Advanced-Systems/security/actions/workflows/dotnet-tests.yml/badge.svg)](https://github.com/Advanced-Systems/security/actions/workflows/dotnet-tests.yml)
[![CodeQL](https://github.com/Advanced-Systems/security/actions/workflows/codeql.yml/badge.svg)](https://github.com/Advanced-Systems/security/actions/workflows/codeql.yml)
[![Docs](https://github.com/Advanced-Systems/security/actions/workflows/docs.yml/badge.svg)](https://github.com/Advanced-Systems/security/actions/workflows/docs.yml)

## About

The `AdvancedSystems.Security` library provides classes and services for symmetric and
asymmetric standard cryptographic algorithms based on the .NET cryptography system.

```powershell
dotnet add package AdvancedSystems.Security
```

The changelog for this package are available [here](https://advanced-systems.github.io/security/docs/changelog.html).

Package consumers can also use the symbols published to nuget.org symbol server by adding <https://symbols.nuget.org/download/symbols>
to their symbol sources in Visual Studio, which allows stepping into package code in the Visual Studio debugger. See
[Specify symbol (.pdb) and source files in the Visual Studio debugger](https://learn.microsoft.com/en-us/visualstudio/debugger/specify-symbol-dot-pdb-and-source-files-in-the-visual-studio-debugger)
for details on that process.

Additionally, this project also supports [source link technology](https://learn.microsoft.com/en-us/dotnet/standard/library-guidance/sourcelink)
for debugging .NET assemblies.

## Development Environment

Configure local user secrets for the test suite (optional):

```powershell
$Password = Read-Host -Prompt "AdvancedSystems-CA.pfx Password"
dotnet user-secrets set CertificatePassword $Password --project ./AdvancedSystems.Tests
```

Run test suite:

```powershell
dotnet test .\AdvancedSystems.Core.Tests\ --no-logo
```

In addition to unit testing, this project also uses stryker for mutation testing, which is setup to be installed with

```powershell
dotnet tool restore --configfile nuget.config
```

Run stryker locally:

```powershell
dotnet stryker
```

Build and serve documentation locally (`http://localhost:8080`):

```powershell
docfx .\docs\docfx.json --serve
```
