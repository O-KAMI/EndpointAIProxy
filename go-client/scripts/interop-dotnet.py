#!/usr/bin/env python3
"""Run real old C# <-> Go state interoperability using isolated synthetic data.

DOTNET selects an installed .NET 10 SDK host. DOTNET_REFERENCE_DIR selects a
previous client publish directory containing SQLite assemblies/native library.
No network restore, production state, installed services, or user profiles are used.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from xml.sax.saxutils import escape

CLIENT = Path(__file__).resolve().parents[1]
SOURCE = CLIENT.parent
dotnet = os.environ.get("DOTNET") or shutil.which("dotnet")
if not dotnet:
    raise SystemExit("Set DOTNET to an existing .NET 10 SDK host.")
references = Path(os.environ.get("DOTNET_REFERENCE_DIR", str(Path(dotnet).resolve().parent.parent / "publish")))
assemblies = ["Microsoft.Data.Sqlite.dll", "SQLitePCLRaw.core.dll", "SQLitePCLRaw.provider.e_sqlite3.dll", "SQLitePCLRaw.batteries_v2.dll"]
for filename in assemblies:
    if not (references / filename).is_file():
        raise SystemExit("Set DOTNET_REFERENCE_DIR to the existing client publish directory; missing " + filename)

def run(command, cwd, env):
    result = subprocess.run([str(x) for x in command], cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit("Interoperability subprocess failed:\n" + result.stdout)

with tempfile.TemporaryDirectory(prefix="endpointai-interop-") as temporary:
    root = Path(temporary)
    env = os.environ.copy()
    env.update(DOTNET_CLI_HOME=str(root / "dotnet-home"), DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1", DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1", NUGET_PACKAGES=str(root / "nuget"))
    files = list((SOURCE / "src/Sf.EndpointAI.Contracts").glob("*.cs"))
    core = SOURCE / "src/Sf.EndpointAI.Client.Core"
    files += [core / item for item in ["Routing/RouteRecord.cs", "Routing/IRouteRegistry.cs", "Security/ITextProtector.cs", "Security/FileKeyTextProtector.cs", "State/SqliteRouteRegistry.cs", "State/SqliteClientStateStore.cs"]]
    files += [CLIENT / "tools/interop-dotnet/Program.cs"]
    includes = "\n".join('<Compile Include="' + escape(str(path), {'"': '&quot;'}) + '" />' for path in files)
    refs = "\n".join('<Reference Include="' + filename[:-4] + '"><HintPath>' + escape(str(references / filename)) + '</HintPath></Reference>' for filename in assemblies)
    (root / "Interop.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup>' + includes + refs + '</ItemGroup></Project>')
    (root / "NuGet.Config").write_text('<configuration><packageSources><clear /></packageSources></configuration>')
    output = root / "out"
    run([dotnet, "build", root / "Interop.csproj", "--configfile", root / "NuGet.Config", "-o", output, "--nologo"], root, env)
    for pattern in ["libe_sqlite3*", "e_sqlite3.dll"]:
        for path in references.glob(pattern):
            shutil.copy2(path, output / path.name)
    bridge = root / ("interop-check.exe" if os.name == "nt" else "interop-check")
    run(["go", "build", "-o", bridge, "./cmd/interop-check"], CLIENT, env)
    run([dotnet, output / "Interop.dll", "write", root], root, env)
    run([bridge, "verify-dotnet", root], root, env)
    run([bridge, "write-go", root], root, env)
    run([dotnet, output / "Interop.dll", "check", root], root, env)
    print(json.dumps({"status": "passed", "directions": ["dotnet-to-go", "go-to-dotnet"], "checks": ["AES blob", "SQLite identity", "routes", "credentials", "cached policy", "operation state", "command receipts"], "data": "isolated synthetic fixtures"}))
