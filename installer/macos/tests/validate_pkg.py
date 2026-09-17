"""Inspect actual PKG content in a protected temporary directory; never install."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

SOURCE=Path(__file__).resolve().parents[1]


def validate(package, credentials, architecture):
    package=Path(package).resolve()
    with tempfile.TemporaryDirectory(prefix='pkg-inspect-',dir='/private/tmp/endpointai-mac-build') as temp:
        extracted=Path(temp)/'expanded'
        subprocess.run(['/usr/sbin/pkgutil','--expand-full',str(package),str(extracted)],check=True,capture_output=True)
        info=ET.parse(extracted/'PackageInfo').getroot()
        assert info.attrib['identifier']=='com.sf.endpointai.proxy'
        assert info.attrib['version']=='0.1.22' and info.attrib['auth']=='root'
        assert info.attrib['install-location']=='/' and info.attrib['postinstall-action']=='none'
        scripts=extracted/'Scripts'
        for name in ['preinstall','postinstall','InstallerSupport.sh']:
            assert (scripts/name).read_bytes()==(SOURCE/name).read_bytes()
        assert (scripts/'client-credentials.json').read_bytes()==Path(credentials).read_bytes()
        assert (scripts/'client-credentials.json').stat().st_mode & 0o777 == 0o600
        assert set(json.loads((scripts/'client-credentials.json').read_text()))=={'origin','keyId','transportKey','clientToken','policyHmacKey'}
        assert (scripts/'package-arch').read_text().strip()==architecture
        assert (scripts/'package-version').read_text().strip()=='0.1.22'
        assert not any(p.name.startswith('._') for p in extracted.rglob('*'))
        payload=extracted/'Payload'
        app=payload/'Library/Application Support/SF/EndpointAIProxy/bin'
        file_info=subprocess.check_output(['/usr/bin/file','-b',str(app/'Sf.EndpointAI.Client.Service')],text=True)
        assert 'Mach-O' in file_info and architecture in file_info
        for name in ['Sf.EndpointAI.Client.Service.dll','Sf.EndpointAI.Client.Core.dll','Sf.EndpointAI.Contracts.dll',
                     'libhostfxr.dylib','libhostpolicy.dylib','libcoreclr.dylib','run-service.sh']:
            assert (app/name).is_file()
        share=payload/'usr/local/share/sf-endpointai-proxy'
        assert (share/'InstallerSupport.sh').read_bytes()==(SOURCE/'InstallerSupport.sh').read_bytes()
        for tool, source in [('sf-endpointai-installer-logs','Collect-MacInstallerLogs.sh'),
                             ('sf-endpointai-installer-recover','Recover-MacInstallation.sh')]:
            path=payload/'usr/local/sbin'/tool
            assert path.read_bytes()==(SOURCE/source).read_bytes()
            assert path.stat().st_mode & 0o111
        assert not any('client-credentials' in p.name for p in payload.rglob('*'))
        bom=subprocess.check_output(['/usr/bin/lsbom','-f',str(extracted/'Bom')],text=True)
        # Root/wheel ownership is recorded in the BOM, not the inspection UID.
        for line in bom.splitlines():
            fields=line.split('\t')
            assert len(fields)>2 and fields[2]=='0/0'
    print(f'PASS: actual {architecture} PKG version/architecture, final scripts, self-contained runtime, root BOM, tool modes, original private credentials, no AppleDouble.')


if __name__=='__main__':
    validate(*sys.argv[1:])
