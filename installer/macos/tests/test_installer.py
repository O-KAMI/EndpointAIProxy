"""Execute real installation scripts in a rewritten temporary filesystem.

Privileged/service commands are mocks; never installs or attaches on this Mac.
The production scripts have no runtime test bypass or configurable root path.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

SOURCE = Path(__file__).resolve().parents[1]
MOCK = r'''
import json, os, pathlib, sys, time
root = pathlib.Path(os.environ['MOCK_ROOT'])
state_file = root/'mock-state.json'
state = json.loads(state_file.read_text())
mode = os.environ.get('MOCK_MODE', '')
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
bin_path = root/'Library/Application Support/SF/EndpointAIProxy/bin'
if command == 'chown':
    if mode == 'permission_fail' and '/private/etc/sf-endpointai-proxy.' in args[-1] and not args[-1].endswith('.conf'): sys.exit(1)
    sys.exit(0)
if command == 'sysctl':
    print('1'); sys.exit(0)
if command == 'sleep':
    time.sleep(0.02); sys.exit(0)
if command == 'ps':
    if not state.get('alive'): sys.exit(1)
    if 'lstart=' in args: print('Mon Sep 14 12:00:00 2026')
    else:
        if mode == 'process_mismatch' and state['version'] == '0.1.22': print('/opt/other/program')
        else: print(str(bin_path/'Sf.EndpointAI.Client.Service'))
    sys.exit(0)
if command == 'curl':
    if not state.get('alive'): sys.exit(7)
    if mode == 'health_fail' and state['version'] == '0.1.22': sys.exit(7)
    version = '0.1.21' if mode == 'foreign_health' else state['version']
    print(json.dumps({'status':'ok','clientVersion':version,'lastControlSyncAtUtc':None,
                     'lastControlErrorCode':'offline'})); sys.exit(0)
if command == 'launchctl':
    action = args[0]
    with (root/'mock-actions.txt').open('a') as stream: stream.write(action+'\n')
    if action == 'print':
        if not state['loaded']: sys.exit(113)
        program = '/opt/other/run.sh' if mode == 'foreign_job' else str(bin_path/'run-service.sh')
        print(f'    program = {program}\n    pid = 123456'); sys.exit(0)
    if action == 'bootout':
        if mode == 'stop_fail': sys.exit(5)
        state['loaded'] = False
        state['alive'] = mode == 'stop_timeout'
    elif action == 'bootstrap':
        version = (bin_path/'version').read_text()
        if mode == 'start_fail' and version == '0.1.22': sys.exit(5)
        state.update(loaded=True, alive=True, version=version)
    elif action not in ['enable','kickstart']: sys.exit(1)
    state_file.write_text(json.dumps(state)); sys.exit(0)
sys.exit(1)
'''


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mac-installer-test-', dir='/private/tmp/endpointai-mac-build')
        self.root = Path(self.temp.name)
        self.scripts = self.root/'scripts'
        self.scripts.mkdir()
        self.data = self.root/'Library/Application Support/SF/EndpointAIProxy'
        self.bin = self.data/'bin'
        self.config = self.root/'private/etc/sf-endpointai-proxy.conf'
        self.plist = self.root/'Library/LaunchDaemons/com.sf.endpointai.proxy.plist'
        self.share = self.root/'usr/local/share/sf-endpointai-proxy'
        self.session = self.data/'InstallerRollback/current'
        self.lock = self.root/'private/var/run/sf-endpointai-installer.lock'
        self.logs = self.data/'InstallerLogs'
        self.config.parent.mkdir(parents=True)
        self.plist.parent.mkdir(parents=True)
        self.lock.parent.mkdir(parents=True)
        (self.root/'usr/local/sbin').mkdir(parents=True)
        self.env = dict(os.environ, MOCK_ROOT=str(self.root))
        self.state(False, 'none')
        mock_root = self.root/'mocks'
        mock_root.mkdir()
        for command in ['launchctl','ps','curl','chown','sysctl','sleep']:
            mock = mock_root/command
            mock.write_text(f'#!{sys.executable}\n'+MOCK)
            mock.chmod(0o755)
        for name in ['InstallerSupport.sh','preinstall','postinstall','Collect-MacInstallerLogs.sh','Recover-MacInstallation.sh']:
            text = (SOURCE/name).read_text()
            for prefix in ['/Library/','/private/etc/','/private/var/run/','/private/var/log/','/usr/local/']:
                text = text.replace(prefix, str(self.root)+prefix)
            for command, path in [('launchctl','/bin/launchctl'),('ps','/bin/ps'),('curl','/usr/bin/curl'),
                                  ('chown','/usr/sbin/chown'),('sysctl','/usr/sbin/sysctl'),('sleep','/bin/sleep')]:
                text = text.replace(path, str(mock_root/command))
            # Only the sandbox copy bypasses root, UID and longer timeouts.
            text = text.replace('$EUID -eq 0','$EUID -ge 0')
            text = text.replace(') -eq 0', f') -eq {os.getuid()}')
            text = text.replace('SECONDS + 60','SECONDS + 3')
            (self.scripts/name).write_text(text)
        self.credentials = {'origin':'http://control.example.invalid:8080','keyId':'fixture-key',
                            'clientToken':'TEST-TOKEN-NOT-PRODUCTION',
                            'transportKey':base64.b64encode(b'x'*32).decode(),
                            'policyHmacKey':base64.b64encode(b'y'*32).decode()}
        (self.scripts/'client-credentials.json').write_text(json.dumps(self.credentials))
        (self.scripts/'package-arch').write_text('arm64')
        (self.scripts/'package-version').write_text('0.1.22')

    def tearDown(self):
        self.temp.cleanup()

    def state(self, loaded, version, alive=None):
        (self.root/'mock-state.json').write_text(json.dumps({'loaded':loaded,'alive':loaded if alive is None else alive,'version':version}))

    def old_install(self, loaded=True):
        self.bin.mkdir(parents=True)
        (self.bin/'version').write_text('0.1.21')
        (self.bin/'run-service.sh').write_text('old launcher')
        (self.bin/'Sf.EndpointAI.Client.Service').write_text('old executable')
        self.share.mkdir(parents=True)
        (self.share/'old-marker').write_text('preserve')
        self.config.write_text("SF_PROXY_DEVICE_ID='fixture-identity'\nSF_PROXY_CONTROL_TOKEN='old-token'\nUSER_SETTING='preserve'\n")
        shutil.copyfile(SOURCE/'com.sf.endpointai.proxy.plist',self.plist)
        (self.data/'state').mkdir()
        (self.data/'state/client.db').write_text('identity-state')
        self.state(loaded,'0.1.21')

    def payload(self):
        self.bin.mkdir(parents=True,exist_ok=True)
        (self.bin/'version').write_text('0.1.22')
        (self.bin/'Sf.EndpointAI.Client.Service').write_text('new executable')
        (self.bin/'run-service.sh').write_text('new launcher')
        self.share.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(self.scripts/'InstallerSupport.sh',self.share/'InstallerSupport.sh')
        shutil.copyfile(SOURCE/'com.sf.endpointai.proxy.plist',self.plist)

    def run_script(self, name, success=True, mode='', target='/'):
        env = dict(self.env, MOCK_MODE=mode)
        result = subprocess.run(['/bin/zsh',str(self.scripts/name),'fixture.pkg','/',target] if name in ['preinstall','postinstall']
                                else ['/bin/zsh',str(self.scripts/name)],env=env,capture_output=True,text=True)
        for value in [self.credentials['clientToken'],self.credentials['transportKey'],self.credentials['policyHmacKey']]:
            self.assertNotIn(value,result.stdout+result.stderr)
        self.assertEqual(result.returncode == 0,success,result.stdout+result.stderr)
        return result

    def outcomes(self):
        text='\n'.join(p.read_text() for p in self.logs.glob('*.jsonl'))
        for name in ['clientToken','transportKey','policyHmacKey']:
            self.assertNotIn(self.credentials[name],text)
        return [json.loads(line).get('outcome') for line in text.splitlines() if line]

    def assert_old(self):
        self.assertEqual((self.bin/'version').read_text(),'0.1.21')
        self.assertIn("SF_PROXY_CONTROL_TOKEN='old-token'",self.config.read_text())
        self.assertEqual((self.data/'state/client.db').read_text(),'identity-state')
        self.assertFalse(self.session.exists())
        self.assertFalse(self.lock.exists())

    def test_fresh_install_offline_is_successful(self):
        self.run_script('preinstall'); self.payload(); self.run_script('postinstall')
        self.assertIn('success',self.outcomes()); self.assertIn('sync_pending',self.outcomes())
        self.assertFalse(self.session.exists()); self.assertFalse(self.lock.exists())
        self.assertEqual(self.config.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.logs.stat().st_mode & 0o777,0o700)

    def test_upgrade_and_reinstall_preserve_identity_and_settings(self):
        self.old_install()
        for _ in range(2):
            self.run_script('preinstall'); self.payload(); self.run_script('postinstall')
        self.assertIn("SF_PROXY_DEVICE_ID='fixture-identity'",self.config.read_text())
        self.assertIn("USER_SETTING='preserve'",self.config.read_text())
        self.assertEqual(self.config.read_text().count('SF_PROXY_CONTROL_TOKEN='),1)
        self.assertEqual((self.data/'state/client.db').read_text(),'identity-state')

    def test_wrong_architecture_never_stops_old_service(self):
        self.old_install(); (self.scripts/'package-arch').write_text('x86_64')
        self.run_script('preinstall',False)
        self.assertFalse((self.root/'mock-actions.txt').exists())
        self.assertIn('wrong_architecture',self.outcomes())

    def test_wrong_target_never_stops_service(self):
        self.old_install(); self.run_script('preinstall',False,target='/Volumes/Other')
        self.assertFalse((self.root/'mock-actions.txt').exists())

    def test_bad_credentials_never_stops_service(self):
        self.old_install(); (self.scripts/'client-credentials.json').write_text('{}')
        self.run_script('preinstall',False)
        self.assertFalse((self.root/'mock-actions.txt').exists())
        self.assertIn('invalid_credentials',self.outcomes())

    def test_symlink_config_rejected(self):
        self.old_install(); self.config.unlink(); self.config.symlink_to(self.root/'outside')
        self.run_script('preinstall',False)
        self.assertFalse((self.root/'mock-actions.txt').exists())

    def test_concurrent_install_does_not_remove_first_lock(self):
        self.run_script('preinstall')
        identity=(self.lock/'id').read_text()
        self.run_script('preinstall',False)
        self.assertEqual((self.lock/'id').read_text(),identity)
        self.run_script('Recover-MacInstallation.sh')

    def test_stop_failure_keeps_files_and_backup(self):
        self.old_install(); self.run_script('preinstall',False,mode='stop_fail')
        self.assertEqual((self.bin/'version').read_text(),'0.1.21')
        self.assertTrue(self.session.exists())
        self.run_script('Recover-MacInstallation.sh'); self.assert_old()

    def test_detached_process_timeout_does_not_restore_running_files(self):
        self.old_install(); self.run_script('preinstall',False,mode='stop_timeout')
        self.assertEqual((self.bin/'version').read_text(),'0.1.21')
        self.assertTrue(self.session.exists()); self.assertIn('stop_timeout',self.outcomes())
        self.state(False,'0.1.21',False)
        self.run_script('Recover-MacInstallation.sh'); self.assert_old()

    def test_foreign_launchdaemon_is_not_stopped(self):
        self.old_install(); self.run_script('preinstall',False,mode='foreign_job')
        self.assertNotIn('bootout',(self.root/'mock-actions.txt').read_text())
        self.assertTrue(self.session.exists())

    def test_start_failure_rolls_back_old_program_config_and_service(self):
        self.old_install(); self.run_script('preinstall'); self.payload()
        self.run_script('postinstall',False,mode='start_fail'); self.assert_old()
        self.assertIn('old_service_ready',self.outcomes())
        entries=[json.loads(line) for f in self.logs.glob('*.jsonl') for line in f.read_text().splitlines()]
        failure=next(e for e in entries if e.get('outcome') == 'failed')
        self.assertEqual(failure['member'],'sf_start')
        self.assertGreater(failure['lineNumber'],0)

    def test_permission_failure_rolls_back(self):
        self.old_install(); self.run_script('preinstall'); self.payload()
        self.run_script('postinstall',False,mode='permission_fail'); self.assert_old()
        self.assertEqual([p for p in self.config.parent.glob('sf-endpointai-proxy.*') if p != self.config],[])

    def test_health_failure_rolls_back(self):
        self.old_install(); self.run_script('preinstall'); self.payload()
        self.run_script('postinstall',False,mode='health_fail'); self.assert_old()

    def test_wrong_health_version_is_not_success(self):
        self.old_install(); self.run_script('preinstall'); self.payload()
        self.run_script('postinstall',False,mode='foreign_health'); self.assert_old()

    def test_wrong_process_path_is_not_success(self):
        self.old_install(); self.run_script('preinstall'); self.payload()
        self.run_script('postinstall',False,mode='process_mismatch'); self.assert_old()

    def test_fresh_failure_disables_new_service(self):
        self.run_script('preinstall'); self.payload()
        self.run_script('postinstall',False,mode='start_fail')
        self.assertFalse(self.bin.exists()); self.assertFalse(self.config.exists())
        self.assertFalse(self.session.exists())

    def test_payload_interruption_can_be_recovered(self):
        self.old_install(); self.run_script('preinstall'); self.payload()
        self.run_script('Recover-MacInstallation.sh'); self.assert_old()

    def test_collection_exports_no_credentials_or_unfiltered_output(self):
        self.run_script('preinstall'); self.payload(); self.run_script('postinstall')
        secret=self.credentials['clientToken']
        log=next(self.logs.glob('*.jsonl'))
        with log.open('a') as stream: stream.write(json.dumps({'stage':'complete','outcome':secret,'token':secret})+'\n')
        system=self.root/'private/var/log/install.log'; system.parent.mkdir(parents=True)
        from datetime import datetime
        now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        system.write_text(f'{now} com.sf.endpointai.proxy Error {secret}\n{now} other product request-body\n')
        result=self.run_script('Collect-MacInstallerLogs.sh')
        archive=Path(result.stdout.strip())
        with zipfile.ZipFile(archive) as z:
            content='\n'.join(z.read(n).decode() for n in z.namelist() if not n.endswith('/'))
            self.assertNotIn(secret,content); self.assertNotIn('request-body',content)
            self.assertNotIn(self.credentials['transportKey'],content)
            self.assertTrue(all('credentials' not in n and 'Rollback' not in n and '.conf' not in n for n in z.namelist()))
            self.assertIn('package_failure',content)
        self.assertEqual(archive.stat().st_mode & 0o777,0o600)

    def test_log_retention_is_twenty(self):
        result=subprocess.run(['/bin/zsh','-c',f'source "{self.scripts}/InstallerSupport.sh"; for n in {{1..25}}; do sf_open_log; done'],
                              env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(list(self.logs.glob('install-*.jsonl'))),20)


if __name__ == '__main__':
    unittest.main(verbosity=2)
