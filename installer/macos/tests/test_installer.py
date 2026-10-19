"""Execute real installation scripts in a rewritten temporary filesystem.

Privileged/service commands are mocks; never installs or attaches on this Mac.
The production scripts have no runtime test bypass or configurable root path.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
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
        else:
            bundled=bin_path/'EndpointAIProxy.app/Contents/MacOS/Sf.EndpointAI.Client.Service'
            print(str(bundled if bundled.is_file() else bin_path/'Sf.EndpointAI.Client.Service'))
    sys.exit(0)
if command == 'curl':
    if not state.get('alive'): sys.exit(7)
    if mode == 'health_fail' and state['version'] == '0.1.22': sys.exit(7)
    version = '0.1.21' if mode == 'foreign_health' else state['version']
    print(json.dumps({'status':'ok','deviceId':'40000000-0000-0000-0000-000000000004','clientVersion':version,'lastControlSyncAtUtc':None,
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
        if version.startswith('0.2.'):
            guard = root/'Library/Application Support/SF/EndpointAIProxy/.installation-pending'
            if not guard.is_file() or not guard.read_text(): sys.exit(9)
            if mode == 'guard_start_fail': sys.exit(5)
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
        for name in ['InstallerSupport.sh','preinstall','postinstall','Collect-MacInstallerLogs.sh','Recover-MacInstallation.sh','uninstall.sh']:
            text = (SOURCE/name).read_text()
            for prefix in ['/Library/','/private/etc/','/private/var/run/','/private/var/log/','/usr/local/']:
                text = text.replace(prefix, str(self.root)+prefix)
            for command, path in [('launchctl','/bin/launchctl'),('ps','/bin/ps'),('curl','/usr/bin/curl'),
                                  ('chown','/usr/sbin/chown'),('sysctl','/usr/sbin/sysctl'),('sleep','/bin/sleep')]:
                text = text.replace(path, str(mock_root/command))
            # Only the sandbox copy invokes the synthetic client through Python;
            # no real installed/signed endpoint executable is launched.
            if name == 'uninstall.sh':
                text = text.replace('"$SERVICE" --maintenance', f'"{sys.executable}" "$SERVICE" --maintenance')
            # Only the sandbox copy bypasses root, UID and longer timeouts.
            text = text.replace('$EUID -eq 0','$EUID -ge 0')
            text = text.replace(') -eq 0', f') -eq {os.getuid()}')
            # Keep the native healthy readiness budget; only tests expecting a
            # readiness timeout shorten it, through this sandbox-only seam.
            text = text.replace('SECONDS + 60','SECONDS + ${ENDPOINTAI_TEST_READY_TIMEOUT:-60}')
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
        with sqlite3.connect(self.data/'state/client.db') as db:
            db.execute('CREATE TABLE client_identity(singleton_id INTEGER PRIMARY KEY, device_id TEXT)')
            db.execute('INSERT INTO client_identity VALUES(1,?)',('40000000-0000-0000-0000-000000000004',))
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
        if mode in ['health_fail','foreign_health','process_mismatch']:
            env['ENDPOINTAI_TEST_READY_TIMEOUT']='3'
        began=time.monotonic()
        result = subprocess.run(['/bin/zsh',str(self.scripts/name),'fixture.pkg','/',target] if name in ['preinstall','postinstall']
                                else ['/bin/zsh',str(self.scripts/name)],env=env,capture_output=True,text=True)
        for value in [self.credentials['clientToken'],self.credentials['transportKey'],self.credentials['policyHmacKey']]:
            self.assertNotIn(value,result.stdout+result.stderr)
        if (result.returncode == 0) != success:
            evidence=self.failure_evidence(result.returncode, time.monotonic()-began)
            self.fail('Installer fixture result mismatch: '+json.dumps(evidence,sort_keys=True))
        return result

    def failure_evidence(self, code, elapsed):
        # Persist only fixed enums and numeric locations in unittest output;
        # temporary raw logs/configs still get removed by tearDown.
        stages=set('begin preflight backup stop_service payload postinstall write_config start_service health_check control_plane complete restore_files rollback manual_recovery service_exit environment uninstall_detach uninstall_remove uninstall_recover'.split())
        outcomes=set('begin validated install_locked recovery_required unsupported_target unsupported_os wrong_architecture invalid_credentials unsafe_path saved unexpected_service_path bootout_failed stopped stop_timeout protected_config_written registered local_ready sync_observed sync_pending not_ready files_restored old_service_ready old_service_not_ready previous_service_state_restored failed prepared success incomplete_snapshot_discarded detached'.split())
        records=[]
        for file in sorted(self.logs.glob('install-*.jsonl')):
            for line in file.read_text().splitlines()[-24:]:
                try: record=json.loads(line)
                except (ValueError,TypeError): continue
                if not isinstance(record,dict): continue
                safe={}
                for field,allowed in [('stage',stages),('outcome',outcomes)]:
                    value=record.get(field)
                    safe[field]=value if isinstance(value,str) and value in allowed else 'unknown'
                for field in ['exitCode','lineNumber','lastExitCode','lastSignal']:
                    value=record.get(field)
                    if type(value) is int and 0<=value<=1000000: safe[field]=value
                records.append(safe)
        actions=[]
        action_file=self.root/'mock-actions.txt'
        if action_file.exists():
            actions=[v if v in ['print','bootout','bootstrap','enable','kickstart'] else 'unknown' for v in action_file.read_text().splitlines()[-24:]]
        return {'scriptExitCode':code,'elapsedSeconds':round(elapsed,3),'events':records[-24:],'mockActions':actions}

    def outcomes(self):
        text='\n'.join(p.read_text() for p in self.logs.glob('*.jsonl'))
        for name in ['clientToken','transportKey','policyHmacKey']:
            self.assertNotIn(self.credentials[name],text)
        return [json.loads(line).get('outcome') for line in text.splitlines() if line]

    def assert_old(self):
        self.assertEqual((self.bin/'version').read_text(),'0.1.21')
        self.assertIn("SF_PROXY_CONTROL_TOKEN='old-token'",self.config.read_text())
        with sqlite3.connect(self.data/'state/client.db') as db:
            self.assertEqual(db.execute('SELECT device_id FROM client_identity WHERE singleton_id=1').fetchone()[0],'40000000-0000-0000-0000-000000000004')
        self.assertFalse(self.session.exists())
        self.assertFalse(self.lock.exists())


    def uninstall_executable(self, bundled=False):
        executable=self.bin/'Sf.EndpointAI.Client.Service'
        if bundled:
            executable=self.bin/'EndpointAIProxy.app/Contents/MacOS/Sf.EndpointAI.Client.Service'
            executable.parent.mkdir(parents=True)
        executable.write_text(f'#!{sys.executable}\n'+r'''import json, os, pathlib, sys
root=pathlib.Path(os.environ['MOCK_ROOT'])
state=json.loads((root/'mock-state.json').read_text())
with (root/'detach-actions.txt').open('a') as f: f.write(str(pathlib.Path(sys.argv[0]).relative_to(root))+'\n')
if state.get('alive'): sys.exit(41)
if os.environ.get('MOCK_MODE')=='detach_fail': sys.exit(42)
sys.exit(0)
''')
        executable.chmod(0o755)
        return executable

    def test_uninstall_stops_before_detach_plain(self):
        self.old_install();self.uninstall_executable()
        self.run_script('uninstall.sh')
        self.assertFalse(self.plist.exists());self.assertFalse(self.share.exists())
        self.assertTrue(self.config.exists());self.assertTrue((self.data/'state/client.db').exists())
        self.assertIn('detached',self.outcomes())
        self.assertFalse(self.session.exists());self.assertFalse(self.lock.exists())
        self.assertIn('bootout',(self.root/'mock-actions.txt').read_text().splitlines())

    def test_uninstall_prefers_bundle_with_flat_wrapper(self):
        self.old_install();exe=self.uninstall_executable(bundled=True)
        self.run_script('uninstall.sh')
        self.assertEqual((self.root/'detach-actions.txt').read_text().strip(),str(exe.relative_to(self.root)))

    def test_uninstall_detach_failure_restores_service_and_keeps_files(self):
        self.old_install();self.uninstall_executable()
        self.run_script('uninstall.sh',False,mode='detach_fail')
        self.assertTrue(self.plist.exists());self.assertTrue(self.share.exists())
        with sqlite3.connect(self.data/'state/client.db') as db:
            self.assertEqual(db.execute('SELECT device_id FROM client_identity WHERE singleton_id=1').fetchone()[0],'40000000-0000-0000-0000-000000000004')
        state=json.loads((self.root/'mock-state.json').read_text())
        self.assertTrue(state['loaded']);self.assertTrue(state['alive'])
        self.assertIn('old_service_ready',self.outcomes())
        self.assertNotIn('success',self.outcomes())

    def test_uninstall_stop_failure_never_detaches(self):
        self.old_install();self.uninstall_executable()
        self.run_script('uninstall.sh',False,mode='stop_fail')
        self.assertFalse((self.root/'detach-actions.txt').exists())
        self.assertTrue(self.plist.exists());self.assertTrue(self.share.exists())
        self.assertTrue(json.loads((self.root/'mock-state.json').read_text())['loaded'])

    def test_uninstall_stop_timeout_never_detaches(self):
        self.old_install();self.uninstall_executable()
        self.run_script('uninstall.sh',False,mode='stop_timeout')
        self.assertFalse((self.root/'detach-actions.txt').exists())
        self.assertTrue(self.plist.exists());self.assertTrue(self.share.exists())
        self.assertIn('stop_timeout',self.outcomes())

    def test_uninstall_restore_failure_is_visible_and_keeps_registration(self):
        self.old_install();self.uninstall_executable()
        # Only the sandbox command simulation rejects restoration.
        mock=self.root/'mocks/launchctl'
        mock.write_text(mock.read_text().replace("elif action == 'bootstrap':", "elif action == 'bootstrap':\n        if mode == 'detach_fail': sys.exit(5)"))
        result=self.run_script('uninstall.sh',False,mode='detach_fail')
        self.assertIn('UNINSTALL_SERVICE_RESTORE_FAILED',result.stderr)
        self.assertIn('old_service_not_ready',self.outcomes())
        self.assertTrue(self.plist.exists());self.assertTrue(self.share.exists())
        self.assertTrue(self.session.exists());self.assertTrue(self.lock.exists())

    def test_uninstall_removal_failure_restores_registration_and_tools(self):
        self.old_install();self.uninstall_executable()
        diagnostics=self.root/'usr/local/sbin/sf-endpointai-diagnostics'
        diagnostics.write_text('fixture-diagnostic-helper')
        script=self.scripts/'uninstall.sh'
        script.write_text(script.read_text().replace('/bin/rm -rf "$SF_SHARE"','/usr/bin/false'))
        self.run_script('uninstall.sh',False)
        self.assertTrue(self.plist.exists());self.assertTrue((self.share/'old-marker').exists())
        self.assertEqual(diagnostics.read_text(),'fixture-diagnostic-helper')
        self.assertTrue(json.loads((self.root/'mock-state.json').read_text())['loaded'])
        self.assertIn('old_service_ready',self.outcomes())

    def test_uninstall_failure_does_not_start_originally_stopped_service(self):
        self.old_install(loaded=False);self.uninstall_executable()
        self.run_script('uninstall.sh',False,mode='detach_fail')
        self.assertTrue(self.plist.exists());self.assertTrue(self.share.exists())
        self.assertFalse(json.loads((self.root/'mock-state.json').read_text())['loaded'])
        self.assertNotIn('bootstrap',(self.root/'mock-actions.txt').read_text().splitlines())

    def test_collector_matches_new_go_package_without_bundle_id(self):
        install_log=self.root/'private/var/log/install.log'
        install_log.parent.mkdir(parents=True,exist_ok=True)
        stamp=subprocess.check_output(['/bin/date','+%Y-%m-%d %H:%M:%S'],text=True).strip()
        install_log.write_text(stamp+' Installer: EndpointAIDLP-Client-0.2.0-development-osx-arm64.pkg finished\n'+stamp+' Installer: EndpointAIDLP-Client-0.2.0-osx-x64.pkg failed\n'+stamp+' OtherProduct-9.9.9.pkg finished\n')
        result=self.run_script('Collect-MacInstallerLogs.sh')
        archive=Path(result.stdout.strip().splitlines()[-1])
        with zipfile.ZipFile(archive) as z:
            events=[n for n in z.namelist() if n.endswith('system-install-events.jsonl')]
            self.assertEqual(len(events),1)
            records=[json.loads(v) for v in z.read(events[0]).decode().splitlines()]
            self.assertEqual([v['event'] for v in records],['package_finished','package_failure'])

    def test_fresh_install_offline_is_successful(self):
        self.run_script('preinstall'); self.payload(); self.run_script('postinstall')
        self.assertIn('success',self.outcomes()); self.assertIn('sync_pending',self.outcomes())
        self.assertFalse(self.session.exists()); self.assertFalse(self.lock.exists())
        self.assertEqual(self.config.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.logs.stat().st_mode & 0o777,0o700)

    def go_payload(self):
        self.payload()
        (self.bin/'version').write_text('0.2.0')
        bundled=self.bin/'EndpointAIProxy.app/Contents/MacOS/Sf.EndpointAI.Client.Service'
        bundled.parent.mkdir(parents=True)
        bundled.write_text('synthetic native executable')

    def select_go_package(self):
        support=self.scripts/'InstallerSupport.sh'
        support.write_text(support.read_text().replace('SF_VERSION=0.1.22','SF_VERSION=0.2.0').replace('SF_IMPLEMENTATION=dotnet','SF_IMPLEMENTATION=go'))
        (self.scripts/'package-version').write_text('0.2.0')

    def test_go_development_bundle_upgrade_preserves_state(self):
        self.old_install();self.select_go_package()
        self.run_script('preinstall');self.go_payload();self.run_script('postinstall')
        with sqlite3.connect(self.data/'state/client.db') as db:
            self.assertEqual(db.execute('SELECT device_id FROM client_identity WHERE singleton_id=1').fetchone()[0],'40000000-0000-0000-0000-000000000004')
        self.assertEqual((self.bin/'version').read_text(),'0.2.0')
        self.assertIn('local_ready',self.outcomes())

    def test_go_development_bundle_failure_restores_old_dotnet_layout(self):
        self.old_install();self.select_go_package()
        self.run_script('preinstall');self.go_payload();self.run_script('postinstall',False,'foreign_health')
        self.assert_old()
        self.assertFalse((self.bin/'EndpointAIProxy.app').exists())

    def test_go_commit_releases_installation_guard(self):
        self.old_install();self.select_go_package()
        self.run_script('preinstall');self.go_payload();self.run_script('postinstall')
        self.assertFalse((self.data/'.installation-pending').exists())
        self.assertFalse(self.session.exists())

    def test_go_start_failure_restores_identity_and_releases_guard(self):
        self.old_install();self.select_go_package()
        self.run_script('preinstall');self.go_payload()
        self.run_script('postinstall',False,'guard_start_fail')
        self.assert_old()
        self.assertFalse((self.data/'.installation-pending').exists())

    def test_go_changed_database_rejected_before_candidate_start(self):
        self.old_install();self.select_go_package()
        self.run_script('preinstall');self.go_payload()
        with sqlite3.connect(self.data/'state/client.db') as db:
            db.execute('UPDATE client_identity SET device_id=?',('50000000-0000-0000-0000-000000000005',))
        self.run_script('postinstall',False)
        self.assert_old()
        self.assertFalse((self.data/'.installation-pending').exists())

    def test_go_cleanup_failure_after_commit_does_not_restore_old_state(self):
        self.old_install();self.select_go_package()
        self.run_script('preinstall');self.go_payload()
        post=self.scripts/'postinstall'
        post.write_text(post.read_text().replace('  sf_clear_session || return 1', '  /usr/bin/false || return 1'))
        self.run_script('postinstall',False)
        self.assertEqual((self.bin/'version').read_text(),'0.2.0')
        self.assertFalse((self.data/'.installation-pending').exists())
        self.assertTrue(self.session.exists())
        self.assertIn('recovery_required',self.outcomes())

    def test_go_ephemeral_shm_change_does_not_reject_preserved_state(self):
        self.old_install();self.select_go_package()
        # SHM is coordination metadata, never the identity/WAL durability proof.
        (self.data/'state/client.db-shm').write_bytes(b'old coordination')
        self.run_script('preinstall');self.go_payload()
        (self.data/'state/client.db-shm').write_bytes(b'new coordination')
        self.run_script('postinstall')
        self.assertFalse((self.data/'.installation-pending').exists())

    def test_upgrade_and_reinstall_preserve_identity_and_settings(self):
        self.old_install()
        for _ in range(2):
            self.run_script('preinstall'); self.payload(); self.run_script('postinstall')
        self.assertIn("SF_PROXY_DEVICE_ID='fixture-identity'",self.config.read_text())
        self.assertIn("USER_SETTING='preserve'",self.config.read_text())
        self.assertEqual(self.config.read_text().count('SF_PROXY_CONTROL_TOKEN='),1)
        with sqlite3.connect(self.data/'state/client.db') as db:
            self.assertEqual(db.execute('SELECT device_id FROM client_identity WHERE singleton_id=1').fetchone()[0],'40000000-0000-0000-0000-000000000004')

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

    def test_healthy_readiness_survives_slow_mock_scheduling(self):
        # One healthy verification iteration deliberately exceeds the old
        # fixture's 3s wall-clock budget. Production needs two stable samples.
        for command in ['ps','curl']:
            mock=self.root/'mocks'/command
            mock.write_text(mock.read_text().replace(
                "bin_path = root/'Library/Application Support/SF/EndpointAIProxy/bin'",
                "bin_path = root/'Library/Application Support/SF/EndpointAIProxy/bin'\nif state.get('alive') and 'lstart=' not in args: time.sleep(1.6)"))
        self.run_script('preinstall');self.payload();self.run_script('postinstall')
        self.assertIn('local_ready',self.outcomes())
        self.assertNotIn('not_ready',self.outcomes())

    def test_failure_evidence_rejects_untrusted_log_fields(self):
        self.logs.mkdir(parents=True)
        secret=self.credentials['clientToken']
        (self.logs/'install-fixture.jsonl').write_text(json.dumps({
            'stage':secret,'outcome':secret,'exitCode':secret,
            'lineNumber':23,'token':secret,'member':secret})+'\n'+json.dumps([])+'\n'+json.dumps({'stage':[],'outcome':{}})+'\n')
        evidence=self.failure_evidence(1,0.25)
        self.assertNotIn(secret,json.dumps(evidence))
        self.assertEqual(evidence['events'],[{'stage':'unknown','outcome':'unknown','lineNumber':23},{'stage':'unknown','outcome':'unknown'}])

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
