"""Installer lifecycle tests: real staging/hashes, stubbed privileged OS calls."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
MOCK = '''#!PYTHON
import json,os,sys,shutil,socket
from pathlib import Path
c=json.loads(os.environ['AES128_TEST_CASE'])
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['AES128_TEST_LOG'],'a') as f: f.write(json.dumps([name]+args)+'\\n')
if name=='sysctl': print(c.get('arm',1))
elif name=='sw_vers': print(c.get('os','13.0'))
elif name=='id': print(c.get('installer_uid',0))
elif name=='stat':
 if args[-1]=='/dev/console': print(c.get('uid',501))
 elif args[1]=='%u': print(c.get('owner',0))
 else: print(oct(os.stat(args[-1]).st_mode & 0o777)[2:])
elif name=='pgrep':
 key='gui' if args[-1]=='aes128' else 'helper'
 sys.exit(0 if c.get(key,False) else 1)
elif name=='launchctl':
 if args[0]=='print': sys.exit(0 if c.get('registered',False) else 1)
 if args[0]=='bootout': sys.exit(c.get('bootout_exit',0))
 if args[0]=='asuser':
  if args[-1]=='--unregister-helper' and c.get('unregister_fail',False): sys.exit(1)
  if args[-1]=='--register-helper' and c.get('readiness_fail',False): sys.exit(1)
 if args[0]=='bootstrap':
  if c.get('bootstrap_exit',0): sys.exit(c['bootstrap_exit'])
  s=socket.socket(socket.AF_UNIX); s.bind(os.environ['AES128_TEST_SOCKET']); s.close()
elif name=='codesign': sys.exit(c.get('signature_exit',0))
elif name=='install':
 paths=[]; mode=0o755; directory=False; i=0
 while i<len(args):
  arg=args[i]
  if arg in ('-o','-g','-m'):
   if arg=='-m': mode=int(args[i+1],8)
   i+=2; continue
  if arg=='-d': directory=True
  else: paths.append(arg)
  i+=1
 if directory:
  for p in paths: os.makedirs(p,exist_ok=True); os.chmod(p,mode)
 else: shutil.copyfile(*paths); os.chmod(paths[-1],mode)
'''

class InstallerScripts(unittest.TestCase):
    def run_script(self, script='preinstall', installed=False, target='/', managed=False, **case):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); mockdir=root/'bin'; mockdir.mkdir()
            for command in ['sysctl','sw_vers','stat','pgrep','launchctl','sleep','codesign','id','install']:
                f=mockdir/command; f.write_text(MOCK.replace('PYTHON',sys.executable)); f.chmod(0o755)
            app=root/'AES128 VPN.app'; parent=root/'PrivilegedHelperTools'; parent.mkdir(mode=0o755)
            service=parent/'com.aes128.vpn'; plist=root/'helper.plist'; sock=root/'control.sock'
            if installed or script=='postinstall':
                executables=app/'Contents/MacOS'; executables.mkdir(parents=True)
                manifest=[]
                for binary in ['aes128','aes128-helper','xray','sing-box']:
                    f=executables/binary; f.write_bytes(binary.encode()); f.chmod(0o755)
                    if binary!='aes128': manifest.append(f'{hashlib.sha256(f.read_bytes()).hexdigest()}  {binary}\n')
                (root/'helper.sha256').write_text(''.join(manifest))
                if case.get('tampered'): (executables/'aes128-helper').write_text('tampered')
            if managed or script=='postinstall': plist.write_text('test service plist'); plist.chmod(0o644)
            if managed: service.mkdir(mode=0o700); (service/'aes128-helper').write_text('previous')
            if case.get('unsafe_parent'): parent.chmod(0o777)
            if case.get('symlink_service'):
                elsewhere=root/'elsewhere'; elsewhere.mkdir(); service.symlink_to(elsewhere)
            text=(SCRIPTS/script).read_text()
            text=text.replace('PATH=/usr/bin:/bin:/usr/sbin:/sbin',f'PATH="{mockdir}:/usr/bin:/bin:/usr/sbin:/sbin"')
            text=text.replace('/Applications/AES128 VPN.app',str(app)).replace('/Library/PrivilegedHelperTools',str(parent))
            text=text.replace('/Library/LaunchDaemons/com.aes128.vpn.helper.plist',str(plist)).replace('/var/run/com.aes128.vpn/control.sock',str(sock))
            scriptfile=root/script; scriptfile.write_text(text)
            log=root/'commands'
            env={**os.environ,'AES128_TEST_CASE':json.dumps(case),'AES128_TEST_LOG':str(log),'AES128_TEST_SOCKET':str(sock)}
            result=subprocess.run(['/bin/sh',str(scriptfile),'package.pkg','/',target],env=env,capture_output=True,text=True)
            calls=[json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
            result.backups=[p.read_text() for p in parent.glob('.aes128-install.*/previous/aes128-helper')]
            result.helper=(service/'aes128-helper').read_text() if (service/'aes128-helper').is_file() else None
            return result,calls

    def test_fresh_install(self):
        result,calls=self.run_script()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(any(x[0]=='launchctl' for x in calls))
    def test_unsupported_targets(self):
        for params in [{'arm':0},{'os':'12.7'},{'target':'/Volumes/Other'}]:
            result,calls=self.run_script(**params)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(any(x[0]=='launchctl' for x in calls))
    def test_running_gui_does_not_change_service(self):
        result,calls=self.run_script(installed=True,gui=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Command-Q',result.stderr)
        self.assertFalse(any(x[0]=='launchctl' for x in calls))
    def test_upgrade_unregisters_as_console_user(self):
        result,calls=self.run_script(installed=True)
        self.assertEqual(result.returncode,0,result.stderr)
        call=next(x for x in calls if x[0]=='launchctl')
        self.assertEqual(call[1:7],['asuser','501','sudo','-n','-u','#501'])
        self.assertEqual(call[-1],'--unregister-helper')
    def test_managed_upgrade_stops_service_without_changing_user_preference(self):
        result,calls=self.run_script(installed=True,managed=True,registered=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(['launchctl','bootout','system/com.aes128.vpn.helper'],calls)
        self.assertFalse(any(x[0]=='launchctl' and x[1] in ['asuser','enable','disable'] for x in calls))
    def test_cannot_replace_live_helper(self):
        for params in [{'unregister_fail':True,'registered':True},{'uid':0,'registered':True},{'helper':True},{'managed':True,'registered':True,'bootout_exit':1}]:
            result,_=self.run_script(installed=True,**params)
            self.assertNotEqual(result.returncode,0)
    def test_unregistered_existing_app_can_upgrade(self):
        result,_=self.run_script(installed=True,unregister_fail=True,registered=False)
        self.assertEqual(result.returncode,0,result.stderr)
    def test_postinstall_never_launches_gui_as_root(self):
        result,calls=self.run_script(script='postinstall',uid=0)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([x[1] for x in calls if x[0]=='launchctl'],['bootstrap'])
        result,calls=self.run_script(script='postinstall')
        self.assertEqual(result.returncode,0,result.stderr)
        launches=[x for x in calls if x[:2]==['launchctl','asuser']]
        self.assertEqual(len(launches),2)
        for call in launches: self.assertEqual(call[1:7],['asuser','501','sudo','-n','-u','#501'])
        self.assertEqual(launches[0][-1],'--register-helper')
        self.assertEqual(launches[1][7],'open')
        self.assertEqual(result.helper,'aes128-helper')
    def test_invalid_payload_or_untrusted_location_never_bootstraps(self):
        for params in [{'signature_exit':1},{'tampered':True},{'owner':501},{'unsafe_parent':True},{'symlink_service':True},{'installer_uid':501}]:
            result,calls=self.run_script(script='postinstall',**params)
            self.assertNotEqual(result.returncode,0,params)
            self.assertFalse(any(x[0]=='launchctl' for x in calls),params)
    def test_failed_start_preserves_old_binaries_for_repair(self):
        result,calls=self.run_script(script='postinstall',managed=True,bootstrap_exit=1)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.backups,['previous'])
        self.assertFalse(any(x[0]=='launchctl' and x[1]=='enable' for x in calls))
    def test_successful_update_cleans_staging(self):
        result,_=self.run_script(script='postinstall',managed=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.backups,[])
        self.assertEqual(result.helper,'aes128-helper')
    def test_failed_client_readiness_does_not_open_app(self):
        result,calls=self.run_script(script='postinstall',readiness_fail=True)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any('open' in x for x in calls))

if __name__ == '__main__': unittest.main(verbosity=2)
