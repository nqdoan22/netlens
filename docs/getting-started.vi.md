# Hướng dẫn chạy NetLens trên Windows (laptop + iPhone)

Tài liệu này hướng dẫn từng bước để laptop Windows phát Wi-Fi cho iPhone, sau đó
dùng NetLens xem iPhone đang kết nối tới đâu.

## 1. Cài đặt (một lần)

| Phần mềm | Dùng để | Tải |
|---|---|---|
| **Npcap** | driver bắt gói tin (Wireshark cũng dùng) | https://npcap.com → *Npcap installer* |
| **Go** 1.25 trở lên | biên dịch NetLens | https://go.dev/dl |
| **Git** | tải mã nguồn | https://git-scm.com |
| Wireshark *(không bắt buộc)* | tự xem gói tin, đối chiếu với NetLens | https://www.wireshark.org |

Khi cài Npcap, **giữ dấu tích** ở ô *Install Npcap in WinPcap API-compatible Mode*.
Không cần tích *Restrict Npcap driver's access to Administrators only*. Nếu đã tích
ô này thì phải chạy NetLens bằng terminal mở với quyền Administrator.

Tải và biên dịch NetLens (mở **PowerShell**):

```powershell
git clone https://github.com/nqdoan22/netlens.git
cd netlens
go build -o netlens.exe ./cmd/netlens
```

Chạy thử với file mẫu (không cần hotspot):

```powershell
.\netlens.exe -r testdata\sample.pcap
```

## 2. Bật hotspot trên laptop

1. **Settings → Network & internet → Mobile hotspot**.
2. *Share my Internet connection from*: chọn **Wi-Fi**.
3. *Share over*: chọn **Wi-Fi**.
4. Bấm **Edit** để đặt tên mạng và mật khẩu, ví dụ `NetLens-Hotspot`.
5. Bật công tắc **Mobile hotspot**.
6. Trong *Power saving*, tắt *Turn off hotspot when no devices are connected*.

Laptop vẫn kết nối Wi-Fi nhà như bình thường. Card Wi-Fi tự làm hai việc cùng lúc.

## 3. Cài đặt trên iPhone

Kết nối iPhone vào `NetLens-Hotspot`, rồi bấm nút **ⓘ** cạnh tên mạng:

| Cài đặt | Chọn | Lý do |
|---|---|---|
| **Private Wi-Fi Address** | **Fixed** | Địa chỉ MAC không đổi, nên NetLens luôn nhận ra đúng chiếc iPhone này |
| **Limit IP Address Tracking** | **Tắt** | Nếu bật (và có iCloud Private Relay), traffic Safari bị mã hóa qua máy chủ Apple, NetLens không thấy đích thật |

Thêm một mục nữa: **Settings → Cellular (Di động) → Wi-Fi Assist: Tắt**, hoặc tắt hẳn
dữ liệu di động khi đo. Nếu không, khi Wi-Fi yếu iPhone tự chuyển sang 4G/5G và
traffic đó không đi qua laptop.

## 4. Chạy NetLens

```powershell
.\netlens.exe -list
```

Adapter hotspot được đánh dấu `*`. Thường có mô tả *Microsoft Wi-Fi Direct Virtual
Adapter* và địa chỉ `192.168.137.1`.

```powershell
.\netlens.exe
```

Mặc định NetLens tự tìm adapter hotspot (`-i auto`). Mở vài app trên iPhone, các
dòng như sau sẽ hiện ra:

```text
14:02:11.520  DEVICE Doans-iPhone     192.168.137.45 a2:...
14:02:11.532  DNS    Doans-iPhone        graph.instagram.com A -> 157.240.x.x
14:02:11.540  OPEN   Doans-iPhone     -> graph.instagram.com  [157.240.x.x:443 TCP tls h2]
14:02:41.010  CLOSE  Doans-iPhone     -> graph.instagram.com  29.5s  out 12.4 KB  in 340.1 KB  (fin)
```

Ý nghĩa từng loại dòng:

- **DEVICE**: có thiết bị mới. Tên lấy từ DHCP.
- **DNS**: thiết bị hỏi địa chỉ IP của một tên miền.
- **OPEN**: mở kết nối. Trong ngoặc là IP:cổng, giao thức, và nếu có thì `tls` kèm giao thức con (`h2` = HTTP/2).
- **CLOSE**: kết nối kết thúc. `out` là dữ liệu thiết bị gửi đi, `in` là dữ liệu nhận về. Lý do kết thúc: `fin` (đóng bình thường), `rst` (bị ngắt), `idle` (im lặng quá lâu), `capture_end` (bạn dừng NetLens).

Bấm **Ctrl+C** để dừng. NetLens in ra bảng tổng kết, trong đó có số gói tin bị bỏ sót (`dropped`).

Các tùy chọn hữu ích:

```powershell
.\netlens.exe -v                    # hiện cả DNS, mDNS, DHCP, multicast
.\netlens.exe -json > log.jsonl     # ghi sự kiện ra file JSON để phân tích sau
```

## 5. Lỗi thường gặp

| Hiện tượng | Cách xử lý |
|---|---|
| `is Npcap installed?` | Cài Npcap (mục 1), rồi mở lại terminal |
| `no Windows Mobile Hotspot adapter found` | Hotspot chưa bật, hoặc chưa có thiết bị nào kết nối và Windows đã tự tắt hotspot. Bật lại theo mục 2. |
| Không bật được hotspot / mục *Share over Wi-Fi* bị mờ | Card Wi-Fi không phát được khi đang kết nối Wi-Fi. Thử cập nhật driver card Wi-Fi, chọn *Network band: Any*, hoặc dùng USB Wi-Fi rời. |
| Có dòng DNS nhưng ít dòng OPEN | Nhiều app dùng QUIC (UDP) cho video. Các kết nối QUIC vẫn hiện, với tên lấy từ DNS. |
| Một số kết nối chỉ có IP, không có tên miền | App dùng DNS mã hóa (DoH) hoặc Encrypted Client Hello. Đây là giới hạn đã biết. |
| Không thấy traffic của iPhone | Kiểm tra iPhone có đang ở `NetLens-Hotspot` không, và đã tắt Wi-Fi Assist chưa (mục 3) |

## 6. Ghi lại traffic để gửi cho người khác xem

Có thể dùng Wireshark: chọn adapter hotspot → Start → File → Save As `.pcapng`.
Sau đó phân tích lại bằng:

```powershell
.\netlens.exe -r capture.pcapng
```

**Không** đưa file capture thật lên GitHub hay gửi công khai. File đó chứa toàn bộ
lịch sử kết nối của thiết bị bạn.
