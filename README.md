# WCH BLE Analyzer Pro — Linux Driver

> WinChipHead forgot to ship a Linux driver.
> We forgot to ask permission.

A reverse-engineered libusb-1.0 driver for the **WCH BLE Analyzer Pro** — a $30 USB
BLE 5.1 sniffer built around three CH582F RISC-V MCUs and a CH334 hub.  Each MCU gets
its own advertising channel (37 / 38 / 39), so you capture the entire BLE advertising
spectrum simultaneously.  Output is a standard pcap that Wireshark opens without plugins.

---

## Hardware

```
┌─────────────────────────────────────┐
│         WCH BLE Analyzer Pro        │
│                                     │
│  [CH582F ch37]  VID 0x1A86          │
│  [CH582F ch38]  PID 0x8009  × 3     │
│  [CH582F ch39]                      │
│  [CH334 hub  ]  PID 0x8091          │
└─────────────────────────────────────┘
```

The device shows up as three independent USB devices through the hub.  The Windows app
knows this.  Now Linux does too.

---

## Requirements

```bash
sudo apt install libusb-1.0-0-dev   # that's it
```

---

## Build & install

```bash
cd linux-driver
make
sudo make install          # installs binary + udev rule
sudo udevadm control --reload-rules && sudo udevadm trigger
```

---

## Usage

```bash
# Capture to file and watch live
sudo ./wch_capture -v -w capture.pcap

# Open in Wireshark
wireshark capture.pcap

# Pin all MCUs to channel 37 (why though)
sudo ./wch_capture -w capture.pcap -c 37

# 2M PHY
sudo ./wch_capture -w capture.pcap -p 2
```

After installing the udev rule you can drop `sudo`.

```
Options:
  -v            Print packets to stdout
  -w FILE.pcap  Write PCAP (DLT 256, BLE LL + phdr)
  -p PHY        PHY: 1=1M (default), 2=2M, 3=CodedS8, 4=CodedS2
  -i ADDR       Initiator MAC filter  (AA:BB:CC:DD:EE:FF)
  -a ADDR       Advertiser MAC filter (AA:BB:CC:DD:EE:FF)
  -k KEY        LTK, 32 hex chars
  -K PASSKEY    BLE passkey (6-digit decimal)
  -2            Custom 2.4G mode
  -c CHAN       Channel: BLE adv 37/38/39 or 0=all (auto per MCU); 2.4G 0-39
  -h            Show this help
```

---

## How it works

The CH582F speaks a simple vendor protocol over USB bulk transfers:

```
Host  →  AA 84 ...          identify / check firmware
Device → 33 32              firmware present, let's go
Host  →  AA 81 ... ch ...   BLE monitor config (PHY + channel)
Host  →  AA A1              start scan
Device → 55 10 ...          BLE packets, forever
```

Packets arrive as `[0x55][0x10][len16][payload]` frames.  The driver decodes them,
reconstructs the BLE LL PDU, appends a BLE CRC-24, and writes a
`LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` pcap record.  Wireshark takes it from there.

Full reverse engineering notes: [`CLAUDE.md`](CLAUDE.md) and [`RE_PROCESS.md`](RE_PROCESS.md).

---

## Status

**Working.** All three MCUs capture simultaneously on ch37/38/39.
Wireshark decodes ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND, SCAN_REQ, SCAN_RSP,
CONNECT_IND, OUI lookups, the works.

Some `[Malformed Packet]` warnings appear for BLE 5.0 devices sending >37-byte payloads
in legacy PDU types — the data is correct, Wireshark is just strict about the BLE 4.x
length limit.

---

## License

Do whatever you want.  WinChipHead certainly wasn't going to help you.
