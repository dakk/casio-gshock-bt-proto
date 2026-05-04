# casio-gshock-bt-proto


Interactive BLE probe and protocol documentation for the **Casio GBD-200** watch.

## What it does

`probe_casio.py` connects to the watch over BLE and lets you:

- fetch step count and hourly history
- fetch all sport activity sessions (full CONVOY handshake)
- send phone notifications to the watch display
- sync the current time
- receive phone-finder alerts from the watch

## Requirements

```
pip install bleak
```

## Usage

```
python3 probe_casio.py [MAC]
```

The MAC defaults to `D1:3C:8F:15:D6:34`. Edit `GPS_LAT`/`GPS_LON`/`GPS_ALT` at the top of the file to set your location before connecting.

### Commands

| Command | Description |
|---------|-------------|
| `steps` | Fetch step count and hourly history |
| `sport` | Fetch all sport sessions |
| `notify [msg]` | Send a notification |
| `notify sender\|title\|msg` | Send with explicit fields |
| `time` | Resync current time |
| `config` | Re-send config sync (clears "connection failed") |
| `raw <hex …>` | Write raw bytes to DATA_REQUEST_SP |
| `quit` | Disconnect and exit |

## Protocol

See [PROTOCOL.md](PROTOCOL.md) for a full description of the BLE GATT characteristics, feature IDs, init handshake, CONVOY data encoding, sport session layout, notifications, GPS chunks, and running session events.

## License

MIT — see [LICENSE](LICENSE).
