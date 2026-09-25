# casio-gshock-bt-proto


Interactive BLE probe and protocol documentation for the **Casio GBD-200** and **Casio GG-B100** watches.

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
python3 probe_casio.py MAC
```

Edit `GPS_LAT`/`GPS_LON`/`GPS_ALT` at the top of the file to set your location before connecting.

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

### GG-B100

```
python3 probe_casio_ggb100.py MAC
```

The GG-B100 only advertises when it wants to talk, so start the probe and then press CONNECT on the watch. Commands: `lifelog`, `mission`, `status`, `newdata`, `settings`, `set`, `mode`, `screen`, `alarms`, `alarm`, `timer`, `settimer`, `worldtime`, `dst`, `locind`, `time`, `appinfo`, `req`, `wfeat`, `raw` (type `help`). Edit `GPS_LAT`/`GPS_LON` and `WORLD_LAT`/`WORLD_LON` at the top of the file first.

Both probes share [casio_ble.py](casio_ble.py): the GATT layer, the feature ids common to both watches, the connection prefix, the world-time "city block", the time packet and the plain DATA_REQUEST_SP fetch.

## Protocol

See [PROTOCOL.md](PROTOCOL.md) for a full description of the BLE GATT characteristics, feature IDs, init handshake, CONVOY data encoding, sport session layout, notifications, GPS chunks, and running session events.

For the GG-B100 see [PROTOCOL-GGB100.md](PROTOCOL-GGB100.md); [CAPTURES-GGB100.md](CAPTURES-GGB100.md) has the frame-by-frame timelines of the recordings it was derived from.

## TODO 

### GBD200

- [] Phone GPS during workouts
- [] Workout timers settings
- [] Workout screen customization

### GG-B100

- [] Fresh pairing with snoop on (GATT table, `h0009`, APP_INFO setup)
- [] "Display orologio" switches toggled one at a time
- [] `0x38` "Ripristina Impostazioni"
- [] Phone finder with the app killed (the watch-side trigger, reason `02` + `0x0a`, is done)
- [] Mission with the phone unreachable for hours — answered: it survives 5 h 47 min offline (2026-09-25 test, screenshot in `dumps/ggb100/`); still open: a BT log of the reconnection sync (does the 60-sample series wrap or compact past 2 h? does GOAL offline set `0x37` / save the point?)
- [] LIFE LOG day-history overflow (4 of 7 slots filled after 4 unsynced days; does day 8+ evict?)
- [] An 18:30 / 00:30 scheduled sync (`0x36` slot index: 06:30 = `00`, 12:30 = `01`)

Details and recording instructions per item: [PROTOCOL-GGB100.md](PROTOCOL-GGB100.md#todo--what-to-capture-next).

## License

MIT — see [LICENSE](LICENSE).
