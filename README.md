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

- [] User profile / `0x2d` encoding (capture 7 only caught an unchanged rewrite; toggle one profile field at a time)
- [] LIFE LOG day-history overflow (4 of 7 slots filled after 4 unsynced days; does day 8+ evict?)
- [] A failed mission LOG OFF (capture 10: LOG OFF on the watch failed and the mission vanished with no G record — capture a failed log-off with the snoop on)

Answered by captures 9/10 (see PROTOCOL-GGB100.md): the reconnection sync after a long offline mission (rolling window raw-confirmed, `0x37` flags cleared by any completed init, the app's "HIGHEST" waypoint is a real record written ≈ buffer-full); all four scheduled syncs captured — `0x36` splits AM/PM, 4/4.

Details and recording instructions per item: [PROTOCOL-GGB100.md](PROTOCOL-GGB100.md#todo--what-to-capture-next).

## License

MIT — see [LICENSE](LICENSE).
