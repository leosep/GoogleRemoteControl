# GoogleRemoteControl

An open-source Android remote control for **Google TV / Android TV** devices, written in Kotlin with Jetpack Compose.

It talks to the TV directly over the local network using the official Android TV Remote Service v2 protocol (TLS on ports `6466`/`6467`), the same protocol used by the Google TV mobile app. No account, no cloud, no ads.

## Features

- Automatic TV discovery on the local network (NSD / mDNS).
- One-time pairing with the 6-character code shown on the TV.
- Full D-pad navigation (Up / Down / Left / Right / OK).
- Back, Home and Menu.
- Volume +, Volume − and Mute.
- Channel +, Channel − and Play/Pause.
- Power and Google Assistant.
- Shortcuts to open Netflix and YouTube on the TV.
- On-screen keyboard to type text on the TV.

## Requirements

- Android 8.0 (API 26) or newer.
- A Google TV / Android TV device on the same Wi-Fi network with **Android TV Remote Service** enabled
  (`Settings → Remotes & accessories → Pair remote or accessory`).

## Getting started

1. Install the app on your phone.
2. Make sure the phone and the TV are on the same network.
3. Pick your TV from the discovered list (or type its IP address).
4. Tap **Pair** and enter the 6-character code shown on the TV.
5. Tap **Connect** and use the remote.

## Building

```bash
./gradlew assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

A release build (signed with the debug key, for local testing) is available with:

```bash
./gradlew assembleRelease
```

## Project layout

```
app/src/main/java/com/leosep/googleremotecontrol/
├── MainActivity.kt   # Jetpack Compose UI
└── TvRemote.kt       # Protocol client (TLS, protobuf, pairing, keys, discovery)
```

## Disclaimer

This project is not affiliated with, endorsed by, or sponsored by Google. "Google TV" and "Android TV" are trademarks of Google LLC. The app name is used only to describe compatibility.

## License

MIT — see [LICENSE](LICENSE).
