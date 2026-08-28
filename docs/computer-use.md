# Computer Use

Computer Use is disabled by default and should be enabled only for a bounded,
user-understood task. `--allow-screen` permits screenshots and semantic
AT-SPI2 inspection. `--allow-computer-use` additionally permits keyboard,
pointer, focus, semantic actions, and editable-text changes; it also implies
screen access.

## Linux backends

- Accessibility: AT-SPI2 over the desktop session bus.
- Screenshots: KWin ScreenShot2 when available, then Spectacle, `grim`,
  `gnome-screenshot`, or ImageMagick `import` where detected.
- Wayland input: XDG RemoteDesktop Portal first, retaining compositor consent.
- X11 input: `xdotool` fallback; `wdotool` is supported when present.

The Agent does not automatically use `/dev/uinput`, `ydotool`, or another
consent-bypassing input mechanism. GUI tools return bounded semantic data and
short-lived UI refs; ambiguous or incomplete selectors fail instead of
guessing.

## Persistence and environment

Portal permission restoration defaults to `--computer-persist=process`. Choose
`none` for no restore, or explicitly choose `persistent` to store only the
rotating restore token below the Agent state directory with mode 0600. The
Agent needs the logged-in graphical user's `WAYLAND_DISPLAY`, session D-Bus,
runtime directory, and AT-SPI environment. `doctor` checks these without
opening a browser or enabling a service.

Use `computer_observe` first, prefer semantic actions and direct editable-text
operations, and fall back to screenshots/pointer coordinates only for
pixel-only applications. Screenshots and accessibility trees can reveal
secrets visible in other applications; use a dedicated desktop profile and
revoke the capability when the task ends.
