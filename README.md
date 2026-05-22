# controller

  iOS toolbox using the **DarkSword kernel exploit** (by [rooootdev](https://github.com/rooootdev/lara)).

  Supports **iOS 17.0 – 18.7.1** and **iOS 26.0.x**, excluding M5 and A19 devices.

  ## Features

  ### IPA Installer
  Install unsigned IPA files permanently — no developer account, no 7-day expiry.
  DarkSword's VFS access writes app bundles directly to the app container directory,
  bypassing `amfid` code-signature enforcement.

  ### Root Manager
  Grant true root (`uid=0`) to any running process by writing directly to its `ucred`
  structure in kernel memory. Includes one-tap self-root for controller itself.

  ## How it works

  controller uses **DarkSword** — a kernel exploit supporting iOS 17.0–26.0.x —
  to obtain arbitrary kernel read/write primitives. These primitives are used to:

  - Initialise VFS access (read/write any file on the system)
  - Patch process credentials in kernel memory (root escalation)
  - Bypass `amfid` for unsigned code execution

  DarkSword credit: [rooootdev](https://github.com/rooootdev/lara)

  ## Build

  Open `controller.xcodeproj` in Xcode 16+, select your signing team, and build.

  Requires `libgrabkernel2.dylib` and `libxpf.dylib` (included in `controller/lib/`).

  ## Disclaimer

  For research and educational purposes only.
  