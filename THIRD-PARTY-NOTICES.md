# Third-party notices

`mobile-backup-reconstructor` is distributed under the GNU General Public License
v3.0 or later (see [LICENSE](LICENSE)). It depends on the following third-party
packages, which carry their own licences and are **not** redistributed by this
repository — they are installed from PyPI by `uv sync` or `pip`.

| Package | Licence | Role |
| --- | --- | --- |
| [PySide6](https://doc.qt.io/qtforpython/) (with `PySide6-Essentials`, `PySide6-Addons`, `shiboken6`) | `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only` — used here under **LGPL-3.0** | The graphical interface |
| [cryptography](https://cryptography.io/) | `Apache-2.0 OR BSD-3-Clause` | AES-CBC and AES key unwrap for encrypted backups |

## Why GPL-3.0-or-later

PySide6 (Qt for Python) is offered under LGPL-3.0 or a commercial licence. This
project takes the LGPL-3.0 option, whose terms permit combining the library into
a work released under the GPL. GPL-3.0-or-later was chosen as the project licence
because it is compatible with that option and with `cryptography`'s
Apache-2.0/BSD-3-Clause terms, and because a forensic tool benefits from
derivative work staying inspectable.

## Scope of these obligations

This repository distributes **source code only**. It contains no Qt or OpenSSL
binaries, and installing the dependencies is the user's own action, so the
LGPL's "Combined Work" conveyance duties in section 4 are not triggered by
cloning or downloading this repository.

That changes if the project is ever shipped as a **frozen or bundled
application** (PyInstaller, cx_Freeze, an OS installer, a container image that
embeds the wheels). Such a build does convey Qt, and would then need to:

- include the LGPL-3.0 text and a notice identifying the Qt/PySide6 components;
- keep Qt dynamically linked and allow the user to substitute their own build;
- state prominently that the work uses Qt and is covered by the LGPL.

Anyone producing a binary distribution of this project should review those
requirements before publishing it.

*This summary is provided for orientation and is not legal advice.*
