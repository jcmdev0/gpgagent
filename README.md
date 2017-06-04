Provides a golang interface to the gnupg-agent daemon.  It is currently
oriented toward the "classic" version.  Support for the [modern
version](https://www.gnupg.org/faq/whats-new-in-2.1.html) likely
requires some changes to [core openpgp go
libraries](https://github.com/golang/crypto/tree/master/openpgp) to
fundamentally incorporate communication with the new agent-centric key
handling.

This package is a standalone fork of code in
[trousseau](https://github.com/oleiade/trousseau), which is in turn a
fork from [passphrase](https://github.com/jgrocho/passphrase), which is
a fork from [camlistore.org](camlistore.org/pkg/misc/gpgagent).
