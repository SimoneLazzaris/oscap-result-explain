# Oscap result explain

Need to understand why a CVE is affecting you but you only have an OSCAP xml report that is too cumbersome to read by hand.
Look no farther!

## Usage

Let's say you have you result in file `oscap-result.xml` and you want to know why CVE-2021-3520 is affecting you.

```sh
./oscap-result-explain --filename oscap-result.xml --cveid CVE-2021-3520
```

The output will show which criteria is triggered, and which tests are involved:
```
oval:com.tuxcare.clsa:def:1695326199: CVE-2021-3520 <true>
Criteria:
oval:com.tuxcare.clsa:tst:1695326199001: true
  oval:com.tuxcare.clsa:tst:1695326199001: CentOS 7.9 with ELS isn't installed <true>
oval:com.tuxcare.clsa:tst:1695326199002: false
  oval:com.tuxcare.clsa:tst:1695326199002: lz4 is earlier than 0:1.8.3-1.el7.tuxcare.els1 <false>
  item 107207134: false
      .id: 107207134
      .status: exists
      arch: x86_64
      epoch: (none)
      evr: 0:1.8.3-1.el7.tuxcare.els1
      extended_name: lz4-0:1.8.3-1.el7.tuxcare.els1.x86_64
      name: lz4
      release: 1.el7.tuxcare.els1
      signature_keyid: d07bf2a08d50eb66
      version: 1.8.3
oval:com.tuxcare.clsa:tst:1695326199003: true
  oval:com.tuxcare.clsa:tst:1695326199003: lz4 isn't signed with CentOS 7 key <true>
  item 107207134: false
      .id: 107207134
      .status: exists
      arch: x86_64
      epoch: (none)
      evr: 0:1.8.3-1.el7.tuxcare.els1
      extended_name: lz4-0:1.8.3-1.el7.tuxcare.els1.x86_64
      name: lz4
      release: 1.el7.tuxcare.els1
      signature_keyid: d07bf2a08d50eb66
      version: 1.8.3
oval:com.tuxcare.clsa:tst:1695326199004: false
  oval:com.tuxcare.clsa:tst:1695326199004: lz4 isn't signed with Tuxcare ELS key <false>
  item 107207134: true
      .id: 107207134
      .status: exists
      arch: x86_64
      epoch: (none)
      evr: 0:1.8.3-1.el7.tuxcare.els1
      extended_name: lz4-0:1.8.3-1.el7.tuxcare.els1.x86_64
      name: lz4
      release: 1.el7.tuxcare.els1
      signature_keyid: d07bf2a08d50eb66
      version: 1.8.3
oval:com.tuxcare.clsa:tst:1695326199005: false
  oval:com.tuxcare.clsa:tst:1695326199005: lz4-devel is earlier than 0:1.8.3-1.el7.tuxcare.els1 <false>
oval:com.tuxcare.clsa:tst:1695326199006: false
  oval:com.tuxcare.clsa:tst:1695326199006: lz4-devel isn't signed with CentOS 7 key <false>
oval:com.tuxcare.clsa:tst:1695326199007: false
  oval:com.tuxcare.clsa:tst:1695326199007: lz4-devel isn't signed with Tuxcare ELS key <false>
oval:com.tuxcare.clsa:tst:1695326199008: false
  oval:com.tuxcare.clsa:tst:1695326199008: lz4-static is earlier than 0:1.8.3-1.el7.tuxcare.els1 <false>
oval:com.tuxcare.clsa:tst:1695326199009: false
  oval:com.tuxcare.clsa:tst:1695326199009: lz4-static isn't signed with CentOS 7 key <false>
oval:com.tuxcare.clsa:tst:1695326199010: false
  oval:com.tuxcare.clsa:tst:1695326199010: lz4-static isn't signed with Tuxcare ELS key <false>
```

Ok, it is not much better than looking at the raw xml, but it is fast and it narrows down your search by some orders of magnitude.

Enjoy!
