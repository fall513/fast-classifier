# fast-classifier
fast-classifier for OPENWRT

1, copy patch to target/linux/ramips/patches-3.18/;

2, copy shortcut-fe to package/kernel/;

3, make menuconfig, choose Kernel modules -> Network Support -> kmod-fast-classifier;

4, compile and enjoy it;

Notice:
Tested mt7621 with OpenWrt 15.05, in fact, it could work with any chipset.
It could improve throughput, especially PPPoE mode.