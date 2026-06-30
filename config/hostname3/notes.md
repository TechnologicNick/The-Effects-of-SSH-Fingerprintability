map this config file as normal, and use a volume so cat /etc/hostname is the same. E.g.

-v "etc/hostname:/cowrie/cowrie-git/honeyfs/etc/hostname:ro" \
