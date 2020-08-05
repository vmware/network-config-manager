FROM fedora:32


RUN dnf update -y
RUN dnf -y install systemd; systemctl enable systemd-networkd;systemctl start systemd-networkd