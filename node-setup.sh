#!/bin/bash

# Check whether Nix is installed, otherwise prompt the user to install it. It
# might be installed, but the current shell session may not have it included
# in its path. Thus we check for the existence of `/nix` instead.

if [ ! -d /nix ]; then
    echo "Nix does not seem to be installed on this node, press any key to install it"
    read
    sh <(curl -L https://nixos.org/nix/install) --daemon --yes
fi

# Ensure that the Nix tools are accessible to this script:
. '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'

# Make sure we're running in a Nix shell with all of our required dependencies,
# and are running as root. Otherwise re-launch this script through sudo and
# nix-shell:
if [ "$IN_RELAUNCHED_NIX_SHELL" != "yes" ]; then
    echo "Relaunching script as root within nix-shell environment..."
    exec sudo HOME=/root "$(which nix-shell)" \
        -p linuxPackages.cpupower util-linux \
	--run "IN_RELAUNCHED_NIX_SHELL=yes bash \"$(readlink -f "$0")\" \"$@\""
fi

function banner() {
    RED='\033[0;31m'
    NC='\033[0m' # No Color
    printf "\n\n${RED}========== %s ========== ${NC}\n" "$1"
}

# Print useful information for reproducibility
banner "Printing node & CPU information"
hostname
lscpu

UPDATE_GRUB_REQD="0"
banner "Ensuring that cpuidle driver is not loaded"
if [ ! -f /sys/module/cpuidle/parameters/off ] || [ "$(cat /sys/module/cpuidle/parameters/off)" != "1" ]; then
    echo "cpuidle is enabled on this system"
    if [ -f /etc/default/grub ]; then
        if grep 'cpuidle.off=1' /etc/default/grub >/dev/null 2>&1; then
	    echo "Found 'cpuidle.off=1' in your GRUB config, did you reboot?"
	    UPDATE_GRUB_REQD="1"
	else
            echo "We can attempt to automatically patch a kernel parameter into your grub config"
            echo "WARNING: this may break your system. Press any key to continue..."
            read
            sed -i -E 's/GRUB_CMDLINE_LINUX="(.*)"/GRUB_CMDLINE_LINUX="\1 cpuidle.off=1"/' /etc/default/grub
	    UPDATE_GRUB_REQD="1"
	fi
    else
        echo "Please reboot your system with the 'cpuidle.off=1' kernel parameter"
    	exit 1
    fi
else
    echo "cpuidle turned off: /sys/module/cpuidle/parameters/off = $(cat /sys/module/cpuidle/parameters/off)"
fi

banner "Ensuring that systemd does not create its own cgroup2 hierarchies"
if (grep -v "systemd.unified_cgroup_hierarchy=false" /proc/cmdline); then
    echo "Systemd unified_cgroup_hierarchy is enabled on this system"
    if [ -f /etc/default/grub ]; then
        if grep 'systemd.unified_cgroup_hierarchy=false' /etc/default/grub >/dev/null 2>&1; then
            echo "Found 'systemd.unified_cgroup_hierarchy=false' in your GRUB config, did you reboot?"
	    UPDATE_GRUB_REQD="1"
        else
            echo "We can attempt to automatically patch a kernel parameter into your grub config"
            echo "WARNING: this may break your system. Press any key to continue..."
            read
            sed -i -E 's/GRUB_CMDLINE_LINUX="(.*)"/GRUB_CMDLINE_LINUX="\1 systemd.unified_cgroup_hierarchy=false"/' /etc/default/grub
	    UPDATE_GRUB_REQD="1"
        fi
    else
        echo "Please reboot your system with the 'systemd.unified_cgroup_hierarchy=false' kernel parameter"
    	exit 1
    fi
else
    echo "Systemd does not appear to have mounted the cgroup file system (no mount for \"$SYSTEMD_CGROUP_MOUNT\")"
fi

if [ "$UPDATE_GRUB_REQD" != "0" ]; then
	update-grub
	echo "Patched bootloader config, reboot required"
	exit 1
fi

# Install cpuset
banner "Checking for cpuset and setting up a cset shield"
if ! which cset 2>/dev/null; then
    echo "cpuset does not seem to be installed on this system. We can attempt"
    echo "to install it for you using apt. Press any key to continue..."
    read
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y cpuset
else
    echo "cpuset seems to be installed."
fi
sudo cset shield --kthread on --cpu 19


# Set the CPU frequency governor to performance:
banner "Setting CPU frequency governor to 'performance'"
cpupower frequency-set -g performance

# Disabling SMT (Hyperthreading)
banner "Disabling SMT (Hyperthreading)..."
if [ -f /sys/devices/system/cpu/smt/control ]; then
    if [ "$(cat /sys/devices/system/cpu/smt/control)" != "forceoff" ]; then
        echo forceoff > /sys/devices/system/cpu/smt/control
    fi
    echo "SMT control: $(cat /sys/devices/system/cpu/smt/control)"
else
    echo "No SMT (Hyperthreading) control available"
fi

# Disable processor boosting:
banner "Disabling cpufreq boosting..."
if [ -f /sys/devices/system/cpu/cpufreq/boost ]; then
    echo 0 > /sys/devices/system/cpu/cpufreq/boost
    echo "Processor boost: $(cat /sys/devices/system/cpu/cpufreq/boost)"
else
    echo "No cpufreq boost control available"
fi

# Disable hardware-managed P-states:
banner "Disabling Intel hardware P-state control"
if [ -f /sys/devices/system/cpu/intel_pstate/status ]; then
    echo "passive" > /sys/devices/system/cpu/intel_pstate/status
    echo "Intel P-state control: $(cat /sys/devices/system/cpu/intel_pstate/status)"
else
    echo "No Intel P-state status / control available"
fi

# Disable Intel CPU boost / turbo:
banner "Disabling Intel CPU boost / turbo"
if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
    echo "1" > /sys/devices/system/cpu/intel_pstate/no_turbo
    echo "Intel P-state no_turbo: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo)"
else
    echo "No Intel P-state \"no_turbo\" control available"
fi

# Summary:
banner "Summary:"
cpupower frequency-info
cpupower monitor
